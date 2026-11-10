"""Private Linux/Docker topology for the opt-in stabilization tests.

Xray 26.10.31 defaults to its embedded CA bundle. The fixture-scoped outbound
renderer adds native useSystemCA=true to TLS outbounds so SSL_CERT_FILE can
trust the temporary CA for both gateway deployments and monitor containers.
The production schema and renderer remain unchanged outside this scope.
See https://raw.githubusercontent.com/XTLS/Xray-core/v26.10.31/transport/internet/tls/config.go

Services explicitly run as 0:0, matching production Compose. Host UID mapping
and Linux bind-mount access still require verification in the live suite.
"""

from contextlib import redirect_stderr, redirect_stdout
import datetime
import http.client
import http.server
from io import StringIO
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

import vpnctl


IMAGE = "ghcr.io/xtls/xray-core:26.10.31"
BODY = bytes(range(256)) * 512


def fixture_tls_roots():
    """Return a scoped patch of the renderer shared by vpnctl and vpn_monitor."""
    renderer = vpnctl.vpn_transports.render_outbound

    def render_outbound(upstream, tag):
        outbound = renderer(upstream, tag)
        stream = outbound["streamSettings"]
        if stream["security"] == "tls":
            stream["tlsSettings"]["useSystemCA"] = True
        return outbound

    return patch.object(vpnctl.vpn_transports, "render_outbound", render_outbound)


def command(args, timeout=45):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout)


def require_runtime():
    if platform.system() != "Linux":
        raise unittest.SkipTest(
            "stabilization monitoring requires a Linux host with local Docker host networking; "
            "Docker Desktop on macOS/Windows is unsupported"
        )
    if not shutil.which("docker"):
        raise unittest.SkipTest("stabilization integration requires Docker and Docker Compose")
    try:
        command(["docker", "compose", "version"])
        context = json.loads(command(["docker", "context", "inspect"]).stdout)
        endpoint = os.environ.get("DOCKER_HOST", context[0]["Endpoints"]["docker"]["Host"])
        if not endpoint.startswith("unix://"):
            raise unittest.SkipTest("stabilization requires a local Unix-socket Docker daemon")
        info = json.loads(command(["docker", "info", "--format", "{{json .}}"]).stdout)
        if info.get("OSType") != "linux" or "docker desktop" in info.get("OperatingSystem", "").lower():
            raise unittest.SkipTest("stabilization requires native Linux Docker host networking")
    except (OSError, subprocess.SubprocessError) as error:
        raise unittest.SkipTest("local Docker/Compose unavailable: " + type(error).__name__) from None
    try:
        command(["docker", "image", "inspect", IMAGE])
    except subprocess.CalledProcessError:
        try:
            command(["docker", "pull", IMAGE], timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            detail = (getattr(error, "stderr", "") or "")[-1000:]
            raise RuntimeError(
                "required official image " + IMAGE + " unavailable; no fallback is permitted: "
                + type(error).__name__ + (": " + detail if detail else "")
            ) from None
    version = command(["docker", "run", "--rm", "--network", "none", "--entrypoint", "xray",
                       IMAGE, "version"]).stdout
    if not re.search(r"\bXray 26\.10\.31\b", version):
        raise AssertionError("official image did not report Xray 26.10.31")


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)


def free_ports(count):
    listeners = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listeners.append(listener)
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


class FaultProxy:
    def __init__(self, target):
        self.target = target
        self.lock = threading.Lock()
        self.connections = set()
        self.workers = []
        self.enabled = True
        self.stopped = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(32)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                incoming, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self.relay, args=(incoming,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def relay(self, incoming):
        outgoing = None
        try:
            with self.lock:
                if not self.enabled or self.stopped.is_set():
                    return
                self.connections.add(incoming)
            outgoing = socket.create_connection(self.target, timeout=1)
            outgoing.settimeout(1)
            incoming.settimeout(1)
            with self.lock:
                if not self.enabled or self.stopped.is_set():
                    return
                self.connections.add(outgoing)
            idle_deadline = time.monotonic() + 15
            while not self.stopped.is_set() and time.monotonic() < idle_deadline:
                ready, _, _ = select.select([incoming, outgoing], [], [], 0.1)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (outgoing if source is incoming else incoming).sendall(data)
                    idle_deadline = time.monotonic() + 15
        except (OSError, ValueError):
            pass
        finally:
            for connection in (incoming, outgoing):
                if connection is not None:
                    with self.lock:
                        self.connections.discard(connection)
                    connection.close()

    def set_enabled(self, enabled):
        with self.lock:
            self.enabled = enabled
            if not enabled:
                for connection in self.connections:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    connection.close()

    def close(self):
        self.stopped.set()
        self.set_enabled(False)
        self.listener.close()
        self.thread.join(timeout=2)
        deadline = time.monotonic() + 3
        for worker in self.workers:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            raise AssertionError("fault proxy did not stop within its cleanup deadline")


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == self.server.prefix + "/body":
            body, content_type = BODY, "application/octet-stream"
        elif self.path == self.server.prefix + "/egress":
            body = json.dumps({"ip": self.client_address[0]}).encode("ascii")
            content_type = "application/json"
        else:
            self.send_error(404)
            return
        with self.server.lock:
            self.server.requests.append((self.path, self.client_address[0]))
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args):
        pass


class HttpsFixture(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return self.context.wrap_socket(connection, server_side=True,
                                        do_handshake_on_connect=False), address


class StabilizationFixture:
    def __init__(self, case):
        self.case = case
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", vpnctl.DEFAULT_API_PORT))
            except OSError:
                raise unittest.SkipTest("gateway API port 10085 is occupied; existing services are left untouched")
        temporary = tempfile.TemporaryDirectory(prefix="xray-stabilization-")
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = "xray-stabilization-" + uuid.uuid4().hex
        self.compose_file = self.root / "compose.json"
        self.config_path = self.root / "gateway.json"
        self.state_path = self.root / "state.json"
        environment = patch.dict(os.environ, {
            "COMPOSE_PROJECT_NAME": self.project,
            "SSL_CERT_FILE": str(self.root / "cert.pem"),
            "XRAY_CONFIG_PATH": str(self.config_path),
        })
        environment.start()
        case.addCleanup(environment.stop)
        trust = fixture_tls_roots()
        trust.start()
        case.addCleanup(trust.stop)
        self.make_certificate()
        self.http = HttpsFixture(("0.0.0.0", 0), FixtureHandler)
        self.http.prefix = "/" + uuid.uuid4().hex
        self.http.requests = []
        self.http.lock = threading.Lock()
        self.http.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.http.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.http.context.set_ecdh_curve("X25519")
        self.http.context.set_alpn_protocols(["h2", "http/1.1"])
        self.http.context.load_cert_chain(self.root / "cert.pem", self.root / "key.pem")
        self.http_thread = threading.Thread(target=self.http.serve_forever,
                                            kwargs={"poll_interval": 0.1}, daemon=True)
        self.http_thread.start()
        case.addCleanup(self.stop_http)
        self.ny_tcp_port, self.ny_tls_port, self.gateway_port, self.socks_port = free_ports(4)
        self.proxy = FaultProxy(("127.0.0.1", self.ny_tcp_port))
        case.addCleanup(self.proxy.close)
        self.reality_target = "origin.example.test:" + str(self.http.server_port)
        self.make_configs()
        case.addCleanup(self.stop_containers)
        self.compose("up", "-d", "ny")
        container = self.compose("ps", "-q", "ny").stdout.strip()
        networks = json.loads(command(["docker", "inspect", "--format",
                                       "{{json .NetworkSettings.Networks}}", container]).stdout)
        case.assertEqual(len(networks), 1, "NY must have one isolated bridge interface")
        self.exit_ip = next(iter(networks.values()))["IPAddress"]
        case.assertTrue(self.exit_ip, "NY bridge address is missing")
        self.wait_ny()
        self.cli("up")
        self.compose("up", "-d", "client")
        self.wait_socks()

    def make_certificate(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.example.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("origin.example.test"), x509.DNSName("host.docker.internal"),
                ]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(key, hashes.SHA256()))
        private_write(self.root / "cert.pem", cert.public_bytes(serialization.Encoding.PEM))
        private_write(self.root / "key.pem", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

    def make_configs(self):
        state = vpnctl.create_state("127.0.0.1", self.reality_target, "fixture.test",
                                    self.gateway_port, ["fixture"], None)
        ny = vpnctl.create_state("127.0.0.1", self.reality_target, "fixture.test",
                                 18443, ["exit"], None)
        profile = ny["profiles"][0]
        primary = vpnctl.vpn_transports.parse_link(vpnctl.generate_vless_link(
            profile["clients"][0], ny, profile))
        primary["port"] = self.proxy.port
        fallback = vpnctl.vpn_transports.parse_link(
            f"vless://{profile['clients'][0]['id']}@127.0.0.1:{self.ny_tls_port}"
            "?security=tls&type=xhttp&sni=origin.example.test&path=%2Fstabilization&mode=stream-one")
        state["node"] = {"id": "fixture-gateway", "role": "gateway", "foreign_only": True}
        state["upstreams"] = {"ny-primary": primary, "ny-tls": fallback}
        state["routing_policies"].update({
            "ny-primary": {"type": "upstream", "upstreams": ["ny-primary"]},
            "ny-tls": {"type": "upstream", "upstreams": ["ny-tls"]},
        })
        state["profiles"][0].update(route="ny-primary", outbound_mode="proxy")
        vpnctl.save_state(self.state_path, state)
        private_write(self.config_path, json.dumps(vpnctl.render_config(state)).encode())
        tls_inbound = {
            "tag": "ny-tls", "listen": "0.0.0.0", "port": 18444, "protocol": "vless",
            "settings": {"decryption": "none", "clients": [{"id": profile["clients"][0]["id"]}]},
            "streamSettings": vpnctl.vpn_transports.render_stream(fallback["transport"], {
                "type": "tls", "settings": {"alpn": ["h2", "http/1.1"], "certificates": [{
                    "certificateFile": "/work/cert.pem", "keyFile": "/work/key.pem",
                }]},
            }, server=True),
        }
        configs = {
            "ny": {"log": {"loglevel": "warning"},
                   "inbounds": [vpnctl.render_vless_inbound(ny, profile), tls_inbound],
                   "outbounds": [{"tag": "exit", "protocol": "freedom", "settings": {}}]},
            "client": {"log": {"loglevel": "warning"}, "inbounds": [{
                "listen": "127.0.0.1", "port": self.socks_port, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }], "outbounds": [vpnctl.vpn_transports.render_outbound(
                vpnctl.vpn_transports.parse_link(vpnctl.generate_vless_link(
                    state["profiles"][0]["clients"][0], state, state["profiles"][0])), "gateway")]},
        }
        services = {}
        for name in ("ny", "client", "xray"):
            config_path = self.config_path if name == "xray" else self.root / (name + ".json")
            target = "/etc/xray/config.json"
            services[name] = {
                "image": IMAGE, "entrypoint": ["xray"], "user": "0:0",
                "command": ["run", "-config", target],
                "read_only": True, "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "environment": {"SSL_CERT_FILE": "/work/cert.pem"},
                "volumes": [f"{config_path}:{target}:ro", f"{self.root}:/work:ro"],
                "extra_hosts": ["host.docker.internal:host-gateway",
                                "origin.example.test:" + ("host-gateway" if name == "ny" else "127.0.0.1")],
            }
            if name == "ny":
                services[name]["ports"] = [f"127.0.0.1:{self.ny_tcp_port}:18443",
                                            f"127.0.0.1:{self.ny_tls_port}:18444"]
            else:
                services[name]["network_mode"] = "host"
        for name, config in configs.items():
            private_write(self.root / (name + ".json"), json.dumps(config).encode())
        private_write(self.compose_file, json.dumps({"name": self.project, "services": services}).encode())

    def compose(self, *args):
        return command(["docker", "compose", "--project-name", self.project,
                        "--file", str(self.compose_file), *args])

    def stop_containers(self):
        self.compose("down", "--volumes", "--timeout", "5")

    def wait_ny(self):
        deadline = time.monotonic() + 10
        context = ssl.create_default_context()
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.ny_tls_port), timeout=0.5) as connection:
                    with context.wrap_socket(connection, server_hostname="origin.example.test"):
                        return
            except OSError:
                time.sleep(0.1)
        self.case.fail("NY verified TLS listener did not become ready")

    def stop_http(self):
        self.http.shutdown()
        self.http.server_close()
        self.http_thread.join(timeout=2)
        self.case.assertFalse(self.http_thread.is_alive(), "HTTPS fixture did not stop")

    def cli(self, *args):
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = vpnctl.main(["--state", str(self.state_path), "--config", str(self.config_path),
                                "--compose-file", str(self.compose_file), *args])
        self.case.assertEqual(code, 0, "vpnctl " + " ".join(args[:2]) + " failed: " + output.getvalue())
        return self.state()

    def state(self):
        return vpnctl.load_state(self.state_path)

    @staticmethod
    def usage(state):
        client = state["profiles"][0]["clients"][0]
        return tuple(client["used_" + direction + "_bytes"] for direction in ("uplink", "downlink"))

    def settled_usage(self, minimum_downlink=0):
        previous, repeats = None, 0
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = self.cli("usage", "--refresh")
            current = self.usage(state)
            if previous is not None:
                self.case.assertTrue(all(a >= b for a, b in zip(current, previous)),
                                     "usage polling moved backwards")
            repeats = repeats + 1 if current == previous else 0
            if repeats >= 2 and current[1] >= minimum_downlink:
                return state
            previous = current
            time.sleep(0.15)
        self.case.fail("live Xray usage did not settle above the transferred byte count")

    @staticmethod
    def read_exact(connection, count):
        data = bytearray()
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise ConnectionError("SOCKS stream closed early")
            data.extend(chunk)
        return bytes(data)

    def wait_socks(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.socks_port), timeout=0.5) as connection:
                    connection.sendall(b"\x05\x01\x00")
                    if self.read_exact(connection, 2) == b"\x05\x00":
                        return
            except OSError:
                pass
            time.sleep(0.1)
        self.case.fail("local Xray client SOCKS listener did not become ready")

    def request(self, suffix):
        deadline = time.monotonic() + 6
        context = ssl.create_default_context()
        host = b"host.docker.internal"
        with socket.create_connection(("127.0.0.1", self.socks_port), timeout=2) as connection:
            connection.settimeout(max(0.01, deadline - time.monotonic()))
            connection.sendall(b"\x05\x01\x00")
            if self.read_exact(connection, 2) != b"\x05\x00":
                raise ConnectionError("SOCKS greeting rejected")
            connection.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host
                               + self.http.server_port.to_bytes(2, "big"))
            reply = self.read_exact(connection, 4)
            if reply[:3] != b"\x05\x00\x00":
                raise ConnectionError("SOCKS CONNECT rejected")
            if reply[3] == 1:
                self.read_exact(connection, 4)
            elif reply[3] == 4:
                self.read_exact(connection, 16)
            elif reply[3] == 3:
                self.read_exact(connection, self.read_exact(connection, 1)[0])
            else:
                raise ConnectionError("invalid SOCKS address type")
            self.read_exact(connection, 2)
            connection.settimeout(max(0.01, deadline - time.monotonic()))
            with context.wrap_socket(connection, server_hostname=host.decode()) as tls:
                tls.sendall((f"GET {self.http.prefix}/{suffix} HTTP/1.1\r\n"
                             "Host: host.docker.internal\r\nConnection: close\r\n\r\n").encode())
                tls.settimeout(max(0.01, deadline - time.monotonic()))
                with http.client.HTTPResponse(tls) as response:
                    response.begin()
                    if response.status != 200:
                        raise ConnectionError("fixture returned an unsuccessful HTTP response")
                    result = bytearray()
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("fixture transfer deadline exceeded")
                        tls.settimeout(remaining)
                        chunk = response.read1(16384)
                        if not chunk:
                            break
                        result.extend(chunk)
                        if len(result) > len(BODY):
                            raise ValueError("fixture response exceeded its size limit")
                    return bytes(result)

    def transfer(self):
        self.case.assertEqual(self.request("body"), BODY, "known 128 KiB body was corrupted")
        self.case.assertEqual(json.loads(self.request("egress")), {"ip": self.exit_ip},
                              "HTTPS fixture did not observe the real NY container peer IP")

    def request_count(self):
        with self.http.lock:
            return len(self.http.requests)

    def assert_blocked(self):
        before = self.request_count()
        with self.case.assertRaises((OSError, http.client.HTTPException)):
            self.request("body")
        self.case.assertEqual(self.request_count(), before, "blocked traffic reached the HTTPS origin")

    def outbound_counters(self):
        completed = self.compose("exec", "-T", "xray", "xray", "api", "statsquery",
                                  "--server=127.0.0.1:10085", "-pattern", "outbound>>>")
        return {entry["name"]: int(entry.get("value") or 0)
                for entry in vpnctl.stat_entries(json.loads(completed.stdout))}

    def assert_traffic_route(self, selected):
        before = self.outbound_counters()
        self.transfer()
        deadline = time.monotonic() + 5
        key = f"outbound>>>{selected}>>>traffic>>>downlink"
        while time.monotonic() < deadline:
            after = self.outbound_counters()
            if after.get(key, 0) - before.get(key, 0) >= len(BODY):
                for other in {"ny-primary", "ny-tls"} - {selected}:
                    for direction in ("uplink", "downlink"):
                        other_key = f"outbound>>>{other}>>>traffic>>>{direction}"
                        self.case.assertEqual(after.get(other_key, 0), before.get(other_key, 0),
                                              "inactive gateway upstream carried client traffic")
                return
            time.sleep(0.1)
        self.case.fail("selected gateway outbound did not carry the fixture body")

    def configure_health(self, cooldown=30):
        for name in ("ny-primary", "ny-tls"):
            base = f"https://host.docker.internal:{self.http.server_port}{self.http.prefix}"
            self.cli("health", "configure", name, "--download-url", base + "/body",
                     "--egress-url", base + "/egress", "--expected-exit-ip", self.exit_ip,
                     "--interval", "0.1", "--fail-threshold", "2", "--success-threshold", "2",
                     "--timeout", "4")
        self.cli("policy", "set", "foreign", "--type", "priority", "--upstream", "ny-primary",
                 "--upstream", "ny-tls", "--cooldown", str(cooldown))
        self.cli("route", "set", "default", "--policy", "foreign")

    def health_check(self):
        state = self.state()
        due = max((record.get("next_probe_at", 0) for record in state.get("health", {}).values()), default=0)
        delay = due - time.time()
        self.case.assertLessEqual(delay, 1, "fixture health interval unexpectedly changed")
        if delay > 0:
            time.sleep(delay + 0.01)
        return self.cli("health", "check")
