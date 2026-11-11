"""Local Xray 26.10.31 ECH transfers, enabled only by an integration flag.

XRAY_ECH_INTEGRATION=1 \
    python3 -m unittest discover -s tests -p test_ech_integration.py -v
"""

import base64
import http.server
import json
import os
import re
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from certificates import write_certificate
from fixture_data import fixture_data

BODY = bytes(range(256)) * 512


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path != self.server.fixture_path:
            self.send_error(404)
            return
        with self.server.request_lock:
            self.server.request_count += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


@unittest.skipUnless(
    os.environ.get("XRAY_INTEGRATION") == "1"
    or os.environ.get("XRAY_ECH_INTEGRATION") == "1",
    "set XRAY_INTEGRATION=1 or XRAY_ECH_INTEGRATION=1 for local Docker ECH tests",
)
class EchIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = os.environ.get("XRAY_TEST_IMAGE", "ghcr.io/xtls/xray-core:26.10.31")
        cls.secret_values = []
        temporary = tempfile.TemporaryDirectory(prefix="xray-ech-material-")
        cls.addClassCleanup(temporary.cleanup)
        cls.material = Path(temporary.name).resolve()
        version = cls.command(
            ["docker", "run", "--rm", "--entrypoint", "xray", cls.image, "version"]
        )
        if not re.search(r"\bXray 26\.10\.31\b", version):
            raise AssertionError("XRAY_TEST_IMAGE must provide Xray 26.10.31")
        cls.ech_config, cls.ech_keys = cls.generate_ech()
        cls.wrong_ech_config, _ = cls.generate_ech()
        if cls.ech_config == cls.wrong_ech_config:
            raise AssertionError(
                "independent ECH key generation produced identical configs"
            )

        key_pem = write_certificate(
            cls.material, "origin.example.test", ["origin.example.test"], ca=True
        )
        cls.secret_values.append(key_pem.decode("ascii"))

    @classmethod
    def redacted(cls, text):
        for value in cls.secret_values:
            text = text.replace(value, "[redacted]")
        return text

    @classmethod
    def command(cls, args, timeout=45, sensitive=False):
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            raise AssertionError("Docker command exceeded its time limit") from None
        if result.returncode:
            detail = (
                "output withheld"
                if sensitive
                else cls.redacted(result.stdout + result.stderr)
            )
            raise AssertionError(
                f"Docker command failed (exit {result.returncode}): {detail}"
            )
        return result.stdout

    @classmethod
    def generate_ech(cls):
        output = cls.command(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "xray",
                cls.image,
                "tls",
                "ech",
                "--serverName",
                "outer.example.test",
            ],
            sensitive=True,
        )
        config = re.search(r"ECH config list:\s*([A-Za-z0-9+/=]+)", output)
        keys = re.search(r"ECH server keys:\s*([A-Za-z0-9+/=]+)", output)
        if not config or not keys:
            raise AssertionError(
                "native ECH generator output did not contain config and keys"
            )
        values = (config.group(1), keys.group(1))
        cls.secret_values.extend(values)
        for value in values:
            if not base64.b64decode(value, validate=True):
                raise AssertionError("native ECH generator returned empty material")
        return values

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="xray-ech-case-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ("cert.pem", "key.pem"):
            (self.root / name).write_bytes((self.material / name).read_bytes())
        self.project = "xray-ech-" + uuid.uuid4().hex
        self.compose_file = self.root / "compose.json"
        self.fixture = http.server.ThreadingHTTPServer(("0.0.0.0", 0), FixtureHandler)
        self.fixture.daemon_threads = True
        self.fixture.fixture_path = "/" + uuid.uuid4().hex
        self.fixture.request_lock = threading.Lock()
        self.fixture.request_count = 0
        self.fixture_thread = threading.Thread(
            target=self.fixture.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True,
        )
        self.fixture_thread.start()
        self.addCleanup(self.stop_fixture)
        client_id = str(uuid.uuid4())
        self.server = fixture_data(
            "test_ech_integration_data_1", [client_id, self.ech_keys]
        )
        self.client = fixture_data(
            "test_ech_integration_data_2", [client_id, self.ech_config]
        )
        services = {}
        for name in ("server", "client"):
            services[name] = {
                "image": self.image,
                "entrypoint": ["xray"],
                "command": ["run", "-config", f"/work/{name}.json"],
                "volumes": [f"{self.root}:/work:ro"],
            }
        services["server"]["extra_hosts"] = ["host.docker.internal:host-gateway"]
        services["client"]["ports"] = ["127.0.0.1::1080"]
        self.compose_file.write_text(
            json.dumps(
                {
                    "services": services,
                    "networks": {"default": {"driver": "bridge"}},
                }
            ),
            encoding="utf-8",
        )
        self.addCleanup(self.stop_containers)

    def stop_fixture(self):
        self.fixture.shutdown()
        self.fixture.server_close()
        self.fixture_thread.join(timeout=3)
        self.assertFalse(self.fixture_thread.is_alive(), "HTTP fixture did not stop")

    def compose(self, *args, timeout=45):
        return self.command(
            [
                "docker",
                "compose",
                "--project-name",
                self.project,
                "--file",
                str(self.compose_file),
                *args,
            ],
            timeout=timeout,
        )

    def stop_containers(self):
        self.compose("down", "--volumes", "--timeout", "5", timeout=30)

    def write_configs(self):
        for name, config in (("server", self.server), ("client", self.client)):
            (self.root / f"{name}.json").write_text(
                json.dumps(config), encoding="utf-8"
            )

    def start_pair(self):
        self.write_configs()
        self.compose("up", "--detach", "--wait", "--wait-timeout", "20")
        self.wait_socks()

    def restart_pair(self):
        self.write_configs()
        self.compose(
            "up", "--detach", "--force-recreate", "--wait", "--wait-timeout", "20"
        )
        self.wait_socks()

    def logs(self):
        return self.redacted(
            self.compose("logs", "--no-color", "--tail", "100", "client", "server")
        )

    @staticmethod
    def read_exact(sock, length):
        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError(
                    "SOCKS/HTTP stream closed before the expected data"
                )
            data.extend(chunk)
        return bytes(data)

    def wait_socks(self):
        binding = self.compose("port", "client", "1080").strip()
        self.assertTrue(
            binding.startswith("127.0.0.1:"),
            "SOCKS must be published only on localhost",
        )
        self.socks_port = int(binding.rsplit(":", 1)[1])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.socks_port), timeout=1
                ) as sock:
                    sock.sendall(b"\x05\x01\x00")
                    if self.read_exact(sock, 2) == b"\x05\x00":
                        return
            except OSError:
                pass
            time.sleep(0.1)
        self.fail("SOCKS listener did not become ready\n" + self.logs())

    def transfer(self):
        deadline = time.monotonic() + 12
        host = b"host.docker.internal"
        port = self.fixture.server_address[1]
        with socket.create_connection(
            ("127.0.0.1", self.socks_port), timeout=3
        ) as sock:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            sock.sendall(b"\x05\x01\x00")
            if self.read_exact(sock, 2) != b"\x05\x00":
                raise ConnectionError("SOCKS no-auth negotiation failed")
            sock.sendall(
                b"\x05\x01\x00\x03"
                + bytes([len(host)])
                + host
                + struct.pack("!H", port)
            )
            reply = self.read_exact(sock, 4)
            if reply[:3] != b"\x05\x00\x00":
                raise ConnectionError("SOCKS CONNECT was rejected")
            if reply[3] == 1:
                self.read_exact(sock, 4)
            elif reply[3] == 4:
                self.read_exact(sock, 16)
            elif reply[3] == 3:
                self.read_exact(sock, self.read_exact(sock, 1)[0])
            else:
                raise ConnectionError("SOCKS returned an invalid address type")
            self.read_exact(sock, 2)
            sock.sendall(
                (
                    f"GET {self.fixture.fixture_path} HTTP/1.1\r\n"
                    f"Host: host.docker.internal:{port}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
            )
            response = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HTTP transfer exceeded its deadline")
                sock.settimeout(remaining)
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > len(BODY) + 16384:
                    raise ValueError("HTTP response exceeded the fixture size limit")
            headers, separator, body = bytes(response).partition(b"\r\n\r\n")
            if not separator or not headers.startswith(b"HTTP/1.1 200 "):
                raise ConnectionError("no successful HTTP response through the tunnel")
            return body

    def assert_transfer(self):
        try:
            body = self.transfer()
        except OSError as error:
            self.fail(f"local transfer failed: {type(error).__name__}\n{self.logs()}")
        self.assertEqual(
            body, BODY, "tunnel did not deliver the known 128 KiB body intact"
        )

    def assert_ech_failure(self):
        before = self.fixture.request_count
        try:
            self.transfer()
        except TimeoutError:
            self.fail(
                "negative ECH case timed out instead of rejecting the handshake\n"
                + self.logs()
            )
        except (ConnectionError, OSError):
            pass
        else:
            self.fail("mismatched ECH settings unexpectedly allowed an HTTP response")
        logs = self.logs()
        self.assertRegex(
            logs.lower(),
            r"(?s)(tls:|ech).*?(ech|certificate|handshake)",
            "failure was not accompanied by a TLS/ECH handshake error",
        )
        self.assertEqual(
            self.fixture.request_count,
            before,
            "HTTP fixture was reached despite failed ECH",
        )

    def test_ech_handshake_transfers_128_kib(self):
        self.start_pair()
        self.assert_transfer()

    def test_without_ech_config_falls_back_to_verified_tls(self):
        self.client["outbounds"][0]["streamSettings"]["tlsSettings"].pop(
            "echConfigList"
        )
        self.start_pair()
        self.assert_transfer()

    def test_wrong_ech_config_rejects_handshake(self):
        self.start_pair()
        self.assert_transfer()
        self.client["outbounds"][0]["streamSettings"]["tlsSettings"][
            "echConfigList"
        ] = self.wrong_ech_config
        self.restart_pair()
        self.assert_ech_failure()

    def test_missing_server_keys_rejects_ech_handshake(self):
        self.start_pair()
        self.assert_transfer()
        self.server["inbounds"][0]["streamSettings"]["tlsSettings"].pop("echServerKeys")
        self.restart_pair()
        self.assert_ech_failure()


if __name__ == "__main__":
    unittest.main()
