"""Own the temporary file and named container for one isolated path probe."""

import json
import math
import os
import re
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import vpn_health


def _failure(code):
    return {"success": False, "error": code, "exit_ip_verified": False}


def _runtime_version_matches(banner, version):
    return (
        isinstance(banner, str)
        and re.search(
            r"^Xray[ \t]+" + re.escape(version) + r"(?=\s|$)", banner, re.MULTILINE
        )
        is not None
    )


def _wait_bound(port, timeout):
    deadline = time.monotonic() + min(timeout, 10)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=min(remaining, 0.2)
            ):
                return time.monotonic() < deadline
        except OSError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(remaining, 0.05))


def _timeout(settings):
    timeout = settings.get("timeout", 15)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("invalid timeout")
    return timeout


def _socks_config(outbound, port):
    return {
        "log": {"access": "none", "loglevel": "warning"},
        "inbounds": [
            {
                "tag": "probe_socks",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [outbound],
    }


class ProbeSession:
    def __init__(self, compose_file, config_dir, run_compose, runner, measure, wait):
        self.compose_file = compose_file
        self.config_dir = config_dir
        self.run_compose = run_compose
        self.runner, self.measure, self.wait = runner, measure, wait
        self.temporary = None
        self.container_name = None
        self.launch_attempted = False
        self.error_code = "invalid_configuration"

    def probe(self, upstream, settings):
        result = _failure("probe_failed")
        try:
            result = self._measure(upstream, settings)
        except Exception:
            result = _failure(self.error_code)
        finally:
            cleanup_failed = self._cleanup()
            if cleanup_failed and result.get("success") is True:
                result = _failure("probe_cleanup_failed")
        return result

    def _measure(self, upstream, settings):
        timeout = _timeout(settings)
        self.error_code = "compose_config_failed"
        if not self._host_network():
            return _failure("host_network_required")
        self.error_code = "invalid_upstream"
        import vpn_transports

        outbound = vpn_transports.render_outbound(upstream, "probe_exit")
        self.error_code = "probe_setup_failed"
        port = self._prepare(outbound)
        self.error_code = "probe_start_failed"
        if not self._launch():
            return _failure(self.error_code)
        if upstream.get("security", {}).get("settings", {}).get("ech_config_list"):
            self.error_code = "runtime_version_mismatch"
            if not self._version_matches(timeout, vpn_transports.PINNED_XRAY_VERSION):
                return _failure(self.error_code)
        self.error_code = "probe_start_timeout"
        if not self.wait(port, timeout):
            return _failure(self.error_code)
        self.error_code = "probe_failed"
        return self.measure(
            "127.0.0.1",
            port,
            settings.get("download_url"),
            settings.get("egress_url"),
            settings.get("expected_exit_ips"),
            bytes_required=settings.get("bytes_required", 131072),
            timeout=timeout,
        )

    def _host_network(self):
        completed = self.run_compose(
            self.compose_file, ["config", "--format", "json"], capture=True
        )
        if completed.returncode != 0:
            raise ValueError("compose config failed")
        return (
            json.loads(completed.stdout)["services"]["xray"].get("network_mode")
            == "host"
        )

    def _prepare(self, outbound):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        fd, self.temporary = tempfile.mkstemp(
            prefix=".vpn-probe-", suffix=".json", dir=Path(self.config_dir).resolve()
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(_socks_config(outbound, port), stream)
            stream.flush()
            os.fsync(stream.fileno())
        self.container_name = "vpn-probe-" + uuid.uuid4().hex
        return port

    def _launch(self):
        self.launch_attempted = True
        completed = self.run_compose(
            self.compose_file,
            [
                "run",
                "--rm",
                "-d",
                "--no-deps",
                "--name",
                self.container_name,
                "-v",
                self.temporary + ":/etc/xray/probe.json:ro",
                "xray",
                "run",
                "-config",
                "/etc/xray/probe.json",
            ],
            capture=True,
        )
        return completed.returncode == 0

    def _version_matches(self, timeout, version):
        completed = self.runner(
            ["docker", "exec", self.container_name, "xray", "version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=min(timeout, 10),
        )
        return _runtime_version_matches(completed.stdout, version)

    def _cleanup(self):
        failed = False
        if self.launch_attempted and self.container_name is not None:
            try:
                self.runner(
                    ["docker", "rm", "-f", self.container_name],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            except Exception:
                failed = True
        if self.temporary is not None:
            try:
                os.unlink(self.temporary)
            except FileNotFoundError:
                pass
            except OSError:
                failed = True
        return failed


def probe_upstream(upstream, settings, compose_file, config_dir, run_compose) -> dict:
    session = ProbeSession(
        compose_file,
        config_dir,
        run_compose,
        subprocess.run,
        vpn_health.probe_path,
        _wait_bound,
    )
    return session.probe(upstream, settings)
