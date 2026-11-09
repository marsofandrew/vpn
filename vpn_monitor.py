"""Opt-in, isolated upstream probes; importing this module performs no I/O.

Production requires a local Docker daemon on Linux and an Xray Compose service
with ``network_mode: host``. ``config_dir`` must be on that daemon's filesystem.
Only calling probe_upstream starts a container or makes a connection. Target
DNS and HTTPS verification belong to vpn_health.probe_path's SOCKS transport.
"""

import json
import math
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid

import vpn_health

__all__ = ["probe_upstream"]


def _failure(code):
    return {"success": False, "error": code, "exit_ip_verified": False}


def _wait_bound(port, timeout):
    """Wait at most ten seconds (or timeout, if shorter) for the listener."""
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


def probe_upstream(upstream, settings, compose_file, config_dir, run_compose) -> dict:
    """Measure one upstream through a private, temporary Xray SOCKS listener.

    Settings supply download_url, egress_url, expected_exit_ips, and optional
    bytes_required (131072) / timeout (15 seconds). Health results are returned
    unchanged. Setup failures return fixed codes without exception text or
    endpoint data. Cleanup targets only this invocation's random container and
    temporary file, even if Compose fails after creating the container. Cleanup
    failure turns an otherwise successful result into ``probe_cleanup_failed``.
    """
    temporary = None
    container_name = None
    launch_attempted = False
    result = _failure("probe_failed")
    error_code = "invalid_configuration"
    try:
        timeout = settings.get("timeout", 15)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            return _failure("invalid_configuration")
        download_url = settings.get("download_url")
        egress_url = settings.get("egress_url")
        expected_exit_ips = settings.get("expected_exit_ips")
        bytes_required = settings.get("bytes_required", 131072)

        error_code = "compose_config_failed"
        completed = run_compose(
            compose_file, ["config", "--format", "json"], capture=True
        )
        if completed.returncode != 0:
            return _failure(error_code)
        service = json.loads(completed.stdout)["services"]["xray"]
        if service.get("network_mode") != "host":
            return _failure("host_network_required")

        error_code = "invalid_upstream"
        import vpn_transports

        outbound = vpn_transports.render_outbound(upstream, "probe_exit")

        error_code = "probe_setup_failed"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = {
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
        fd, temporary = tempfile.mkstemp(
            prefix=".vpn-probe-", suffix=".json", dir=Path(config_dir).resolve()
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(config, stream)
            stream.flush()
            os.fsync(stream.fileno())

        container_name = "vpn-probe-" + uuid.uuid4().hex
        error_code = "probe_start_failed"
        launch_attempted = True
        completed = run_compose(
            compose_file,
            [
                "run",
                "--rm",
                "-d",
                "--no-deps",
                "--name",
                container_name,
                "-v",
                temporary + ":/etc/xray/probe.json:ro",
                "xray",
                "run",
                "-config",
                "/etc/xray/probe.json",
            ],
            capture=True,
        )
        if completed.returncode != 0:
            result = _failure(error_code)
        else:
            error_code = "probe_start_timeout"
            if not _wait_bound(port, timeout):
                result = _failure(error_code)
            else:
                error_code = "probe_failed"
                result = vpn_health.probe_path(
                    "127.0.0.1",
                    port,
                    download_url,
                    egress_url,
                    expected_exit_ips,
                    bytes_required=bytes_required,
                    timeout=timeout,
                )
    except Exception:
        result = _failure(error_code)
    finally:
        cleanup_failed = False
        if launch_attempted and container_name is not None:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            except Exception:
                cleanup_failed = True
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        if cleanup_failed and result.get("success") is True:
            result = _failure("probe_cleanup_failed")
    return result
