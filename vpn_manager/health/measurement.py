import http.client
import ipaddress
import json
import socket
import ssl
import time
from contextlib import ExitStack

from vpn_manager.health.fields import (
    _MAX_BODY,
    _MAX_JSON,
    _MIN_BODY,
    _integer,
    _number,
    _ProbeError,
)
from vpn_manager.health.http import _response, _url
from vpn_manager.health.wire import _remaining


def probe_path(
    socks_host,
    socks_port,
    download_url,
    egress_url,
    expected_exit_ips,
    bytes_required=131072,
    timeout=15,
) -> dict:
    """Probe only through the supplied local SOCKS route; errors are fixed codes."""
    started = time.monotonic()
    result = _empty_result()
    try:
        plan = _probe_settings(
            socks_host,
            socks_port,
            download_url,
            egress_url,
            expected_exit_ips,
            bytes_required,
            timeout,
            started,
        )
    except _ProbeError as error:
        result["error"] = error.args[0]
    except (ValueError, TypeError, OverflowError):
        result["error"] = "invalid_configuration"
    else:
        _run_probe(result, plan, bytes_required, started)
    result["total_time_ms"] = (time.monotonic() - started) * 1000
    return result


def _empty_result():
    return {
        "success": False,
        "error": None,
        "status_code": None,
        "egress_status_code": None,
        "latency_ms": None,
        "body_bytes": 0,
        "download_time_ms": None,
        "total_time_ms": None,
        "throughput_bps": None,
        "exit_ip_verified": False,
    }


def _probe_settings(
    socks_host,
    socks_port,
    download_url,
    egress_url,
    expected_exit_ips,
    bytes_required,
    timeout,
    started,
):
    timeout = _number(timeout, "timeout", 0)
    if timeout == 0:
        raise ValueError("invalid timeout")
    deadline = started + timeout
    _integer(bytes_required, "bytes_required", _MIN_BODY)
    if bytes_required > _MAX_BODY:
        raise ValueError("invalid bytes_required")
    proxy = _proxy_address(socks_host, socks_port)
    expected = _expected_addresses(expected_exit_ips)
    if not egress_url:
        raise _ProbeError("egress_url_required")
    download = _url(download_url)
    egress = _url(egress_url)
    return proxy, download, egress, expected, deadline


def _proxy_address(socks_host, socks_port):
    _integer(socks_port, "socks_port")
    if socks_port > 65535 or not isinstance(socks_host, str) or "%" in socks_host:
        raise ValueError("invalid proxy")
    local = ipaddress.ip_address(
        "127.0.0.1" if socks_host == "localhost" else socks_host
    )
    if not local.is_loopback:
        raise ValueError("invalid proxy")
    proxy = (
        socket.AF_INET if local.version == 4 else socket.AF_INET6,
        (str(local), socks_port),
    )
    return proxy


def _expected_addresses(expected_exit_ips):
    if not expected_exit_ips:
        raise _ProbeError("expected_exit_ips_required")
    if not isinstance(expected_exit_ips, (list, tuple, set, frozenset)):
        raise ValueError("invalid expected IPs")
    expected = set()
    for ip in expected_exit_ips:
        if not isinstance(ip, str) or "%" in ip:
            raise ValueError("invalid expected IP")
        expected.add(ipaddress.ip_address(ip))
    return expected


def _run_probe(result, plan, bytes_required, started):
    proxy, download, egress, expected, deadline = plan
    download_finished = None
    try:
        context = ssl.create_default_context()
        download_finished = _download(
            result, proxy, download, context, deadline, bytes_required, started
        )
        _verify_egress(result, proxy, egress, context, deadline, expected)
        _remaining(deadline)
        result["success"] = True
    except _ProbeError as error:
        result["error"] = error.args[0]
    except ssl.SSLCertVerificationError:
        result["error"] = "tls_verification_failed"
    except TimeoutError:
        result["error"] = "timeout"
    except ssl.SSLError:
        result["error"] = "tls_failed"
    except OverflowError:
        result["error"] = "invalid_configuration"
    except (http.client.HTTPException, ValueError):
        result["error"] = "invalid_http"
    except OSError:
        result["error"] = "connection_failed"
    finally:
        elapsed = (download_finished or time.monotonic()) - started
        result["download_time_ms"] = elapsed * 1000
        if elapsed > 0:
            result["throughput_bps"] = result["body_bytes"] * 8 / elapsed


def _download(result, proxy, download, context, deadline, bytes_required, started):
    with ExitStack() as stack:
        response, wire = _response(
            stack, proxy, download, context, deadline, bytes_required
        )
        result["status_code"] = response.status
        result["latency_ms"] = (wire.first_byte_at - started) * 1000
        if not 200 <= response.status < 300:
            raise _ProbeError("http_status")
        while result["body_bytes"] < bytes_required:
            chunk = response.read(min(16384, bytes_required - result["body_bytes"]))
            _remaining(deadline)
            if not chunk:
                raise _ProbeError("body_too_short")
            result["body_bytes"] += len(chunk)
        return time.monotonic()


def _verify_egress(result, proxy, egress, context, deadline, expected):
    with ExitStack() as stack:
        response, _ = _response(stack, proxy, egress, context, deadline, _MAX_JSON + 1)
        result["egress_status_code"] = response.status
        if not 200 <= response.status < 300:
            raise _ProbeError("egress_http_status")
        if response.length is not None and response.length > _MAX_JSON:
            raise _ProbeError("response_too_large")
        body = response.read(_MAX_JSON + 1)
        _remaining(deadline)
        if len(body) > _MAX_JSON:
            raise _ProbeError("response_too_large")
        if response.length not in (None, 0):
            raise _ProbeError("invalid_http")
        try:
            data = json.loads(body)
            ip = data["ip"]
            if not isinstance(ip, str) or "%" in ip:
                raise ValueError("invalid IP")
            observed = ipaddress.ip_address(ip)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise _ProbeError("invalid_egress_response") from None
        if observed not in expected:
            raise _ProbeError("exit_ip_mismatch")
        result["exit_ip_verified"] = True
