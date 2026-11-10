"""Standalone health decisions and an opt-in, stdlib-only SOCKS5 HTTPS probe.

Public API (no persistence, scheduling, routing changes, or default probe URLs):

* select_route(policy, upstreams, health, now) -> stable upstream ID or None.
  Policies use ``type`` and an ordered ``upstreams`` list, matching v4 policy
  records. Types: upstream (exactly one member), priority, balanced. Priority
  optionally takes ``current_upstream`` and ``cooldown`` (seconds, default 60).
  A healthy current member is kept until a preferred member's ``restored_at``
  is at least cooldown seconds old. Without a healthy current member, failover
  is immediate. Balanced minimizes ``latency_ms``; absent measurements sort
  last and ties follow member order. Missing, disabled, or nonhealthy members
  are excluded. Direct/block return None for the orchestrator to handle;
  None never authorizes direct fallback. Unknown policy types raise ValueError.
* record_probe(previous, result, now, config) -> new health dictionary.
  Config: ``interval`` (30 seconds), ``fail_threshold`` (3),
  ``success_threshold`` (3). ``cooldown`` (60) is validated here and supplied
  separately to priority policies by the orchestrator. Status starts unknown;
  consecutive results transition it to healthy/unhealthy at the thresholds.
  Success requires both success and exit_ip_verified to be exactly True.
  ``restored_at`` marks each transition to healthy, not each successful probe.
  ``next_probe_at`` is advisory: callers schedule probes and pass ordered
  timestamps; every call records an actual observation, even within interval.
* probe_path(socks_host, socks_port, download_url, egress_url,
  expected_exit_ips, bytes_required=131072, timeout=15) -> result dictionary.
  Both URLs must be operator-configured HTTPS URLs without credentials or
  fragments. Success requires 2xx responses, at least bytes_required body
  bytes, and an egress JSON object {"ip": "literal IPv4 or IPv6 address"}
  matching a nonempty expected_exit_ips sequence. Missing verification config
  fails before any connection. There is no unverified healthy mode.

Probe results contain success, error (a fixed code or None), status_code,
egress_status_code, latency_ms (time to first download HTTP octet, including
SOCKS/TLS setup), body_bytes, download_time_ms, total_time_ms, throughput_bps
(body bits / complete download sample time), and exit_ip_verified. Failed
probes may contain partial measurements. record_probe copies these metrics
and adds status, consecutive_failures, consecutive_successes, last_probe,
next_probe_at, last_success, restored_at. Inputs are never mutated.

Limits: unauthenticated SOCKS5 on numeric loopback (localhost means 127.0.0.1);
target DNS is performed by SOCKS, never locally. TLS uses system trust and
hostname verification. No redirects, retries, decompression, or proxy env vars.
Download samples are 128 KiB..16 MiB and stop at the requested size, without
reading the rest of a larger response. Egress JSON is at most 16 KiB. Header
reads and additional wire/framing bytes each have a 64 KiB budget. One
monotonic deadline covers both requests, including each underlying read, so
trickling headers/chunks cannot reset it. OS scheduling and certificate-store
loading cannot be preempted. Separate connections use the same SOCKS listener;
the operator must dedicate that listener to one upstream (this module cannot
prove listener routing or end-client reachability). No endpoint data, URLs,
credentials, exception text, or observed exit addresses enter error messages.

Protocol references: https://www.rfc-editor.org/rfc/rfc1928 and
https://docs.python.org/3/library/ssl.html#ssl.create_default_context
"""

import http.client
import io
import ipaddress
import json
import math
import socket
import ssl
import time
from contextlib import ExitStack
from typing import Any
from urllib.parse import urlsplit

__all__ = ["select_route", "record_probe", "probe_path"]

_MIN_BODY = 131072
_MAX_BODY = 16 * 1024 * 1024
_MAX_JSON = 16 * 1024
_WIRE_OVERHEAD = 64 * 1024
_METRICS = ("latency_ms", "download_time_ms", "total_time_ms", "throughput_bps")
_ERROR_CODES = frozenset(
    {
        "invalid_configuration",
        "expected_exit_ips_required",
        "egress_url_required",
        "timeout",
        "connection_failed",
        "socks_protocol",
        "socks_authentication",
        "socks_connect_failed",
        "tls_verification_failed",
        "tls_failed",
        "invalid_http",
        "http_status",
        "egress_http_status",
        "unsupported_encoding",
        "response_too_large",
        "body_too_short",
        "invalid_egress_response",
        "exit_ip_mismatch",
        "exit_ip_unverified",
        "runtime_version_mismatch",
        "probe_failed",
        "compose_config_failed",
        "host_network_required",
        "invalid_upstream",
        "probe_setup_failed",
        "probe_start_failed",
        "probe_start_timeout",
        "probe_cleanup_failed",
    }
)


def _number(value, name, minimum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("invalid " + name)
    try:
        number = float(value)
    except OverflowError:
        raise ValueError("invalid " + name) from None
    if not math.isfinite(number) or (minimum is not None and number < minimum):
        raise ValueError("invalid " + name)
    return number


def _integer(value, name, minimum=1):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError("invalid " + name)
    return value


def select_route(policy: dict, upstreams: dict, health: dict, now: float) -> str | None:
    """Return an eligible stable ID; see module docstring for policy fields."""
    now = _number(now, "now")
    kind = policy.get("type")
    if kind in ("direct", "block"):
        return None
    if kind not in ("upstream", "priority", "balanced"):
        raise ValueError("unsupported policy type")
    members = policy.get("upstreams", [])
    if (
        not isinstance(members, list)
        or any(not isinstance(x, str) for x in members)
        or len(set(members)) != len(members)
        or (kind == "upstream" and len(members) != 1)
    ):
        raise ValueError("invalid policy upstreams")
    candidates = [
        uid
        for uid in members
        if uid in upstreams
        and upstreams[uid].get("enabled", True)
        and health.get(uid, {}).get("status") == "healthy"
    ]
    if not candidates:
        return None
    if kind == "balanced":

        def latency(uid):
            value = health[uid].get("latency_ms")
            try:
                return _number(value, "latency_ms", 0)
            except ValueError:
                return math.inf

        return min(candidates, key=latency)
    if kind == "priority":
        cooldown = _number(policy.get("cooldown", 60), "cooldown", 0)
        current = policy.get("current_upstream")
        if current in candidates:
            for uid in candidates[: candidates.index(current)]:
                restored = health[uid].get("restored_at")
                if cooldown == 0:
                    return uid
                if restored is not None:
                    restored = _number(restored, "restored_at")
                    if now - restored >= cooldown:
                        return uid
            return current
    return candidates[0]


def record_probe(previous: dict, result: dict, now: float, config: dict) -> dict:
    """Apply one observation; interval schedules the next call, not this one."""
    now = _number(now, "now")
    interval = _number(config.get("interval", 30), "interval", 0)
    _number(config.get("cooldown", 60), "cooldown", 0)
    fail_threshold = _integer(config.get("fail_threshold", 3), "fail_threshold")
    success_threshold = _integer(
        config.get("success_threshold", 3), "success_threshold"
    )
    if previous.get("last_probe") is not None and now < _number(
        previous["last_probe"], "last_probe"
    ):
        raise ValueError("out of order probe")
    status = previous.get("status", "unknown")
    if status not in ("unknown", "healthy", "unhealthy"):
        raise ValueError("invalid health status")
    verified = result.get("exit_ip_verified") is True
    unverified = result.get("success") is True and not verified
    success = result.get("success") is True and verified
    failures = (
        0
        if success
        else _integer(previous.get("consecutive_failures", 0), "failures", 0) + 1
    )
    successes = (
        _integer(previous.get("consecutive_successes", 0), "successes", 0) + 1
        if success
        else 0
    )
    restored_at = previous.get("restored_at")
    if success and successes >= success_threshold and status != "healthy":
        status, restored_at = "healthy", now
    elif not success and failures >= fail_threshold:
        status, restored_at = "unhealthy", None
    state = {
        "status": status,
        "success": success,
        "consecutive_failures": failures,
        "consecutive_successes": successes,
        "last_probe": now,
        "next_probe_at": _number(now + interval, "next_probe_at"),
        "last_success": now if success else previous.get("last_success"),
        "restored_at": restored_at,
        "error": None
        if success
        else "exit_ip_unverified"
        if unverified
        else (
            result.get("error")
            if isinstance(result.get("error"), str) and result["error"] in _ERROR_CODES
            else "probe_failed"
        ),
        "exit_ip_verified": verified,
    }
    for key in _METRICS:
        try:
            state[key] = _number(result.get(key), key, 0)
        except ValueError:
            state[key] = None
    for key in ("status_code", "egress_status_code", "body_bytes"):
        value = result.get(key)
        valid = (
            isinstance(value, int)
            and not isinstance(value, bool)
            and (value >= 0 if key == "body_bytes" else 100 <= value <= 599)
        )
        state[key] = value if valid else (0 if key == "body_bytes" else None)
    return state


class _ProbeError(Exception):
    pass


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _ProbeError("timeout")
    return remaining


def _recv_exact(sock, count, deadline):
    data = bytearray()
    while len(data) < count:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(count - len(data))
        _remaining(deadline)
        if not chunk:
            raise _ProbeError("socks_protocol")
        data.extend(chunk)
    return bytes(data)


def _send(sock, data, deadline):
    sock.settimeout(_remaining(deadline))
    sock.sendall(data)
    _remaining(deadline)


def _url(value):
    if (
        not isinstance(value, str)
        or len(value) > 8192
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("invalid URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "#" in value
    ):
        raise ValueError("invalid URL")
    host = parsed.hostname.encode("idna").decode("ascii")
    if "%" in host:
        raise ValueError("invalid host")
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (c.isalnum() or c == "-") for c in label)
            for label in labels
        ):
            raise ValueError("invalid host")
        encoded = host.encode("ascii")
        destination = b"\x03" + bytes([len(encoded)]) + encoded
        authority = host
    else:
        destination = (b"\x01" if address.version == 4 else b"\x04") + address.packed
        authority = "[" + host + "]" if address.version == 6 else host
    if port != 443:
        authority += ":" + str(port)
    target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    request = (
        "GET "
        + target
        + " HTTP/1.1\r\nHost: "
        + authority
        + "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    return host, destination + port.to_bytes(2, "big"), request


class _WireReader(io.RawIOBase):
    """Recheck a single deadline on *every* recv, including buffered HTTP reads."""

    def __init__(self, sock, deadline):
        super().__init__()
        self.sock = sock
        self.deadline = deadline
        self.limit = _WIRE_OVERHEAD
        self.received = 0
        self.first_byte_at = None

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(_remaining(self.deadline))
        data = self.sock.recv(min(len(buffer), self.limit - self.received + 1))
        _remaining(self.deadline)
        if data and self.first_byte_at is None:
            self.first_byte_at = time.monotonic()
        self.received += len(data)
        if self.received > self.limit:
            raise _ProbeError("response_too_large")
        buffer[: len(data)] = data
        return len(data)

    def makefile(self, mode):
        return io.BufferedReader(self, buffer_size=8192)


def _response(stack, proxy, destination, context, deadline, max_body):
    host, address, request = destination
    family, proxy_address = proxy
    raw = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
    raw.settimeout(_remaining(deadline))
    raw.connect(proxy_address)
    _send(raw, b"\x05\x01\x00", deadline)
    greeting = _recv_exact(raw, 2, deadline)
    if greeting[0] != 5:
        raise _ProbeError("socks_protocol")
    if greeting[1] != 0:
        raise _ProbeError("socks_authentication")
    _send(raw, b"\x05\x01\x00" + address, deadline)
    reply = _recv_exact(raw, 4, deadline)
    if reply[0] != 5 or reply[2] != 0:
        raise _ProbeError("socks_protocol")
    if reply[1] != 0:
        raise _ProbeError("socks_connect_failed")
    if reply[3] == 1:
        length = 4
    elif reply[3] == 4:
        length = 16
    elif reply[3] == 3:
        length = _recv_exact(raw, 1, deadline)[0]
        if not length:
            raise _ProbeError("socks_protocol")
    else:
        raise _ProbeError("socks_protocol")
    _recv_exact(raw, length + 2, deadline)
    raw.settimeout(_remaining(deadline))
    tls = stack.enter_context(
        context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
    )
    tls.settimeout(_remaining(deadline))
    tls.do_handshake()
    _send(tls, request, deadline)
    wire = _WireReader(tls, deadline)
    response = stack.enter_context(http.client.HTTPResponse(wire))
    response.begin()
    wire.limit = max_body + _WIRE_OVERHEAD
    lengths = response.headers.get_all("Content-Length", [])
    transfer = response.headers.get_all("Transfer-Encoding", [])
    if (
        len(lengths) > 1
        or (lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()))
        or (
            transfer
            and (len(transfer) != 1 or transfer[0].lower() != "chunked" or lengths)
        )
    ):
        raise _ProbeError("invalid_http")
    if response.getheader("Content-Encoding", "identity").lower() != "identity":
        raise _ProbeError("unsupported_encoding")
    return response, wire


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
    result: dict[str, Any] = {
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
    try:
        timeout = _number(timeout, "timeout", 0)
        if timeout == 0:
            raise ValueError("invalid timeout")
        deadline = started + timeout
        _integer(bytes_required, "bytes_required", _MIN_BODY)
        if bytes_required > _MAX_BODY:
            raise ValueError("invalid bytes_required")
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
        if not expected_exit_ips:
            raise _ProbeError("expected_exit_ips_required")
        if not isinstance(expected_exit_ips, (list, tuple, set, frozenset)):
            raise ValueError("invalid expected IPs")
        expected = set()
        for ip in expected_exit_ips:
            if not isinstance(ip, str) or "%" in ip:
                raise ValueError("invalid expected IP")
            expected.add(ipaddress.ip_address(ip))
        if not egress_url:
            raise _ProbeError("egress_url_required")
        download = _url(download_url)
        egress = _url(egress_url)
    except _ProbeError as error:
        result["error"] = error.args[0]
    except (ValueError, TypeError, OverflowError):
        result["error"] = "invalid_configuration"
    else:
        download_finished = None
        try:
            context = ssl.create_default_context()
            with ExitStack() as stack:
                response, wire = _response(
                    stack, proxy, download, context, deadline, bytes_required
                )
                result["status_code"] = response.status
                result["latency_ms"] = (wire.first_byte_at - started) * 1000
                if not 200 <= response.status < 300:
                    raise _ProbeError("http_status")
                while result["body_bytes"] < bytes_required:
                    chunk = response.read(
                        min(16384, bytes_required - result["body_bytes"])
                    )
                    _remaining(deadline)
                    if not chunk:
                        raise _ProbeError("body_too_short")
                    result["body_bytes"] += len(chunk)
                download_finished = time.monotonic()
            with ExitStack() as stack:
                response, _ = _response(
                    stack, proxy, egress, context, deadline, _MAX_JSON + 1
                )
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
    result["total_time_ms"] = (time.monotonic() - started) * 1000
    return result
