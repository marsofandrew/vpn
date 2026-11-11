import math

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


class _ProbeError(Exception):
    pass
