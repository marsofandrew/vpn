import uuid
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values


def first_query_value(
    query: dict[str, list[str]], key: str, default: str | None = None
) -> str | None:
    values = query.get(key)
    if not values:
        return default
    return values[0]


def parse_upstream_link(link: str) -> dict[str, Any]:
    parsed = urlparse(link.strip())
    if parsed.scheme != "vless":
        raise app_errors.VpnctlError("upstream link must use the vless:// scheme")
    if not parsed.username:
        raise app_errors.VpnctlError("upstream VLESS link is missing the client UUID")
    try:
        client_id = str(uuid.UUID(parsed.username))
    except ValueError as error:
        raise app_errors.VpnctlError(
            "upstream VLESS link has an invalid client UUID"
        ) from error
    if not parsed.hostname:
        raise app_errors.VpnctlError("upstream VLESS link is missing the host")
    try:
        port = app_values.parse_port(parsed.port or app_settings.DEFAULT_PORT)
    except ValueError as error:
        raise app_errors.VpnctlError(
            "upstream VLESS link has an invalid port"
        ) from error

    query = parse_qs(parsed.query)
    security = first_query_value(query, "security")
    if security != "reality":
        raise app_errors.VpnctlError("upstream VLESS link must use security=reality")
    network = first_query_value(query, "type", "tcp")
    if network != "tcp":
        raise app_errors.VpnctlError("upstream VLESS link must use type=tcp")
    encryption = first_query_value(query, "encryption", "none")
    if encryption != "none":
        raise app_errors.VpnctlError("upstream VLESS link must use encryption=none")

    public_key = first_query_value(query, "pbk")
    server_name = first_query_value(query, "sni")
    short_id = first_query_value(query, "sid") or first_query_value(query, "shortid")
    if not public_key:
        raise app_errors.VpnctlError("upstream VLESS link is missing pbk")
    if not server_name:
        raise app_errors.VpnctlError("upstream VLESS link is missing sni")
    if short_id is None:
        raise app_errors.VpnctlError("upstream VLESS link is missing sid or shortid")

    return {
        "link_label": unquote(parsed.fragment) if parsed.fragment else None,
        "host": parsed.hostname,
        "port": port,
        "id": client_id,
        "encryption": encryption,
        "network": network,
        "security": security,
        "public_key": public_key,
        "server_name": server_name,
        "short_id": short_id,
        "fingerprint": first_query_value(query, "fp", app_settings.DEFAULT_FINGERPRINT),
        "flow": first_query_value(query, "flow", app_settings.DEFAULT_FLOW),
        "spider_x": first_query_value(query, "spx", app_settings.DEFAULT_SPIDER_X),
    }


def validate_upstream(upstream: dict[str, Any] | None) -> None:
    if not upstream:
        raise app_errors.VpnctlError("upstream VLESS link is required")
    required_fields = ("host", "port", "id", "public_key", "server_name", "short_id")
    for field in required_fields:
        if upstream.get(field) in (None, ""):
            raise app_errors.VpnctlError(f"upstream is missing {field}")
    app_values.parse_port(upstream["port"])
    try:
        uuid.UUID(upstream["id"])
    except ValueError as error:
        raise app_errors.VpnctlError("upstream has an invalid client UUID") from error
