#!/usr/bin/env python3
import argparse
import base64
import fcntl
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import qrcode
import vpn_transports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


STATE_VERSION = 4
DEFAULT_STATE_PATH = Path("data/vpn_state.json")
DEFAULT_CONFIG_PATH = Path("data/config.json")
DEFAULT_COMPOSE_FILE = Path("docker-compose.yaml")
DEFAULT_PROFILE_NAME = "default"
DEFAULT_PORT = 443
DEFAULT_API_PORT = 10085
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_FLOW = "xtls-rprx-vision"
DEFAULT_SPIDER_X = "/"
OUTBOUND_DIRECT = "direct"
OUTBOUND_PROXY = "proxy"
OUTBOUND_MODES = {OUTBOUND_DIRECT, OUTBOUND_PROXY}
UPSTREAM_OUTBOUND_TAG = "main_vpn"
XRAY_SERVICE = "xray"
SIZE_UNITS = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}


class VpnctlError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def current_usage_period() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def encode_x25519_key(key_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode("ascii")


def decode_x25519_key(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        key_bytes = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as error:
        raise VpnctlError("invalid X25519 key encoding") from error
    if len(key_bytes) != 32:
        raise VpnctlError("X25519 keys must decode to 32 bytes")
    return key_bytes


def public_key_from_private(private_key: str) -> str:
    key = x25519.X25519PrivateKey.from_private_bytes(decode_x25519_key(private_key))
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return encode_x25519_key(public_bytes)


def generate_reality_keys() -> dict[str, str]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "private_key": encode_x25519_key(private_bytes),
        "public_key": encode_x25519_key(public_bytes),
    }


def parse_size(value: str | None) -> int | None:
    if value is None:
        return None
    raw = value.strip().lower()
    if not raw:
        raise VpnctlError("quota cannot be empty")

    number_part = ""
    unit_part = ""
    for char in raw:
        if char.isdigit() or char == ".":
            if unit_part:
                raise VpnctlError(f"invalid quota size: {value}")
            number_part += char
        elif char.isalpha():
            unit_part += char
        elif char.isspace():
            continue
        else:
            raise VpnctlError(f"invalid quota size: {value}")

    if not number_part:
        raise VpnctlError(f"invalid quota size: {value}")
    unit = unit_part or "b"
    if unit not in SIZE_UNITS:
        raise VpnctlError(
            f"invalid quota unit '{unit_part}'. Use bytes, KB, MB, GB, KiB, MiB, GiB, or TiB."
        )
    return int(float(number_part) * SIZE_UNITS[unit])


def parse_port(value: str | int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def format_size(value: int | None) -> str:
    if value is None:
        return "unlimited"
    for unit, multiplier in (("TiB", 1024**4), ("GiB", 1024**3), ("MiB", 1024**2)):
        if value >= multiplier:
            return f"{value / multiplier:.2f} {unit}"
    return f"{value} B"


def split_host_port(target: str) -> tuple[str, int | None]:
    if ":" not in target:
        return target, None
    host, port = target.rsplit(":", 1)
    if not port.isdigit():
        return target, None
    return host, int(port)


def validate_server_host(host: str | None) -> str:
    raw = (host or "").strip()
    if not raw:
        raise VpnctlError("server host cannot be empty")
    if "://" in raw:
        raise VpnctlError("server host must not include a URL scheme")
    if any(char in raw for char in "/?#@"):
        raise VpnctlError("server host must be a hostname or IP address only")
    if raw.startswith("[") or raw.endswith("]"):
        if not (raw.startswith("[") and raw.endswith("]") and ":" in raw[1:-1]):
            raise VpnctlError("invalid bracketed IPv6 server host")
        return raw
    if ":" in raw:
        raise VpnctlError("server host must not include a port; profile ports are added to client links")
    return raw


def first_query_value(query: dict[str, list[str]], key: str, default: str | None = None) -> str | None:
    values = query.get(key)
    if not values:
        return default
    return values[0]


def parse_upstream_link(link: str) -> dict[str, Any]:
    parsed = urlparse(link.strip())
    if parsed.scheme != "vless":
        raise VpnctlError("upstream link must use the vless:// scheme")
    if not parsed.username:
        raise VpnctlError("upstream VLESS link is missing the client UUID")
    try:
        client_id = str(uuid.UUID(parsed.username))
    except ValueError as error:
        raise VpnctlError("upstream VLESS link has an invalid client UUID") from error
    if not parsed.hostname:
        raise VpnctlError("upstream VLESS link is missing the host")
    try:
        port = parse_port(parsed.port or DEFAULT_PORT)
    except ValueError as error:
        raise VpnctlError("upstream VLESS link has an invalid port") from error

    query = parse_qs(parsed.query)
    security = first_query_value(query, "security")
    if security != "reality":
        raise VpnctlError("upstream VLESS link must use security=reality")
    network = first_query_value(query, "type", "tcp")
    if network != "tcp":
        raise VpnctlError("upstream VLESS link must use type=tcp")
    encryption = first_query_value(query, "encryption", "none")
    if encryption != "none":
        raise VpnctlError("upstream VLESS link must use encryption=none")

    public_key = first_query_value(query, "pbk")
    server_name = first_query_value(query, "sni")
    short_id = first_query_value(query, "sid") or first_query_value(query, "shortid")
    if not public_key:
        raise VpnctlError("upstream VLESS link is missing pbk")
    if not server_name:
        raise VpnctlError("upstream VLESS link is missing sni")
    if short_id is None:
        raise VpnctlError("upstream VLESS link is missing sid or shortid")

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
        "fingerprint": first_query_value(query, "fp", DEFAULT_FINGERPRINT),
        "flow": first_query_value(query, "flow", DEFAULT_FLOW),
        "spider_x": first_query_value(query, "spx", DEFAULT_SPIDER_X),
    }


def validate_upstream(upstream: dict[str, Any] | None) -> None:
    if not upstream:
        raise VpnctlError("upstream VLESS link is required")
    required_fields = ("host", "port", "id", "public_key", "server_name", "short_id")
    for field in required_fields:
        if upstream.get(field) in (None, ""):
            raise VpnctlError(f"upstream is missing {field}")
    parse_port(upstream["port"])
    try:
        uuid.UUID(upstream["id"])
    except ValueError as error:
        raise VpnctlError("upstream has an invalid client UUID") from error


def validate_outbound_mode(mode: str | None) -> str:
    normalized = (mode or OUTBOUND_DIRECT).strip().lower()
    if normalized not in OUTBOUND_MODES:
        raise VpnctlError(f"invalid outbound mode: {mode}. Use direct or proxy.")
    return normalized


def safe_client_email(name: str, default_domain: str) -> str:
    local = "".join(char if char.isalnum() or char in "._-" else "-" for char in name)
    local = local.strip(".-_") or "client"
    return f"{local}@{default_domain}"


def client_email(name: str, default_domain: str, profile_name: str = DEFAULT_PROFILE_NAME) -> str:
    if profile_name == DEFAULT_PROFILE_NAME:
        return safe_client_email(name, default_domain)
    return safe_client_email(f"{profile_name}-{name}", default_domain)


def create_client(
    name: str,
    default_domain: str,
    quota_bytes: int | None = None,
    profile_name: str = DEFAULT_PROFILE_NAME,
) -> dict[str, Any]:
    now = utc_now()
    return {
        "name": name,
        "id": str(uuid.uuid4()),
        "email": client_email(name, default_domain, profile_name),
        "enabled": True,
        "quota_bytes": quota_bytes,
        "used_uplink_bytes": 0,
        "used_downlink_bytes": 0,
        "created_at": now,
        "updated_at": now,
        "disabled_reason": None,
    }


def validate_profile_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise VpnctlError("profile name cannot be empty")
    if any(char.isspace() for char in normalized):
        raise VpnctlError("profile name cannot contain whitespace")
    return normalized


def create_profile(
    name: str,
    reality_target: str,
    default_domain: str,
    port: int,
    client_names: list[str],
    quota_bytes: int | None,
    outbound_mode: str = OUTBOUND_DIRECT,
) -> dict[str, Any]:
    keys = generate_reality_keys()
    now = utc_now()
    profile_name = validate_profile_name(name)
    return {
        "name": profile_name,
        "created_at": now,
        "updated_at": now,
        "port": parse_port(port),
        "reality_target": reality_target,
        "outbound_mode": validate_outbound_mode(outbound_mode),
        "short_id": os.urandom(8).hex(),
        "keys": keys,
        "clients": [
            create_client(client_name, default_domain, quota_bytes, profile_name)
            for client_name in deduplicate_names(client_names)
        ],
    }


def create_state(
    server_host: str,
    reality_target: str,
    default_domain: str,
    port: int | None,
    client_names: list[str],
    quota_bytes: int | None,
    profile_name: str = DEFAULT_PROFILE_NAME,
    upstream_link: str | None = None,
    mode: str = OUTBOUND_DIRECT,
    direct_port: int = DEFAULT_PORT,
    proxy_port: int = 8443,
) -> dict[str, Any]:
    now = utc_now()
    init_mode = mode.strip().lower()
    if init_mode not in {"direct", "proxy", "both"}:
        raise VpnctlError("init mode must be direct, proxy, or both")
    upstream = parse_upstream_link(upstream_link) if upstream_link else None
    profiles: list[dict[str, Any]]
    if init_mode == "both":
        profiles = [
            create_profile("direct", reality_target, default_domain, direct_port, client_names, quota_bytes, OUTBOUND_DIRECT),
            create_profile("proxy", reality_target, default_domain, proxy_port, client_names, quota_bytes, OUTBOUND_PROXY),
        ]
    else:
        profile_port = port if port is not None else DEFAULT_PORT
        profiles = [
            create_profile(profile_name, reality_target, default_domain, profile_port, client_names, quota_bytes, init_mode)
        ]
    normalized_server_host = validate_server_host(server_host)
    return upgrade_state({
        "version": 3,
        "created_at": now,
        "updated_at": now,
        "usage_period": current_usage_period(),
        "server_host": normalized_server_host,
        "default_domain": default_domain,
        "fingerprint": DEFAULT_FINGERPRINT,
        "flow": DEFAULT_FLOW,
        "spider_x": DEFAULT_SPIDER_X,
        "upstream": upstream,
        "profiles": profiles,
    })


def imported_profile_name(tag: str | None, fallback: str) -> str:
    raw = tag or fallback
    if raw.startswith("vless_reality_"):
        raw = raw.removeprefix("vless_reality_")
    return validate_profile_name(raw or fallback)


def infer_default_domain(config: dict[str, Any], fallback: str) -> str:
    domains: set[str] = set()
    for inbound in config.get("inbounds", []):
        for client in inbound.get("settings", {}).get("clients", []):
            email = client.get("email", "")
            if "@" in email:
                domains.add(email.rsplit("@", 1)[1])
    return domains.pop() if len(domains) == 1 else fallback


def imported_client_name(email: str, client_id: str, profile_name: str) -> str:
    if email and "@" in email:
        local = email.rsplit("@", 1)[0]
    else:
        local = client_id
    prefix = f"{profile_name}-"
    if local.startswith(prefix):
        local = local[len(prefix):]
    return local or client_id


def import_client(client: dict[str, Any], profile_name: str, default_domain: str) -> dict[str, Any]:
    now = utc_now()
    client_id = client.get("id")
    if not client_id:
        raise VpnctlError(f"profile {profile_name} has a VLESS client without id")
    email = client.get("email") or safe_client_email(imported_client_name("", client_id, profile_name), default_domain)
    return {
        "name": imported_client_name(email, client_id, profile_name),
        "id": client_id,
        "email": email,
        "enabled": True,
        "quota_bytes": None,
        "used_uplink_bytes": 0,
        "used_downlink_bytes": 0,
        "created_at": now,
        "updated_at": now,
        "disabled_reason": None,
    }


def routing_outbound_by_inbound(config: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for rule in config.get("routing", {}).get("rules", []):
        if set(rule) - {"type", "inboundTag", "outboundTag"} or not rule.get("inboundTag"):
            raise VpnctlError("import cannot preserve conditional or default routing rules")
        outbound_tag = rule.get("outboundTag")
        inbound_tags = rule.get("inboundTag", [])
        if isinstance(inbound_tags, str):
            inbound_tags = [inbound_tags]
        for inbound_tag in inbound_tags:
            if inbound_tag and outbound_tag:
                if inbound_tag in result:
                    raise VpnctlError("import cannot preserve overlapping inbound rules")
                result[inbound_tag] = outbound_tag
    return result


def import_upstream_from_outbound(outbound: dict[str, Any]) -> dict[str, Any]:
    stream_settings = outbound.get("streamSettings", {})
    reality_settings = stream_settings.get("realitySettings", {})
    vnext = outbound.get("settings", {}).get("vnext", [])
    if not vnext:
        raise VpnctlError("upstream outbound is missing vnext")
    server = vnext[0]
    users = server.get("users", [])
    if not users:
        raise VpnctlError("upstream outbound is missing users")
    user = users[0]
    if len(vnext) != 1 or len(users) != 1:
        raise VpnctlError("import requires one remote and one authentication identity per outbound")
    network = stream_settings.get("network", "tcp")
    security_type = stream_settings.get("security")
    tls = stream_settings.get("tlsSettings", {})
    if tls.get("allowInsecure"):
        raise VpnctlError("insecure TLS upstreams cannot be imported")
    xhttp = stream_settings.get("xhttpSettings", {})
    if set(xhttp) - {"path", "host", "mode"}:
        raise VpnctlError("unsupported XHTTP import settings")
    query = {"type": network, "security": security_type, "encryption": user.get("encryption", "none"),
             "flow": user.get("flow", DEFAULT_FLOW if network == "tcp" else ""),
             "sni": reality_settings.get("serverName", "") if security_type == "reality" else tls.get("serverName", "")}
    if security_type == "reality":
        query.update({"pbk": reality_settings.get("publicKey", ""), "sid": reality_settings.get("shortId", ""),
                      "fp": reality_settings.get("fingerprint", DEFAULT_FINGERPRINT),
                      "spx": reality_settings.get("spiderX", "/")})
    elif tls.get("alpn"):
        query["alpn"] = ",".join(tls["alpn"])
    if network == "xhttp":
        query.update({"path": xhttp.get("path", "/"), "host": xhttp.get("host", ""),
                      "mode": xhttp.get("mode", "stream-one" if security_type == "reality" else "auto")})
    address = server["address"]
    if ":" in address:
        address = f"[{address}]"
    try:
        return vpn_transports.parse_link(f"vless://{user['id']}@{address}:{server['port']}?{urlencode(query)}")
    except ValueError as error:
        raise VpnctlError(str(error)) from None


def import_state_from_xray_config(
    config: dict[str, Any],
    server_host: str,
    default_domain: str | None = None,
) -> dict[str, Any]:
    now = utc_now()
    domain = default_domain or infer_default_domain(config, server_host)
    route_by_inbound = routing_outbound_by_inbound(config)
    upstreams = {}
    for outbound in config.get("outbounds", []):
        stream_settings = outbound.get("streamSettings", {})
        if outbound.get("protocol") == "vless":
            name = validate_stable_name(outbound.get("tag", ""))
            if name in upstreams:
                raise VpnctlError("duplicate outbound tag")
            upstreams[name] = import_upstream_from_outbound(outbound)

    profiles: list[dict[str, Any]] = []
    profile_index = 1
    for inbound in config.get("inbounds", []):
        if inbound.get("protocol") != "vless":
            continue
        stream_settings = inbound.get("streamSettings", {})
        if stream_settings.get("security") not in {"reality", "tls"} or stream_settings.get("network", "tcp") not in {"tcp", "xhttp"}:
            raise VpnctlError("unsupported VLESS inbound transport or security")
        reality_settings = stream_settings.get("realitySettings", {})
        private_key = reality_settings.get("privateKey")
        short_ids = reality_settings.get("shortIds") or []
        if stream_settings.get("security") == "reality" and (not private_key or not short_ids):
            raise VpnctlError(f"inbound {inbound.get('tag', profile_index)} is missing REALITY privateKey or shortIds")
        tag = inbound.get("tag") or f"profile{profile_index}"
        profile_name = imported_profile_name(tag, f"profile{profile_index}")
        default_outbound = (config.get("outbounds") or [{}])[0]
        default_tag = default_outbound.get("tag", "direct") if default_outbound.get("protocol", "freedom") == "freedom" else default_outbound.get("tag")
        outbound_tag = route_by_inbound.get(tag, default_tag)
        if outbound_tag not in {"direct", "block", *upstreams}:
            raise VpnctlError("import cannot preserve the inbound's outbound route")
        outbound_mode = OUTBOUND_PROXY if outbound_tag in upstreams else OUTBOUND_DIRECT
        clients = [
            import_client(client, profile_name, domain)
            for client in inbound.get("settings", {}).get("clients", [])
        ]
        profiles.append(
            {
                "name": profile_name,
                "created_at": now,
                "updated_at": now,
                "port": parse_port(inbound.get("port", DEFAULT_PORT)),
                "reality_target": reality_settings.get("target") or reality_settings.get("dest") or "www.cloudflare.com:443",
                "outbound_mode": outbound_mode,
                "short_id": short_ids[0] if short_ids else "",
                "route": outbound_tag,
                "transport": {"type": stream_settings.get("network", "tcp"), "settings": stream_settings.get("xhttpSettings", {})},
                "keys": {
                    "private_key": private_key,
                    "public_key": public_key_from_private(private_key) if private_key else "",
                },
                "clients": clients,
            }
        )
        if stream_settings.get("security") == "tls":
            tls = stream_settings.get("tlsSettings", {})
            profiles[-1]["security"] = {"type": "tls", "settings": {
                "server_name": tls.get("serverName") or profiles[-1]["reality_target"].split(":")[0],
                "certificates": tls.get("certificates", []), "alpn": tls.get("alpn", ["h2", "http/1.1"]),
            }}
        profile_index += 1

    if not profiles:
        raise VpnctlError("Xray config has no VLESS + REALITY inbounds to import")

    state = {
        "version": STATE_VERSION,
        "created_at": now,
        "updated_at": now,
        "usage_period": current_usage_period(),
        "server_host": server_host,
        "default_domain": domain,
        "fingerprint": DEFAULT_FINGERPRINT,
        "flow": DEFAULT_FLOW,
        "spider_x": DEFAULT_SPIDER_X,
        "upstreams": upstreams,
        "routing_policies": {"direct": {"type": "direct"}, "block": {"type": "block"},
                             **{name: {"type": "upstream", "upstreams": [name]} for name in upstreams}},
        "profiles": profiles,
    }
    return upgrade_state(state)


def deduplicate_names(names: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        normalized = name.strip()
        if not normalized:
            raise VpnctlError("client names cannot be empty")
        if normalized in seen:
            raise VpnctlError(f"duplicate client name: {normalized}")
        seen.add(normalized)
        result.append(normalized)
    return result


def all_profiles(state: dict[str, Any]) -> list[dict[str, Any]]:
    return state.setdefault("profiles", [])


def profile_label(profile: dict[str, Any]) -> str:
    return profile.get("name", DEFAULT_PROFILE_NAME)


def require_profile(state: dict[str, Any], name: str | None = None) -> dict[str, Any]:
    profiles = all_profiles(state)
    target = name or DEFAULT_PROFILE_NAME
    for profile in profiles:
        if profile_label(profile) == target:
            return profile
    raise VpnctlError(f"profile not found: {target}")


def find_profile(state: dict[str, Any], name: str) -> dict[str, Any] | None:
    for profile in all_profiles(state):
        if profile_label(profile) == name:
            return profile
    return None


def clients_in_state(state: dict[str, Any]) -> list[dict[str, Any]]:
    clients: list[dict[str, Any]] = []
    for profile in all_profiles(state):
        clients.extend(profile.get("clients", []))
    return clients


def profile_tag(profile: dict[str, Any]) -> str:
    name = profile_label(profile)
    safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    return f"vless_reality_{safe_name or DEFAULT_PROFILE_NAME}"


def profile_outbound_mode(profile: dict[str, Any]) -> str:
    return validate_outbound_mode(profile.get("outbound_mode", OUTBOUND_DIRECT))


def proxy_profiles(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [profile for profile in all_profiles(state) if profile_outbound_mode(profile) == OUTBOUND_PROXY]


def validate_state(state: dict[str, Any], api_port: int = DEFAULT_API_PORT) -> None:
    state["server_host"] = validate_server_host(state.get("server_host"))
    profiles = all_profiles(state)
    if not profiles:
        raise VpnctlError("at least one profile is required")
    if state.get("version") != STATE_VERSION:
        raise VpnctlError("unsupported state version")
    if state["node"]["role"] not in {"gateway", "exit", "both"}:
        raise VpnctlError("invalid node role")
    validate_profile_name(state["node"]["id"])
    for name, upstream in state["upstreams"].items():
        validate_stable_name(name)
        if name in {"direct", "block", "api"}:
            raise VpnctlError("upstream name is reserved")
        try:
            vpn_transports.validate_upstream(upstream)
        except ValueError as error:
            raise VpnctlError(str(error)) from None
    for name, policy in state["routing_policies"].items():
        validate_stable_name(name)
        if policy["type"] not in {"direct", "upstream", "block"}:
            raise VpnctlError("unsupported routing policy")
        if policy["type"] == "upstream":
            members = policy.get("upstreams", [])
            if len(members) != 1 or members[0] not in state["upstreams"]:
                raise VpnctlError("policy must reference one existing upstream")

    names: set[str] = set()
    ports: dict[int, str] = {}
    emails: dict[str, str] = {}
    ids: dict[str, str] = {}
    for profile in profiles:
        name = validate_profile_name(profile_label(profile))
        profile["outbound_mode"] = profile_outbound_mode(profile)
        route = profile.get("route", "direct" if profile["outbound_mode"] == "direct" else UPSTREAM_OUTBOUND_TAG)
        profile["route"] = route
        policy = state["routing_policies"].get(route)
        if policy is None:
            raise VpnctlError("profile references an unknown policy")
        if policy["type"] == "upstream" and not state["upstreams"][policy["upstreams"][0]]["enabled"]:
            raise VpnctlError("profile references a disabled upstream")
        if name in names:
            raise VpnctlError(f"duplicate profile name: {name}")
        names.add(name)
        port = parse_port(profile.get("port", DEFAULT_PORT))
        if port == api_port:
            raise VpnctlError(f"profile {name} uses reserved API port {api_port}")
        if port in ports:
            raise VpnctlError(f"profile {name} uses duplicate port {port} already used by {ports[port]}")
        ports[port] = name

        client_names: set[str] = set()
        for client in profile.get("clients", []):
            client_name = client.get("name", "")
            client_id = client.get("id", "")
            email = client.get("email", "")
            if client_name in client_names:
                raise VpnctlError(f"duplicate client name in profile {name}: {client_name}")
            client_names.add(client_name)
            if client_id in ids:
                raise VpnctlError(f"duplicate client id {client_id} in profiles {ids[client_id]} and {name}")
            if email in emails:
                raise VpnctlError(f"duplicate client email {email} in profiles {emails[email]} and {name}")
            ids[client_id] = name
            emails[email] = name


def migrate_legacy_state(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("version") == STATE_VERSION:
        raw.setdefault("usage_period", current_usage_period())
        validate_state(raw)
        return raw

    if raw.get("version") == 3:
        migrated = upgrade_state(raw)
        validate_state(migrated)
        return migrated

    if raw.get("version") == 2 and "profiles" in raw:
        raw["version"] = 3
        raw.setdefault("usage_period", current_usage_period())
        raw.setdefault("upstream", None)
        for profile in all_profiles(raw):
            profile.setdefault("outbound_mode", OUTBOUND_DIRECT)
        migrated = upgrade_state(raw)
        validate_state(migrated)
        return migrated

    if {"keys", "short_id", "clients", "default_domain"}.issubset(raw.keys()):
        default_domain = raw["default_domain"]
        now = utc_now()
        migrated_clients = []
        for client in raw.get("clients", []):
            name = client["name"]
            migrated_clients.append(
                {
                    "name": name,
                    "id": client["id"],
                    "email": client.get("email") or safe_client_email(name, default_domain),
                    "enabled": client.get("enabled", True),
                    "quota_bytes": client.get("quota_bytes"),
                    "used_uplink_bytes": int(client.get("used_uplink_bytes", 0)),
                    "used_downlink_bytes": int(client.get("used_downlink_bytes", 0)),
                    "created_at": client.get("created_at", now),
                    "updated_at": client.get("updated_at", now),
                    "disabled_reason": client.get("disabled_reason"),
                }
            )
        migrated = {
            "version": STATE_VERSION,
            "created_at": raw.get("created_at", now),
            "updated_at": now,
            "usage_period": raw.get("usage_period", current_usage_period()),
            "server_host": raw.get("server_host", "127.0.0.1"),
            "default_domain": default_domain,
            "fingerprint": raw.get("fingerprint", DEFAULT_FINGERPRINT),
            "flow": raw.get("flow", DEFAULT_FLOW),
            "spider_x": raw.get("spider_x", DEFAULT_SPIDER_X),
            "upstream": raw.get("upstream"),
            "profiles": [
                {
                    "name": DEFAULT_PROFILE_NAME,
                    "created_at": raw.get("created_at", now),
                    "updated_at": raw.get("updated_at", now),
                    "port": int(raw.get("port", DEFAULT_PORT)),
                    "reality_target": raw.get("reality_target") or raw.get("dest", "www.cloudflare.com:443"),
                    "outbound_mode": raw.get("outbound_mode", OUTBOUND_DIRECT),
                    "short_id": raw["short_id"],
                    "keys": raw["keys"],
                    "clients": migrated_clients,
                }
            ],
        }
        migrated = upgrade_state(migrated)
        validate_state(migrated)
        return migrated

    raise VpnctlError("state file is not a recognized vpnctl state format")


def validate_stable_name(name: str) -> str:
    if not name or any(not (char.isascii() and (char.isalnum() or char in "_-")) for char in name):
        raise VpnctlError("names must use ASCII letters, digits, underscores or hyphens")
    return name


def canonical_upstream(upstream: dict[str, Any]) -> dict[str, Any]:
    if "transport" in upstream:
        return upstream
    if upstream.get("network", "tcp") != "tcp" or upstream.get("security", "reality") != "reality":
        raise VpnctlError("unsupported legacy upstream transport")
    return {
        "protocol": "vless", "address": upstream["host"], "port": upstream["port"],
        "auth": {"id": upstream["id"], "encryption": "none", "flow": upstream.get("flow", DEFAULT_FLOW)},
        "transport": {"type": "tcp", "settings": {}},
        "security": {"type": "reality", "settings": {
            "server_name": upstream["server_name"], "public_key": upstream["public_key"],
            "short_id": upstream["short_id"], "fingerprint": upstream.get("fingerprint", DEFAULT_FINGERPRINT),
            "spider_x": upstream.get("spider_x", "/"),
        }}, "enabled": True,
    }


def upgrade_state(raw: dict[str, Any]) -> dict[str, Any]:
    raw["version"] = STATE_VERSION
    raw.setdefault("node", {"id": "local", "role": "both"})
    upstream = raw.pop("upstream", None)
    raw.setdefault("upstreams", {})
    if upstream:
        raw["upstreams"][UPSTREAM_OUTBOUND_TAG] = canonical_upstream(upstream)
    raw.setdefault("routing_policies", {"direct": {"type": "direct"}, "block": {"type": "block"}})
    if upstream:
        raw["routing_policies"][UPSTREAM_OUTBOUND_TAG] = {"type": "upstream", "upstreams": [UPSTREAM_OUTBOUND_TAG]}
    for profile in raw["profiles"]:
        profile.setdefault("transport", {"type": "tcp", "settings": {}})
        profile.setdefault("route", "direct" if profile_outbound_mode(profile) == "direct" else UPSTREAM_OUTBOUND_TAG)
    return raw


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def state_lock(path: Path):
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def backup_path(path: Path) -> Path:
    return path.with_name(path.name + ".bak")


def load_state(path: Path) -> dict[str, Any]:
    backup = backup_path(path)
    if path.exists() or backup.exists():
        try:
            state = migrate_legacy_state(load_json(path))
            os.chmod(path, 0o600)
            return state
        except (OSError, ValueError, KeyError, TypeError, VpnctlError):
            state = migrate_legacy_state(load_json(backup))
            write_json(path, state)
            print("Recovered state from validated backup.", file=sys.stderr)
            return state
    if not path.exists():
        legacy_path = Path("vpn_config.json")
        if legacy_path.exists():
            return migrate_legacy_state(load_json(legacy_path))
        raise VpnctlError(f"state file not found: {path}")
    return migrate_legacy_state(load_json(path))


def save_state(path: Path, state: dict[str, Any]) -> None:
    validate_state(state)
    state["updated_at"] = utc_now()
    if path.exists():
        previous_raw = load_json(path)
        if previous_raw.get("version") == 3:
            original = path.with_name(path.name + ".v3.bak")
            if not original.exists():
                write_json(original, previous_raw)
        previous = migrate_legacy_state(previous_raw)
        write_json(backup_path(path), previous)
    write_json(path, state)


def render_vless_inbound(state: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    reality_host, _ = split_host_port(profile["reality_target"])
    enabled_clients = []
    for client in profile.get("clients", []):
        if client.get("enabled", True):
            enabled_clients.append(
                {
                    "id": client["id"],
                    "email": client["email"],
                    "flow": state.get("flow", DEFAULT_FLOW) if profile.get("transport", {}).get("type", "tcp") == "tcp" else "",
                    "level": 0,
                }
            )

    inbound = {
        "tag": profile_tag(profile),
        "listen": "0.0.0.0",
        "port": parse_port(profile.get("port", DEFAULT_PORT)),
        "protocol": "vless",
        "settings": {
            "clients": enabled_clients,
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "target": profile["reality_target"],
                "xver": 0,
                "serverNames": [reality_host],
                "privateKey": profile["keys"]["private_key"],
                "shortIds": [profile["short_id"]],
            },
        },
    }
    transport = profile.get("transport", {"type": "tcp", "settings": {}})
    if transport["type"] != "tcp" or profile.get("security"):
        security = profile.get("security") or {"type": "reality", "settings": {
            "target": profile["reality_target"], "server_name": reality_host,
            "private_key": profile["keys"]["private_key"], "short_ids": [profile["short_id"]],
        }}
        try:
            inbound["streamSettings"] = vpn_transports.render_stream(transport, security, server=True)
        except ValueError as error:
            raise VpnctlError(str(error)) from None
    return inbound


def render_upstream_outbound(state: dict[str, Any], name: str = UPSTREAM_OUTBOUND_TAG) -> dict[str, Any]:
    try:
        return vpn_transports.render_outbound(state["upstreams"][name], name)
    except ValueError as error:
        raise VpnctlError(str(error)) from None


def render_direct_outbound() -> dict[str, Any]:
    return {
        "tag": OUTBOUND_DIRECT,
        "protocol": "freedom",
        "settings": {},
    }


def profile_outbound_tag(profile: dict[str, Any], state: dict[str, Any]) -> str:
    policy = state["routing_policies"][profile["route"]]
    if policy["type"] == "upstream":
        return policy["upstreams"][0]
    return policy["type"]


def render_config(state: dict[str, Any], api_port: int = DEFAULT_API_PORT) -> dict[str, Any]:
    validate_state(state, api_port)
    inbounds = [render_vless_inbound(state, profile) for profile in all_profiles(state)]
    inbounds.append(
        {
            "tag": "api",
            "listen": "127.0.0.1",
            "port": api_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        }
    )

    outbounds = [render_direct_outbound()]
    referenced = {member for profile in all_profiles(state)
                  for member in state["routing_policies"][profile["route"]].get("upstreams", [])}
    outbounds.extend(render_upstream_outbound(state, name) for name in sorted(referenced))
    if any(state["routing_policies"][profile["route"]]["type"] == "block" for profile in all_profiles(state)):
        outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {}})

    routing_rules = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]
    for profile in all_profiles(state):
        routing_rules.append(
            {
                "type": "field",
                "inboundTag": [profile_tag(profile)],
                "outboundTag": profile_outbound_tag(profile, state),
            }
        )

    return {
        "log": {
            "access": "none",
            "loglevel": "warning",
        },
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService"],
        },
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "rules": routing_rules
        },
        "stats": {},
    }


def render_and_save_config(state: dict[str, Any], config_path: Path) -> None:
    destination = config_path.with_name(config_path.name + ".pending") if config_path.exists() else config_path
    write_json(destination, render_config(state))


def ensure_monthly_period(state: dict[str, Any]) -> bool:
    period = current_usage_period()
    existing_period = state.get("usage_period")
    if existing_period is None:
        state["usage_period"] = period
        return True
    if existing_period == period:
        return False

    now = utc_now()
    state["usage_period"] = period
    for client in clients_in_state(state):
        client["used_uplink_bytes"] = 0
        client["used_downlink_bytes"] = 0
        if client.get("disabled_reason") == "quota_exceeded":
            client["enabled"] = True
            client["disabled_reason"] = None
        client["updated_at"] = now
    return True


def persist_state_and_config(
    state: dict[str, Any],
    state_path: Path,
    config_path: Path,
    compose_file: Path | None = None,
    restart: bool = False,
) -> None:
    candidate = render_config(state)
    if restart and compose_file is not None:
        deploy_config(state, state_path, config_path, compose_file, candidate)
    else:
        save_state(state_path, state)
        write_json(config_path.with_name(config_path.name + ".pending"), candidate)


def find_client(
    state: dict[str, Any],
    name_or_id: str,
    profile_name: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    profiles = [require_profile(state, profile_name)] if profile_name else all_profiles(state)
    for profile in profiles:
        for client in profile.get("clients", []):
            if client["name"] == name_or_id or client["id"] == name_or_id:
                matches.append((profile, client))
    if not matches:
        return None
    if len(matches) > 1:
        profiles_text = ", ".join(profile_label(profile) for profile, _ in matches)
        raise VpnctlError(f"client name is ambiguous across profiles ({profiles_text}); pass --profile")
    return matches[0]


def require_client(
    state: dict[str, Any],
    name_or_id: str,
    profile_name: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    match = find_client(state, name_or_id, profile_name)
    if match is None:
        suffix = f" in profile {profile_name}" if profile_name else ""
        raise VpnctlError(f"client not found{suffix}: {name_or_id}")
    return match


def generate_vless_link(client: dict[str, Any], state: dict[str, Any], profile: dict[str, Any]) -> str:
    if profile.get("transport", {}).get("type", "tcp") != "tcp" or profile.get("security"):
        host, _ = split_host_port(profile["reality_target"])
        security = profile.get("security") or {"type": "reality", "settings": {
            "server_name": host, "public_key": profile["keys"]["public_key"],
            "short_id": profile["short_id"], "fingerprint": state.get("fingerprint", DEFAULT_FINGERPRINT),
        }}
        security = {"type": security["type"], "settings": dict(security["settings"])}
        for field in ("certificates", "private_key", "short_ids", "target"):
            security["settings"].pop(field, None)
        endpoint = {"protocol": "vless", "address": state["server_host"].strip("[]"),
                    "port": profile["port"], "auth": {"id": client["id"], "encryption": "none", "flow": ""},
                    "transport": profile["transport"], "security": security, "enabled": True}
        return vpn_transports.export_link(endpoint, f"{profile_label(profile)}:{client['name']}")
    reality_host, _ = split_host_port(profile["reality_target"])
    server_host = validate_server_host(state["server_host"])
    params = {
        "type": "tcp",
        "encryption": "none",
        "security": "reality",
        "pbk": profile["keys"]["public_key"],
        "fp": state.get("fingerprint", DEFAULT_FINGERPRINT),
        "sni": reality_host,
        "sid": profile["short_id"],
        "spx": state.get("spider_x", DEFAULT_SPIDER_X),
        "flow": state.get("flow", DEFAULT_FLOW),
    }
    query = urlencode(params)
    label = quote(f"{profile_label(profile)}:{client['name']}")
    return f"vless://{client['id']}@{server_host}:{profile['port']}?{query}#{label}"


def write_qr(link: str, client_name: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    qr_path = output_dir / f"{client_name}.png"
    image = qrcode.make(link)
    descriptor = os.open(qr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        image.save(handle, format="PNG")
    return qr_path


def compose_base_command(compose_file: Path) -> list[str]:
    if shutil.which("docker"):
        return ["docker", "compose", "-f", str(compose_file)]
    if shutil.which("docker-compose"):
        return ["docker-compose", "-f", str(compose_file)]
    raise VpnctlError("docker compose is not installed")


def is_docker_permission_error(error: subprocess.CalledProcessError) -> bool:
    text = " ".join(
        part.lower()
        for part in (str(error), error.stderr or "", error.stdout or "")
        if part
    )
    return (
        "/var/run/docker.sock" in text
        and "permission denied" in text
    ) or (
        "docker api" in text
        and "permission denied" in text
    )


def docker_permission_error() -> VpnctlError:
    return VpnctlError(
        "Docker is installed, but this user cannot access /var/run/docker.sock. "
        "Run 'sudo usermod -aG docker $USER', then log out and back in or run 'newgrp docker'. "
        "Temporary workaround: run this command with sudo."
    )


def run_compose(
    compose_file: Path,
    args: list[str],
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = compose_base_command(compose_file) + args
    try:
        return subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=capture,
            timeout=None if "--follow" in args or "-f" in args else 120,
        )
    except subprocess.CalledProcessError as error:
        if is_docker_permission_error(error):
            raise docker_permission_error() from error
        raise


def restart_xray(compose_file: Path, state: dict[str, Any] | None = None) -> None:
    run_compose(compose_file, ["up", "-d", "--force-recreate", XRAY_SERVICE], capture=True)


def runtime_epoch(compose_file: Path) -> str:
    result = run_compose(compose_file, ["ps", "-q", XRAY_SERVICE], capture=True)
    container_id = result.stdout.strip()
    if not container_id:
        raise VpnctlError("Xray is not running")
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.State.Running}}", container_id],
        check=True, capture_output=True, text=True, timeout=15,
    )
    if not result.stdout.strip().endswith(" true"):
        raise VpnctlError("Xray is not running")
    return result.stdout.strip()


def sample_usage(state: dict[str, Any], compose_file: Path) -> None:
    before = runtime_epoch(compose_file)
    stats = query_xray_stats(compose_file, reset=False, state=state)
    if runtime_epoch(compose_file) != before:
        raise VpnctlError("Xray restarted during statistics read; retry the command")
    apply_usage_snapshot(state, collect_usage_deltas(stats), before)


def apply_usage_snapshot(state: dict[str, Any], counters: dict[str, dict[str, int]], epoch: str) -> None:
    accounting = state.setdefault("accounting", {"epoch": epoch, "checkpoints": {}})
    same_epoch = accounting.get("epoch") == epoch
    checkpoints = accounting.get("checkpoints", {}) if same_epoch else {}
    deltas = {}
    for email, traffic in counters.items():
        previous = checkpoints.get(email, {})
        deltas[email] = {}
        for direction, value in traffic.items():
            if value < 0:
                raise VpnctlError("negative Xray traffic counter")
            baseline = int(previous.get(direction, 0))
            deltas[email][direction] = value - baseline if value >= baseline else value
        checkpoints[email] = traffic.copy()
    apply_usage_deltas(state, deltas)
    state["accounting"] = {"epoch": epoch, "checkpoints": checkpoints}


def validate_config(config: dict[str, Any]) -> None:
    inbounds = [inbound["tag"] for inbound in config["inbounds"]]
    outbounds = [outbound["tag"] for outbound in config["outbounds"]]
    if len(set(inbounds)) != len(inbounds) or len(set(outbounds)) != len(outbounds):
        raise VpnctlError("duplicate Xray tags")
    for rule in config["routing"]["rules"]:
        if not set(rule["inboundTag"]).issubset(inbounds):
            raise VpnctlError("routing references an unknown inbound")
        if rule["outboundTag"] not in outbounds + [config["api"]["tag"]]:
            raise VpnctlError("routing references an unknown outbound")


def validate_native(compose_file: Path, candidate_path: Path) -> None:
    run_compose(compose_file, [
        "run", "--rm", "--no-deps", "-v", f"{candidate_path.resolve()}:/etc/xray/candidate.json:ro",
        XRAY_SERVICE, "run", "-test", "-config", "/etc/xray/candidate.json",
    ], capture=True)


def verify_xray(compose_file: Path, config: dict[str, Any]) -> None:
    deadline = time.monotonic() + 15
    while True:
        try:
            epoch = runtime_epoch(compose_file)
            query_xray_stats(compose_file, reset=False, state={})
            for inbound in config["inbounds"]:
                with socket.create_connection(("127.0.0.1", inbound["port"]), timeout=1):
                    pass
            time.sleep(0.25)
            if epoch != runtime_epoch(compose_file):
                raise VpnctlError("Xray restarted during health check")
            return
        except (OSError, VpnctlError, subprocess.CalledProcessError):
            if time.monotonic() >= deadline:
                raise VpnctlError("Xray failed API/listener health checks") from None
            time.sleep(0.25)


def journal_path(state_path: Path) -> Path:
    return state_path.with_name(state_path.name + ".deploy")


def remove_journal(state_path: Path) -> None:
    journal_path(state_path).unlink()
    sync_directory(state_path.parent)


def recover_deployment(state_path: Path, config_path: Path, compose_file: Path) -> None:
    journal = load_json(journal_path(state_path))
    if journal.get("config_path", str(config_path.resolve())) != str(config_path.resolve()) or \
            journal.get("compose_file", str(compose_file.resolve())) != str(compose_file.resolve()):
        raise VpnctlError("Recovery requires the original --config and --compose-file paths")
    if journal["config"] is None:
        run_compose(compose_file, ["stop", XRAY_SERVICE], capture=True)
        config_path.unlink(missing_ok=True)
    else:
        write_json(config_path, journal["config"])
        restart_xray(compose_file)
        verify_xray(compose_file, journal["config"])
    write_json(state_path, journal["state"])
    write_json(backup_path(state_path), journal["state"])
    remove_journal(state_path)


def deploy_config(state: dict[str, Any], state_path: Path, config_path: Path,
                  compose_file: Path, candidate: dict[str, Any], force: bool = False) -> None:
    validate_config(candidate)
    try:
        previous_config = load_json(config_path) if config_path.exists() else None
    except (ValueError, OSError):
        if not force:
            raise
        previous_config = load_json(backup_path(config_path)) if backup_path(config_path).exists() else None
    if previous_config is not None:
        os.chmod(config_path, 0o600)
    if previous_config == candidate and not force:
        save_state(state_path, state)
        return
    candidate_path = config_path.with_name(config_path.name + ".candidate")
    write_json(candidate_path, candidate)
    try:
        validate_native(compose_file, candidate_path)
    finally:
        candidate_path.unlink(missing_ok=True)
    previous_state = load_state(state_path)
    ensure_monthly_period(previous_state)
    running = run_compose(compose_file, ["ps", "-q", XRAY_SERVICE], capture=True).stdout.strip()
    if running:
        try:
            sample_usage(previous_state, compose_file)
        except (VpnctlError, OSError, ValueError, subprocess.SubprocessError):
            if not force:
                raise
            print("Xray statistics unavailable; explicit recovery may lose unobserved traffic.", file=sys.stderr)
        else:
            save_state(state_path, previous_state)
            accounting = previous_state["accounting"]
            apply_usage_snapshot(state, accounting["checkpoints"], accounting["epoch"])
    write_json(journal_path(state_path), {
        "state": previous_state, "config": previous_config,
        "config_path": str(config_path.resolve()), "compose_file": str(compose_file.resolve()),
    })
    if previous_config is not None:
        write_json(backup_path(config_path), previous_config)
    try:
        write_json(config_path, candidate)
        restart_xray(compose_file, state)
        verify_xray(compose_file, candidate)
        save_state(state_path, state)
        remove_journal(state_path)
    except Exception:
        try:
            recover_deployment(state_path, config_path, compose_file)
        except Exception:
            raise VpnctlError("Deployment and rollback failed; journal retained. Run restart to retry recovery.") from None
        raise VpnctlError("Deployment failed; previous configuration and state restored.") from None


def query_xray_stats(compose_file: Path, reset: bool, state: dict[str, Any]) -> dict[str, Any]:
    args = [
        "exec",
        "-T",
        XRAY_SERVICE,
        "xray",
        "api",
        "statsquery",
        "--server=127.0.0.1:10085",
        "-pattern",
        "user>>>",
    ]
    if reset:
        args.append("-reset")
    completed = run_compose(compose_file, args, capture=True)
    output = completed.stdout.strip()
    if not output:
        return {"stat": []}
    return json.loads(output)


def stat_entries(stats_response: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(stats_response.get("stat"), list):
        return stats_response["stat"]
    if isinstance(stats_response.get("stats"), list):
        return stats_response["stats"]
    return []


def collect_usage_deltas(stats_response: dict[str, Any]) -> dict[str, dict[str, int]]:
    deltas: dict[str, dict[str, int]] = {}
    for entry in stat_entries(stats_response):
        name = entry.get("name", "")
        value = int(entry.get("value") or 0)
        parts = name.split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        email = parts[1]
        direction = parts[3]
        if direction not in {"uplink", "downlink"}:
            continue
        deltas.setdefault(email, {"uplink": 0, "downlink": 0})[direction] += value
    return deltas


def apply_usage_deltas(state: dict[str, Any], deltas: dict[str, dict[str, int]]) -> bool:
    changed = False
    clients_by_email = {client["email"]: client for client in clients_in_state(state)}
    for email, traffic in deltas.items():
        client = clients_by_email.get(email)
        if client is None:
            continue
        uplink = int(traffic.get("uplink", 0))
        downlink = int(traffic.get("downlink", 0))
        if uplink or downlink:
            client["used_uplink_bytes"] = int(client.get("used_uplink_bytes", 0)) + uplink
            client["used_downlink_bytes"] = int(client.get("used_downlink_bytes", 0)) + downlink
            client["updated_at"] = utc_now()
            changed = True
    return changed


def enforce_quotas(state: dict[str, Any]) -> list[dict[str, Any]]:
    disabled: list[dict[str, Any]] = []
    now = utc_now()
    for client in clients_in_state(state):
        quota = client.get("quota_bytes")
        used = int(client.get("used_uplink_bytes", 0)) + int(client.get("used_downlink_bytes", 0))
        if client.get("enabled", True) and quota is not None and used >= int(quota):
            client["enabled"] = False
            client["disabled_reason"] = "quota_exceeded"
            client["updated_at"] = now
            disabled.append(client)
    return disabled


def command_profile_list(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    if ensure_monthly_period(state):
        persist_state_and_config(state, args.state, args.config)
    for profile in all_profiles(state):
        clients = profile.get("clients", [])
        enabled_count = sum(1 for client in clients if client.get("enabled", True))
        print(
            f"{profile_label(profile)}\tport={profile['port']}\treality_target={profile['reality_target']}"
            f"\toutbound={profile_outbound_mode(profile)}\tclients={enabled_count}/{len(clients)}"
        )


def command_profile_add(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile_name = validate_profile_name(args.name)
    if find_profile(state, profile_name):
        raise VpnctlError(f"profile already exists: {profile_name}")
    quota_bytes = parse_size(args.quota)
    outbound_mode = args.outbound or OUTBOUND_DIRECT
    profile = create_profile(
        profile_name,
        args.reality_target,
        state["default_domain"],
        args.port,
        args.client or [],
        quota_bytes,
        outbound_mode,
    )
    if args.transport == "xhttp":
        profile["transport"] = {"type": "xhttp", "settings": {
            "path": args.path, "host": args.host or "", "mode": args.xhttp_mode or ("stream-one" if args.security == "reality" else "auto"),
        }}
    if args.security == "tls":
        if args.transport != "xhttp" or not args.certificate or not args.certificate_key or not args.tls_server_name:
            raise VpnctlError("XHTTP TLS requires certificate, certificate-key and tls-server-name")
        profile["security"] = {"type": "tls", "settings": {
            "server_name": args.tls_server_name,
            "certificates": [{"certificateFile": args.certificate, "keyFile": args.certificate_key}],
        }}
    state["profiles"].append(profile)
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Profile added: {profile_label(profile)} on port {profile['port']} outbound={profile_outbound_mode(profile)}")
    for client in profile["clients"]:
        print(f"Client {profile_label(profile)}/{client['name']}: {generate_vless_link(client, state, profile)}")


def command_profile_remove(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile = require_profile(state, args.name)
    if len(all_profiles(state)) == 1:
        raise VpnctlError("cannot remove the last profile")
    state["profiles"] = [item for item in all_profiles(state) if profile_label(item) != profile_label(profile)]
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Profile removed: {profile_label(profile)}")


def command_profile_outbound(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile = require_profile(state, args.name)
    profile["outbound_mode"] = validate_outbound_mode(args.outbound)
    profile["route"] = "direct" if args.outbound == "direct" else UPSTREAM_OUTBOUND_TAG
    profile["updated_at"] = utc_now()
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Profile outbound updated: {profile_label(profile)} outbound={profile_outbound_mode(profile)}")


def command_init(args: argparse.Namespace) -> None:
    if args.state.exists() and not args.force:
        raise VpnctlError(f"state already exists: {args.state}. Use --force to overwrite it.")
    default_domain = args.default_domain or args.server_host
    quota_bytes = parse_size(args.quota)
    state = create_state(
        server_host=args.server_host,
        reality_target=args.reality_target,
        default_domain=default_domain,
        port=args.port,
        client_names=args.client,
        quota_bytes=quota_bytes,
        profile_name=args.profile,
        upstream_link=args.upstream_link,
        mode=args.mode,
        direct_port=args.direct_port,
        proxy_port=args.proxy_port,
    )
    save_state(args.state, state)
    render_and_save_config(state, args.config)
    print(f"State saved to {args.state}")
    print(f"Xray config rendered to {args.config}")
    for profile in all_profiles(state):
        for client in profile["clients"]:
            print(f"Client {profile_label(profile)}/{client['name']}: {generate_vless_link(client, state, profile)}")


def command_import_config(args: argparse.Namespace) -> None:
    if args.state.exists() and not args.force:
        raise VpnctlError(f"state already exists: {args.state}. Use --force to overwrite it.")
    config = load_json(args.input)
    state = import_state_from_xray_config(config, args.server_host, args.default_domain)
    save_state(args.state, state)
    render_and_save_config(state, args.config)
    print(f"Imported Xray config from {args.input}")
    print(f"State saved to {args.state}")
    print(f"Xray config rendered to {args.config}")
    for profile in all_profiles(state):
        print(
            f"Profile {profile_label(profile)}: port={profile['port']} "
            f"outbound={profile_outbound_mode(profile)} clients={len(profile.get('clients', []))}"
        )


def command_upstream_show(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    name = getattr(args, "name", UPSTREAM_OUTBOUND_TAG)
    upstream = state["upstreams"].get(name)
    if not upstream:
        print("No upstream configured.")
        return
    print(
        f"{name}\thost={upstream['address']}\tport={upstream['port']}"
        f"\ttransport={upstream['transport']['type']}\tsecurity={upstream['security']['type']}"
        f"\tenabled={upstream['enabled']}"
    )


def command_upstream_set(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    name = validate_stable_name(getattr(args, "name", UPSTREAM_OUTBOUND_TAG))
    if getattr(args, "upstream_command", "set") == "add" and name in state["upstreams"]:
        raise VpnctlError("upstream already exists")
    try:
        state["upstreams"][name] = vpn_transports.parse_link(args.link)
    except ValueError as error:
        raise VpnctlError(str(error)) from None
    state["routing_policies"].setdefault(name, {"type": "upstream", "upstreams": [name]})
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Upstream saved: {name}")


def command_upstream_clear(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    name = getattr(args, "name", UPSTREAM_OUTBOUND_TAG)
    assigned = {profile["route"] for profile in all_profiles(state)}
    if any(name in policy.get("upstreams", []) and policy_name in assigned
           for policy_name, policy in state["routing_policies"].items()):
        raise VpnctlError("cannot remove an assigned upstream")
    state["upstreams"].pop(name, None)
    state["routing_policies"] = {key: policy for key, policy in state["routing_policies"].items()
                                 if name not in policy.get("upstreams", [])}
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print("Upstream cleared.")


def command_upstream_list(args: argparse.Namespace) -> None:
    for name in load_state(args.state)["upstreams"]:
        args.name = name
        command_upstream_show(args)


def command_upstream_enabled(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    if args.name not in state["upstreams"]:
        raise VpnctlError("unknown upstream")
    state["upstreams"][args.name]["enabled"] = args.upstream_command == "enable"
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)


def command_route(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    profile = require_profile(state, args.profile)
    if args.route_command == "set":
        if args.policy not in state["routing_policies"]:
            raise VpnctlError("unknown routing policy")
        profile["route"] = args.policy
        profile["outbound_mode"] = "direct" if state["routing_policies"][args.policy]["type"] == "direct" else "proxy"
        persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"{profile_label(profile)}\tpolicy={profile['route']}")


def command_render(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    persist_state_and_config(state, args.state, args.config)
    print(f"Xray config rendered to {args.config}")


def command_client_add(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile = require_profile(state, args.profile)
    if find_client(state, args.name, profile_label(profile)):
        raise VpnctlError(f"client already exists in profile {profile_label(profile)}: {args.name}")
    client = create_client(args.name, state["default_domain"], parse_size(args.quota), profile_label(profile))
    profile["clients"].append(client)
    profile["updated_at"] = utc_now()
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Client added: {profile_label(profile)}/{client['name']}")
    print(generate_vless_link(client, state, profile))


def command_client_remove(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile, client = require_client(state, args.name_or_id, args.profile)
    profile["clients"] = [item for item in profile["clients"] if item["id"] != client["id"]]
    profile["updated_at"] = utc_now()
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Client removed: {profile_label(profile)}/{client['name']}")


def command_client_list(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    if ensure_monthly_period(state):
        persist_state_and_config(state, args.state, args.config)
    profiles = [require_profile(state, args.profile)] if args.profile else all_profiles(state)
    clients = [(profile, client) for profile in profiles for client in profile.get("clients", [])]
    if not clients:
        print("No clients configured.")
        return
    for profile, client in clients:
        used = int(client.get("used_uplink_bytes", 0)) + int(client.get("used_downlink_bytes", 0))
        status = "enabled" if client.get("enabled", True) else f"disabled:{client.get('disabled_reason')}"
        print(
            f"{profile_label(profile)}/{client['name']}\t{status}\tport={profile['port']}\tperiod={state['usage_period']}"
            f"\tmonthly_quota={format_size(client.get('quota_bytes'))}"
            f"\tused={format_size(used)}\tid={client['id']}"
        )


def command_client_enabled(args: argparse.Namespace, enabled: bool) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile, client = require_client(state, args.name_or_id, args.profile)
    client["enabled"] = enabled
    client["disabled_reason"] = None if enabled else args.reason
    client["updated_at"] = utc_now()
    profile["updated_at"] = utc_now()
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Client {'enabled' if enabled else 'disabled'}: {profile_label(profile)}/{client['name']}")


def command_quota_set(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile, client = require_client(state, args.name_or_id, args.profile)
    client["quota_bytes"] = parse_size(args.quota)
    client["updated_at"] = utc_now()
    persist_state_and_config(state, args.state, args.config)
    print(f"Monthly quota for {profile_label(profile)}/{client['name']} set to {format_size(client['quota_bytes'])}")


def command_quota_reset(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile, client = require_client(state, args.name_or_id, args.profile)
    client["used_uplink_bytes"] = 0
    client["used_downlink_bytes"] = 0
    if args.enable:
        client["enabled"] = True
        client["disabled_reason"] = None
    client["updated_at"] = utc_now()
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=args.enable and not args.no_restart)
    print(f"Monthly usage reset for {profile_label(profile)}/{client['name']} in period {state['usage_period']}")


def command_quota_enforce(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    period_changed = ensure_monthly_period(state)
    sample_usage(state, args.compose_file)
    disabled = enforce_quotas(state)
    persist_state_and_config(
        state,
        args.state,
        args.config,
        args.compose_file,
        restart=not args.no_restart,
    )
    profile_by_client_id = {
        client["id"]: profile
        for profile in all_profiles(state)
        for client in profile.get("clients", [])
    }
    for client in disabled:
        used = int(client.get("used_uplink_bytes", 0)) + int(client.get("used_downlink_bytes", 0))
        profile = profile_by_client_id[client["id"]]
        print(f"Disabled {profile_label(profile)}/{client['name']} after {format_size(used)} used")
    if period_changed:
        print(f"Monthly quota period rolled over to {state['usage_period']}.")
    if not disabled:
        print("No clients exceeded quota.")


def command_usage(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    period_changed = ensure_monthly_period(state)
    if args.refresh:
        sample_usage(state, args.compose_file)
        period_changed = True
    if period_changed:
        persist_state_and_config(state, args.state, args.config)
    profiles = [require_profile(state, args.profile)] if args.profile else all_profiles(state)
    for profile in profiles:
        for client in profile.get("clients", []):
            uplink = int(client.get("used_uplink_bytes", 0))
            downlink = int(client.get("used_downlink_bytes", 0))
            print(
                f"{profile_label(profile)}/{client['name']}\tuplink={format_size(uplink)}\tdownlink={format_size(downlink)}"
                f"\ttotal={format_size(uplink + downlink)}\tperiod={state['usage_period']}"
                f"\tmonthly_quota={format_size(client.get('quota_bytes'))}"
            )


def command_link(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    if ensure_monthly_period(state):
        persist_state_and_config(state, args.state, args.config)
    profile, client = require_client(state, args.name_or_id, args.profile)
    link = generate_vless_link(client, state, profile)
    print(link)
    if args.qr:
        path = write_qr(link, f"{profile_label(profile)}-{client['name']}", args.output)
        print(f"QR code saved to {path}")


def command_compose(args: argparse.Namespace, compose_args: list[str]) -> None:
    if compose_args[0] in {"up", "restart"}:
        state = load_state(args.state)
        deploy_config(state, args.state, args.config, args.compose_file, render_config(state), force=True)
    elif compose_args[0] == "down":
        state = load_state(args.state)
        if run_compose(args.compose_file, ["ps", "-q", XRAY_SERVICE], capture=True).stdout.strip():
            try:
                sample_usage(state, args.compose_file)
            except (VpnctlError, OSError, ValueError, subprocess.SubprocessError):
                print("Xray statistics unavailable; stopping may lose unobserved traffic.", file=sys.stderr)
            else:
                save_state(args.state, state)
        run_compose(args.compose_file, compose_args)
    else:
        run_compose(args.compose_file, compose_args)


def add_common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE_PATH, help="Path to vpnctl state JSON.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to rendered Xray config JSON.")
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=DEFAULT_COMPOSE_FILE,
        help="Path to Docker Compose file.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage a Docker Compose Xray VLESS + REALITY VPN server.")
    add_common_paths(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create state and render the initial Xray config.")
    init_parser.add_argument("--server-host", required=True, help="Public IP or DNS name clients connect to.")
    init_parser.add_argument("--upstream-link", help="VLESS + REALITY client link for an upstream VPN.")
    init_parser.add_argument("--reality-target", required=True, help="REALITY target, for example www.cloudflare.com:443.")
    init_parser.add_argument("--default-domain", help="Domain used in generated client emails. Defaults to server host.")
    init_parser.add_argument("--mode", choices=["direct", "proxy", "both"], default=OUTBOUND_DIRECT, help="Initial outbound profile mode.")
    init_parser.add_argument("--port", type=parse_port, help="Public VLESS port for direct-only or proxy-only init. Defaults to 443.")
    init_parser.add_argument("--direct-port", type=parse_port, default=DEFAULT_PORT, help="Public VLESS port for the direct profile in both mode.")
    init_parser.add_argument("--proxy-port", type=parse_port, default=8443, help="Public VLESS port for the proxy profile in both mode.")
    init_parser.add_argument("--profile", default=DEFAULT_PROFILE_NAME, help="Initial profile name for direct-only or proxy-only init.")
    init_parser.add_argument("--client", action="append", required=True, help="Initial client name. Repeatable.")
    init_parser.add_argument("--quota", help="Optional initial monthly quota for all created clients, for example 50GiB.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing state.")
    init_parser.set_defaults(func=command_init)

    import_parser = subparsers.add_parser("import-config", help="Import an existing Xray JSON config into vpnctl state.")
    import_parser.add_argument("--input", type=Path, required=True, help="Existing Xray config JSON to import.")
    import_parser.add_argument("--server-host", required=True, help="Public IP or DNS name clients connect to.")
    import_parser.add_argument("--default-domain", help="Domain used in imported client emails. Defaults to inferred email domain or server host.")
    import_parser.add_argument("--force", action="store_true", help="Overwrite existing state.")
    import_parser.set_defaults(func=command_import_config)

    render_parser = subparsers.add_parser("render", help="Render config from state.")
    render_parser.set_defaults(func=command_render)

    upstream_parser = subparsers.add_parser("upstream", help="Show or change the upstream VPN.")
    upstream_subparsers = upstream_parser.add_subparsers(dest="upstream_command", required=True)
    upstream_show_parser = upstream_subparsers.add_parser("show", help="Show the configured upstream without printing UUIDs.")
    upstream_show_parser.add_argument("name", nargs="?", default=UPSTREAM_OUTBOUND_TAG)
    upstream_show_parser.set_defaults(func=command_upstream_show)
    upstream_set_parser = upstream_subparsers.add_parser("set", help="Replace the upstream VPN link.")
    upstream_set_parser.add_argument("--link", required=True, help="VLESS + REALITY client link for an upstream VPN.")
    upstream_set_parser.add_argument("--no-restart", action="store_true")
    upstream_set_parser.set_defaults(func=command_upstream_set)
    upstream_clear_parser = upstream_subparsers.add_parser("clear", help="Clear upstream when no proxy profiles exist.")
    upstream_clear_parser.add_argument("--no-restart", action="store_true")
    upstream_clear_parser.set_defaults(func=command_upstream_clear)
    upstream_list_parser = upstream_subparsers.add_parser("list", help="List named upstreams.")
    upstream_list_parser.set_defaults(func=command_upstream_list)
    for operation in ("add", "remove", "enable", "disable"):
        operation_parser = upstream_subparsers.add_parser(operation)
        operation_parser.add_argument("name")
        operation_parser.add_argument("--no-restart", action="store_true")
        if operation == "add":
            operation_parser.add_argument("--link", required=True)
            operation_parser.set_defaults(func=command_upstream_set)
        elif operation == "remove":
            operation_parser.set_defaults(func=command_upstream_clear)
        else:
            operation_parser.set_defaults(func=command_upstream_enabled)

    route_parser = subparsers.add_parser("route", help="Assign profile routing policies.")
    route_subparsers = route_parser.add_subparsers(dest="route_command", required=True)
    for operation in ("show", "set"):
        operation_parser = route_subparsers.add_parser(operation)
        operation_parser.add_argument("profile")
        if operation == "set":
            operation_parser.add_argument("--policy", required=True)
            operation_parser.add_argument("--no-restart", action="store_true")
        operation_parser.set_defaults(func=command_route)

    profile_parser = subparsers.add_parser("profile", help="Manage VPN profiles.")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command", required=True)
    profile_list_parser = profile_subparsers.add_parser("list", help="List VPN profiles.")
    profile_list_parser.set_defaults(func=command_profile_list)

    profile_add_parser = profile_subparsers.add_parser("add", help="Add a VPN profile on another port.")
    profile_add_parser.add_argument("name")
    profile_add_parser.add_argument("--port", type=parse_port, required=True, help="Public VLESS port for this profile.")
    profile_add_parser.add_argument("--outbound", choices=["direct", "proxy"], help="Outbound route for this profile.")
    profile_add_parser.add_argument("--reality-target", default="www.cloudflare.com:443", help="REALITY target.")
    profile_add_parser.add_argument("--transport", choices=["tcp", "xhttp"], default="tcp")
    profile_add_parser.add_argument("--security", choices=["reality", "tls"], default="reality")
    profile_add_parser.add_argument("--path", default="/")
    profile_add_parser.add_argument("--host")
    profile_add_parser.add_argument("--xhttp-mode", choices=["auto", "packet-up", "stream-up", "stream-one"])
    profile_add_parser.add_argument("--tls-server-name")
    profile_add_parser.add_argument("--certificate")
    profile_add_parser.add_argument("--certificate-key")
    profile_add_parser.add_argument("--client", action="append", help="Initial client name. Repeatable.")
    profile_add_parser.add_argument("--quota", help="Optional initial monthly quota for created clients, for example 50GiB.")
    profile_add_parser.add_argument("--no-restart", action="store_true")
    profile_add_parser.set_defaults(func=command_profile_add)

    profile_remove_parser = profile_subparsers.add_parser("remove", help="Remove a VPN profile and its clients.")
    profile_remove_parser.add_argument("name")
    profile_remove_parser.add_argument("--no-restart", action="store_true")
    profile_remove_parser.set_defaults(func=command_profile_remove)

    profile_outbound_parser = profile_subparsers.add_parser("outbound", help="Change a profile outbound route.")
    profile_outbound_parser.add_argument("name")
    profile_outbound_parser.add_argument("--outbound", choices=["direct", "proxy"], required=True)
    profile_outbound_parser.add_argument("--no-restart", action="store_true")
    profile_outbound_parser.set_defaults(func=command_profile_outbound)

    client_parser = subparsers.add_parser("client", help="Manage clients.")
    client_subparsers = client_parser.add_subparsers(dest="client_command", required=True)
    add_parser = client_subparsers.add_parser("add", help="Add a client.")
    add_parser.add_argument("name")
    add_parser.add_argument("--profile", default=DEFAULT_PROFILE_NAME, help="VPN profile to add the client to.")
    add_parser.add_argument("--quota", help="Optional monthly quota, for example 50GiB.")
    add_parser.add_argument("--no-restart", action="store_true")
    add_parser.set_defaults(func=command_client_add)

    remove_parser = client_subparsers.add_parser("remove", help="Remove a client.")
    remove_parser.add_argument("name_or_id")
    remove_parser.add_argument("--profile", help="VPN profile to remove the client from.")
    remove_parser.add_argument("--no-restart", action="store_true")
    remove_parser.set_defaults(func=command_client_remove)

    list_parser = client_subparsers.add_parser("list", help="List clients.")
    list_parser.add_argument("--profile", help="Only list clients in this VPN profile.")
    list_parser.set_defaults(func=command_client_list)

    enable_parser = client_subparsers.add_parser("enable", help="Enable a client.")
    enable_parser.add_argument("name_or_id")
    enable_parser.add_argument("--profile", help="VPN profile containing the client.")
    enable_parser.add_argument("--no-restart", action="store_true")
    enable_parser.set_defaults(func=lambda args: command_client_enabled(args, True))

    disable_parser = client_subparsers.add_parser("disable", help="Disable a client.")
    disable_parser.add_argument("name_or_id")
    disable_parser.add_argument("--profile", help="VPN profile containing the client.")
    disable_parser.add_argument("--reason", default="manual")
    disable_parser.add_argument("--no-restart", action="store_true")
    disable_parser.set_defaults(func=lambda args: command_client_enabled(args, False))

    quota_parser = subparsers.add_parser("quota", help="Manage monthly traffic quotas.")
    quota_subparsers = quota_parser.add_subparsers(dest="quota_command", required=True)
    quota_set_parser = quota_subparsers.add_parser("set", help="Set a client monthly quota.")
    quota_set_parser.add_argument("name_or_id")
    quota_set_parser.add_argument("--profile", help="VPN profile containing the client.")
    quota_set_parser.add_argument("--quota", required=True)
    quota_set_parser.set_defaults(func=command_quota_set)

    quota_reset_parser = quota_subparsers.add_parser("reset", help="Reset usage counters for a client.")
    quota_reset_parser.add_argument("name_or_id")
    quota_reset_parser.add_argument("--profile", help="VPN profile containing the client.")
    quota_reset_parser.add_argument("--enable", action="store_true", help="Enable the client after resetting usage.")
    quota_reset_parser.add_argument("--no-restart", action="store_true")
    quota_reset_parser.set_defaults(func=command_quota_reset)

    quota_enforce_parser = quota_subparsers.add_parser("enforce", help="Pull Xray stats and disable clients over monthly quota.")
    quota_enforce_parser.add_argument("--no-restart", action="store_true")
    quota_enforce_parser.set_defaults(func=command_quota_enforce)

    usage_parser = subparsers.add_parser("usage", help="Show persisted usage.")
    usage_parser.add_argument("--profile", help="Only show usage for this VPN profile.")
    usage_parser.add_argument("--refresh", action="store_true", help="Read current Xray counters before printing.")
    usage_parser.set_defaults(func=command_usage)

    link_parser = subparsers.add_parser("link", help="Print a VLESS link for a client.")
    link_parser.add_argument("name_or_id")
    link_parser.add_argument("--profile", help="VPN profile containing the client.")
    link_parser.add_argument("--qr", action="store_true", help="Write a QR code PNG.")
    link_parser.add_argument("--output", type=Path, default=Path("qrcodes"), help="QR output directory.")
    link_parser.set_defaults(func=command_link)

    up_parser = subparsers.add_parser("up", help="Start Xray.")
    up_parser.set_defaults(func=lambda args: command_compose(args, ["up", "-d"]))
    down_parser = subparsers.add_parser("down", help="Stop Xray.")
    down_parser.set_defaults(func=lambda args: command_compose(args, ["down"]))
    restart_parser = subparsers.add_parser("restart", help="Restart Xray.")
    restart_parser.set_defaults(func=lambda args: command_compose(args, ["restart", XRAY_SERVICE]))
    status_parser = subparsers.add_parser("status", help="Show Compose service status.")
    status_parser.set_defaults(func=lambda args: command_compose(args, ["ps"]))
    logs_parser = subparsers.add_parser("logs", help="Follow Xray logs.")
    logs_parser.add_argument("-f", "--follow", action="store_true")
    logs_parser.set_defaults(
        func=lambda args: command_compose(args, ["logs", *(["-f"] if args.follow else []), XRAY_SERVICE])
    )

    validate_parser = subparsers.add_parser("validate", help="Validate the rendered Xray config inside the container.")
    validate_parser.set_defaults(
        func=lambda args: command_compose(args, ["run", "--rm", XRAY_SERVICE, "run", "-test", "-config", "/etc/xray/config.json"])
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.state = args.state.resolve()
    args.config = args.config.resolve()
    args.compose_file = args.compose_file.resolve()
    try:
        os.environ["XRAY_CONFIG_PATH"] = str(args.config.resolve())
        if args.command in {"logs", "status"}:
            args.func(args)
        else:
            with state_lock(args.state):
                if journal_path(args.state).exists():
                    recover_deployment(args.state, args.config, args.compose_file)
                args.func(args)
    except (VpnctlError, subprocess.SubprocessError, json.JSONDecodeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
