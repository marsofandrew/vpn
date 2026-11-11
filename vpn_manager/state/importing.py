from typing import Any
from urllib.parse import urlencode

import vpn_transports
from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import keys as app_keys
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.state import migration as app_state_migration
from vpn_manager.state import model as app_state_model


def imported_profile_name(tag: str | None, fallback: str) -> str:
    raw = tag or fallback
    if raw.startswith("vless_reality_"):
        raw = raw.removeprefix("vless_reality_")
    return app_values.validate_profile_name(raw or fallback)


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
        local = local[len(prefix) :]
    return local or client_id


def import_client(
    client: dict[str, Any], profile_name: str, default_domain: str
) -> dict[str, Any]:
    now = app_clock.utc_now()
    client_id = client.get("id")
    if not client_id:
        raise app_errors.VpnctlError(
            f"profile {profile_name} has a VLESS client without id"
        )
    email = client.get("email") or app_state_model.safe_client_email(
        imported_client_name("", client_id, profile_name), default_domain
    )
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
        if set(rule) - {"type", "inboundTag", "outboundTag"} or not rule.get(
            "inboundTag"
        ):
            raise app_errors.VpnctlError(
                "import cannot preserve conditional or default routing rules"
            )
        outbound_tag = rule.get("outboundTag")
        inbound_tags = rule.get("inboundTag", [])
        if isinstance(inbound_tags, str):
            inbound_tags = [inbound_tags]
        for inbound_tag in inbound_tags:
            if inbound_tag and outbound_tag:
                if inbound_tag in result:
                    raise app_errors.VpnctlError(
                        "import cannot preserve overlapping inbound rules"
                    )
                result[inbound_tag] = outbound_tag
    return result


def import_upstream_from_outbound(outbound: dict[str, Any]) -> dict[str, Any]:
    stream_settings = outbound.get("streamSettings", {})
    reality_settings = stream_settings.get("realitySettings", {})
    vnext = outbound.get("settings", {}).get("vnext", [])
    if not vnext:
        raise app_errors.VpnctlError("upstream outbound is missing vnext")
    server = vnext[0]
    users = server.get("users", [])
    if not users:
        raise app_errors.VpnctlError("upstream outbound is missing users")
    user = users[0]
    if len(vnext) != 1 or len(users) != 1:
        raise app_errors.VpnctlError(
            "import requires one remote and one authentication identity per outbound"
        )
    query = _outbound_query(stream_settings, reality_settings, user)
    address = server["address"]
    if ":" in address:
        address = f"[{address}]"
    try:
        return vpn_transports.parse_link(
            f"vless://{user['id']}@{address}:{server['port']}?{urlencode(query)}"
        )
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None


def import_state_from_xray_config(
    config: dict[str, Any],
    server_host: str,
    default_domain: str | None = None,
) -> dict[str, Any]:
    now = app_clock.utc_now()
    domain = default_domain or infer_default_domain(config, server_host)
    route_by_inbound = routing_outbound_by_inbound(config)
    upstreams = _import_upstreams(config)
    profiles = _import_profiles(config, upstreams, route_by_inbound, domain, now)
    state = {
        "version": app_settings.STATE_VERSION,
        "created_at": now,
        "updated_at": now,
        "usage_period": app_clock.current_usage_period(),
        "server_host": server_host,
        "default_domain": domain,
        "fingerprint": app_settings.DEFAULT_FINGERPRINT,
        "flow": app_settings.DEFAULT_FLOW,
        "spider_x": app_settings.DEFAULT_SPIDER_X,
        "upstreams": upstreams,
        "routing_policies": {
            "direct": {"type": "direct"},
            "block": {"type": "block"},
            **{name: {"type": "upstream", "upstreams": [name]} for name in upstreams},
        },
        "profiles": profiles,
    }
    return app_state_migration.upgrade_state(state)


def _import_upstreams(config):
    upstreams = {}
    for outbound in config.get("outbounds", []):
        if outbound.get("protocol") == "vless":
            name = app_values.validate_stable_name(outbound.get("tag", ""))
            if name in upstreams:
                raise app_errors.VpnctlError("duplicate outbound tag")
            upstreams[name] = import_upstream_from_outbound(outbound)
    return upstreams


def _import_profiles(config, upstreams, route_by_inbound, domain, now):
    profiles: list[dict[str, Any]] = []
    profile_index = 1
    for inbound in config.get("inbounds", []):
        if inbound.get("protocol") != "vless":
            continue
        profiles.append(
            _import_profile(
                inbound, profile_index, config, upstreams, route_by_inbound, domain, now
            )
        )
        profile_index += 1
    if not profiles:
        raise app_errors.VpnctlError(
            "Xray config has no VLESS + REALITY inbounds to import"
        )
    return profiles


def _import_profile(
    inbound, profile_index, config, upstreams, route_by_inbound, domain, now
):
    stream_settings = inbound.get("streamSettings", {})
    if stream_settings.get("security") not in {"reality", "tls"} or stream_settings.get(
        "network", "tcp"
    ) not in {"tcp", "xhttp"}:
        raise app_errors.VpnctlError("unsupported VLESS inbound transport or security")
    reality_settings = stream_settings.get("realitySettings", {})
    private_key = reality_settings.get("privateKey")
    short_ids = reality_settings.get("shortIds") or []
    if stream_settings.get("security") == "reality" and (
        not private_key or not short_ids
    ):
        raise app_errors.VpnctlError(
            f"inbound {inbound.get('tag', profile_index)} is missing REALITY privateKey or shortIds"
        )
    tag = inbound.get("tag") or f"profile{profile_index}"
    profile_name = imported_profile_name(tag, f"profile{profile_index}")
    default_outbound = (config.get("outbounds") or [{}])[0]
    default_tag = (
        default_outbound.get("tag", "direct")
        if default_outbound.get("protocol", "freedom") == "freedom"
        else default_outbound.get("tag")
    )
    outbound_tag = route_by_inbound.get(tag, default_tag)
    if outbound_tag not in {"direct", "block", *upstreams}:
        raise app_errors.VpnctlError(
            "import cannot preserve the inbound's outbound route"
        )
    profile = _profile_data(
        inbound,
        stream_settings,
        reality_settings,
        profile_name,
        now,
        outbound_tag,
        upstreams,
        domain,
        private_key,
        short_ids,
    )
    _import_tls_security(profile, stream_settings)
    return profile


def _profile_data(
    inbound,
    stream_settings,
    reality_settings,
    profile_name,
    now,
    outbound_tag,
    upstreams,
    domain,
    private_key,
    short_ids,
):
    profile = {
        "name": profile_name,
        "created_at": now,
        "updated_at": now,
        "port": app_values.parse_port(inbound.get("port", app_settings.DEFAULT_PORT)),
        "reality_target": reality_settings.get("target")
        or reality_settings.get("dest")
        or "www.cloudflare.com:443",
        "outbound_mode": app_settings.OUTBOUND_PROXY
        if outbound_tag in upstreams
        else app_settings.OUTBOUND_DIRECT,
        "short_id": short_ids[0] if short_ids else "",
        "route": outbound_tag,
        "transport": {
            "type": stream_settings.get("network", "tcp"),
            "settings": stream_settings.get("xhttpSettings", {}),
        },
        "keys": {
            "private_key": private_key,
            "public_key": app_keys.public_key_from_private(private_key)
            if private_key
            else "",
        },
        "clients": [
            import_client(client, profile_name, domain)
            for client in inbound.get("settings", {}).get("clients", [])
        ],
    }
    return profile


def _import_tls_security(profile, stream_settings):
    if stream_settings.get("security") == "tls":
        tls = stream_settings.get("tlsSettings", {})
        profile["security"] = {
            "type": "tls",
            "settings": {
                "server_name": tls.get("serverName")
                or profile["reality_target"].split(":")[0],
                "certificates": tls.get("certificates", []),
                "alpn": tls.get("alpn", ["h2", "http/1.1"]),
            },
        }
        if tls.get("echServerKeys"):
            profile["security"]["settings"]["ech_server_keys"] = tls["echServerKeys"]


def _outbound_query(stream_settings, reality_settings, user):
    network = stream_settings.get("network", "tcp")
    security_type = stream_settings.get("security")
    tls = stream_settings.get("tlsSettings", {})
    if tls.get("allowInsecure"):
        raise app_errors.VpnctlError("insecure TLS upstreams cannot be imported")
    xhttp = stream_settings.get("xhttpSettings", {})
    if set(xhttp) - {"path", "host", "mode"}:
        raise app_errors.VpnctlError("unsupported XHTTP import settings")
    query = {
        "type": network,
        "security": security_type,
        "encryption": user.get("encryption", "none"),
        "flow": user.get("flow", app_settings.DEFAULT_FLOW if network == "tcp" else ""),
        "sni": reality_settings.get("serverName", "")
        if security_type == "reality"
        else tls.get("serverName", ""),
    }
    if security_type == "reality":
        query.update(
            {
                "pbk": reality_settings.get("publicKey", ""),
                "sid": reality_settings.get("shortId", ""),
                "fp": reality_settings.get(
                    "fingerprint", app_settings.DEFAULT_FINGERPRINT
                ),
                "spx": reality_settings.get("spiderX", "/"),
            }
        )
    elif tls.get("alpn"):
        query["alpn"] = ",".join(tls["alpn"])
    if tls.get("echConfigList"):
        if tls.get("echForceQuery", "full") != "full":
            raise app_errors.VpnctlError("import requires full ECH query policy")
        query["ech"] = tls["echConfigList"]
    if network == "xhttp":
        query.update(
            {
                "path": xhttp.get("path", "/"),
                "host": xhttp.get("host", ""),
                "mode": xhttp.get(
                    "mode", "stream-one" if security_type == "reality" else "auto"
                ),
            }
        )
    return query
