import argparse
from typing import Any

from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager.state import model as app_state_model
from vpn_manager.state import validation as app_state_validation


def migrate_legacy_state(raw: dict[str, Any]) -> dict[str, Any]:
    try:
        return _migrate_legacy_state(raw)
    except (
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
        argparse.ArgumentTypeError,
    ):
        raise app_errors.VpnctlError("invalid state structure or field types") from None


def _migrate_legacy_state(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("version") == app_settings.STATE_VERSION:
        raw.setdefault("usage_period", app_clock.current_usage_period())
        app_state_validation.validate_state(raw)
        return raw

    if raw.get("version") == 3:
        migrated = upgrade_state(raw)
        app_state_validation.validate_state(migrated)
        return migrated

    if raw.get("version") == 2 and "profiles" in raw:
        raw["version"] = 3
        raw.setdefault("usage_period", app_clock.current_usage_period())
        raw.setdefault("upstream", None)
        for profile in app_state_model.all_profiles(raw):
            profile.setdefault("outbound_mode", app_settings.OUTBOUND_DIRECT)
        migrated = upgrade_state(raw)
        app_state_validation.validate_state(migrated)
        return migrated

    if {"keys", "short_id", "clients", "default_domain"}.issubset(raw.keys()):
        migrated = app_state_creation_from_legacy(raw)
        app_state_validation.validate_state(migrated)
        return migrated
    raise app_errors.VpnctlError("state file is not a recognized vpnctl state format")


def app_state_creation_from_legacy(raw):
    now = app_clock.utc_now()
    migrated = {
        "version": app_settings.STATE_VERSION,
        "created_at": raw.get("created_at", now),
        "updated_at": now,
        "usage_period": raw.get("usage_period", app_clock.current_usage_period()),
        "server_host": raw.get("server_host", "127.0.0.1"),
        "default_domain": raw["default_domain"],
        "fingerprint": raw.get("fingerprint", app_settings.DEFAULT_FINGERPRINT),
        "flow": raw.get("flow", app_settings.DEFAULT_FLOW),
        "spider_x": raw.get("spider_x", app_settings.DEFAULT_SPIDER_X),
        "upstream": raw.get("upstream"),
        "profiles": [_legacy_profile(raw, now)],
    }
    return upgrade_state(migrated)


def _legacy_profile(raw, now):
    return {
        "name": app_settings.DEFAULT_PROFILE_NAME,
        "created_at": raw.get("created_at", now),
        "updated_at": raw.get("updated_at", now),
        "port": int(raw.get("port", app_settings.DEFAULT_PORT)),
        "reality_target": raw.get("reality_target")
        or raw.get("dest", "www.cloudflare.com:443"),
        "outbound_mode": raw.get("outbound_mode", app_settings.OUTBOUND_DIRECT),
        "short_id": raw["short_id"],
        "keys": raw["keys"],
        "clients": [
            _legacy_client(client, raw["default_domain"], now)
            for client in raw.get("clients", [])
        ],
    }


def _legacy_client(client, default_domain, now):
    return {
        "name": client["name"],
        "id": client["id"],
        "email": client.get("email")
        or app_state_model.safe_client_email(client["name"], default_domain),
        "enabled": client.get("enabled", True),
        "quota_bytes": client.get("quota_bytes"),
        "used_uplink_bytes": int(client.get("used_uplink_bytes", 0)),
        "used_downlink_bytes": int(client.get("used_downlink_bytes", 0)),
        "created_at": client.get("created_at", now),
        "updated_at": client.get("updated_at", now),
        "disabled_reason": client.get("disabled_reason"),
    }


def canonical_upstream(upstream: dict[str, Any]) -> dict[str, Any]:
    if "transport" in upstream:
        return upstream
    if (
        upstream.get("network", "tcp") != "tcp"
        or upstream.get("security", "reality") != "reality"
    ):
        raise app_errors.VpnctlError("unsupported legacy upstream transport")
    return {
        "protocol": "vless",
        "address": upstream["host"],
        "port": upstream["port"],
        "auth": {
            "id": upstream["id"],
            "encryption": "none",
            "flow": upstream.get("flow", app_settings.DEFAULT_FLOW),
        },
        "transport": {"type": "tcp", "settings": {}},
        "security": {
            "type": "reality",
            "settings": {
                "server_name": upstream["server_name"],
                "public_key": upstream["public_key"],
                "short_id": upstream["short_id"],
                "fingerprint": upstream.get(
                    "fingerprint", app_settings.DEFAULT_FINGERPRINT
                ),
                "spider_x": upstream.get("spider_x", "/"),
            },
        },
        "enabled": True,
    }


def upgrade_state(raw: dict[str, Any]) -> dict[str, Any]:
    raw["version"] = app_settings.STATE_VERSION
    raw.setdefault("node", {"id": "local", "role": "both"})
    upstream = raw.pop("upstream", None)
    raw.setdefault("upstreams", {})
    if upstream:
        raw["upstreams"][app_settings.UPSTREAM_OUTBOUND_TAG] = canonical_upstream(
            upstream
        )
    raw.setdefault(
        "routing_policies", {"direct": {"type": "direct"}, "block": {"type": "block"}}
    )
    if upstream:
        raw["routing_policies"][app_settings.UPSTREAM_OUTBOUND_TAG] = {
            "type": "upstream",
            "upstreams": [app_settings.UPSTREAM_OUTBOUND_TAG],
        }
    for profile in raw["profiles"]:
        profile.setdefault("transport", {"type": "tcp", "settings": {}})
        profile.setdefault(
            "route",
            "direct"
            if app_state_model.profile_outbound_mode(profile) == "direct"
            else app_settings.UPSTREAM_OUTBOUND_TAG,
        )
    return raw
