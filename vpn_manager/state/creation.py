import os
import uuid
from typing import Any

from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import keys as app_keys
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.state import legacy_links as app_state_legacy_links
from vpn_manager.state import migration as app_state_migration
from vpn_manager.state import model as app_state_model


def create_client(
    name: str,
    default_domain: str,
    quota_bytes: int | None = None,
    profile_name: str = app_settings.DEFAULT_PROFILE_NAME,
) -> dict[str, Any]:
    now = app_clock.utc_now()
    return {
        "name": name,
        "id": str(uuid.uuid4()),
        "email": app_state_model.client_email(name, default_domain, profile_name),
        "enabled": True,
        "quota_bytes": quota_bytes,
        "used_uplink_bytes": 0,
        "used_downlink_bytes": 0,
        "created_at": now,
        "updated_at": now,
        "disabled_reason": None,
    }


def create_profile(
    name: str,
    reality_target: str,
    default_domain: str,
    port: int,
    client_names: list[str],
    quota_bytes: int | None,
    outbound_mode: str = app_settings.OUTBOUND_DIRECT,
) -> dict[str, Any]:
    keys = app_keys.generate_reality_keys()
    now = app_clock.utc_now()
    profile_name = app_values.validate_profile_name(name)
    return {
        "name": profile_name,
        "created_at": now,
        "updated_at": now,
        "port": app_values.parse_port(port),
        "reality_target": reality_target,
        "outbound_mode": app_values.validate_outbound_mode(outbound_mode),
        "short_id": os.urandom(8).hex(),
        "keys": keys,
        "clients": [
            create_client(client_name, default_domain, quota_bytes, profile_name)
            for client_name in app_values.deduplicate_names(client_names)
        ],
    }


def create_state(
    server_host: str,
    reality_target: str,
    default_domain: str,
    port: int | None,
    client_names: list[str],
    quota_bytes: int | None,
    profile_name: str = app_settings.DEFAULT_PROFILE_NAME,
    upstream_link: str | None = None,
    mode: str = app_settings.OUTBOUND_DIRECT,
    direct_port: int = app_settings.DEFAULT_PORT,
    proxy_port: int = 8443,
) -> dict[str, Any]:
    now = app_clock.utc_now()
    init_mode = mode.strip().lower()
    if init_mode not in {"direct", "proxy", "both"}:
        raise app_errors.VpnctlError("init mode must be direct, proxy, or both")
    upstream = (
        app_state_legacy_links.parse_upstream_link(upstream_link)
        if upstream_link
        else None
    )
    profiles = _initial_profiles(
        init_mode,
        profile_name,
        reality_target,
        default_domain,
        port,
        direct_port,
        proxy_port,
        client_names,
        quota_bytes,
    )
    normalized_server_host = app_values.validate_server_host(server_host)
    return app_state_migration.upgrade_state(
        {
            "version": 3,
            "created_at": now,
            "updated_at": now,
            "usage_period": app_clock.current_usage_period(),
            "server_host": normalized_server_host,
            "default_domain": default_domain,
            "fingerprint": app_settings.DEFAULT_FINGERPRINT,
            "flow": app_settings.DEFAULT_FLOW,
            "spider_x": app_settings.DEFAULT_SPIDER_X,
            "upstream": upstream,
            "profiles": profiles,
        }
    )


def _initial_profiles(
    init_mode,
    profile_name,
    reality_target,
    default_domain,
    port,
    direct_port,
    proxy_port,
    client_names,
    quota_bytes,
):
    profiles: list[dict[str, Any]]
    if init_mode == "both":
        profiles = [
            create_profile(
                "direct",
                reality_target,
                default_domain,
                direct_port,
                client_names,
                quota_bytes,
                app_settings.OUTBOUND_DIRECT,
            ),
            create_profile(
                "proxy",
                reality_target,
                default_domain,
                proxy_port,
                client_names,
                quota_bytes,
                app_settings.OUTBOUND_PROXY,
            ),
        ]
    else:
        profile_port = port if port is not None else app_settings.DEFAULT_PORT
        profiles = [
            create_profile(
                profile_name,
                reality_target,
                default_domain,
                profile_port,
                client_names,
                quota_bytes,
                init_mode,
            )
        ]
    return profiles
