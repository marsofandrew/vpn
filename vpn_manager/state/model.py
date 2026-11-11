from typing import Any

from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values


def safe_client_email(name: str, default_domain: str) -> str:
    local = "".join(char if char.isalnum() or char in "._-" else "-" for char in name)
    local = local.strip(".-_") or "client"
    return f"{local}@{default_domain}"


def client_email(
    name: str,
    default_domain: str,
    profile_name: str = app_settings.DEFAULT_PROFILE_NAME,
) -> str:
    if profile_name == app_settings.DEFAULT_PROFILE_NAME:
        return safe_client_email(name, default_domain)
    return safe_client_email(f"{profile_name}-{name}", default_domain)


def all_profiles(state: dict[str, Any]) -> list[dict[str, Any]]:
    return state.setdefault("profiles", [])


def profile_label(profile: dict[str, Any]) -> str:
    return profile.get("name", app_settings.DEFAULT_PROFILE_NAME)


def require_profile(state: dict[str, Any], name: str | None = None) -> dict[str, Any]:
    profiles = all_profiles(state)
    target = name or app_settings.DEFAULT_PROFILE_NAME
    for profile in profiles:
        if profile_label(profile) == target:
            return profile
    raise app_errors.VpnctlError(f"profile not found: {target}")


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
    safe_name = "".join(
        char if char.isalnum() or char in "._-" else "_" for char in name
    )
    return f"vless_reality_{safe_name or app_settings.DEFAULT_PROFILE_NAME}"


def profile_outbound_mode(profile: dict[str, Any]) -> str:
    return app_values.validate_outbound_mode(
        profile.get("outbound_mode", app_settings.OUTBOUND_DIRECT)
    )


def proxy_profiles(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        profile
        for profile in all_profiles(state)
        if profile_outbound_mode(profile) == app_settings.OUTBOUND_PROXY
    ]


def find_client(
    state: dict[str, Any],
    name_or_id: str,
    profile_name: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    profiles = (
        [require_profile(state, profile_name)] if profile_name else all_profiles(state)
    )
    for profile in profiles:
        for client in profile.get("clients", []):
            if client["name"] == name_or_id or client["id"] == name_or_id:
                matches.append((profile, client))
    if not matches:
        return None
    if len(matches) > 1:
        profiles_text = ", ".join(profile_label(profile) for profile, _ in matches)
        raise app_errors.VpnctlError(
            f"client name is ambiguous across profiles ({profiles_text}); pass --profile"
        )
    return matches[0]


def require_client(
    state: dict[str, Any],
    name_or_id: str,
    profile_name: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    match = find_client(state, name_or_id, profile_name)
    if match is None:
        suffix = f" in profile {profile_name}" if profile_name else ""
        raise app_errors.VpnctlError(f"client not found{suffix}: {name_or_id}")
    return match
