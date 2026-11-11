import math
import time
from typing import Any

import vpn_health
import vpn_transports
import vpn_validation
from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.state import model as app_state_model


def validate_state(
    state: dict[str, Any], api_port: int = app_settings.DEFAULT_API_PORT
) -> None:
    try:
        vpn_validation.validate_state_shape(state)
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None
    state["server_host"] = app_values.validate_server_host(state.get("server_host"))
    if not app_state_model.all_profiles(state):
        raise app_errors.VpnctlError("at least one profile is required")
    if state.get("version") != app_settings.STATE_VERSION:
        raise app_errors.VpnctlError("unsupported state version")
    _validate_node(state["node"])
    _validate_upstreams(state)
    for name, policy in state["routing_policies"].items():
        _validate_policy(name, policy, state["upstreams"])
    _validate_profiles(state, api_port)


def _validate_node(node):
    if node["role"] not in {"gateway", "exit", "both"}:
        raise app_errors.VpnctlError("invalid node role")
    if not isinstance(node.get("foreign_only", False), bool):
        raise app_errors.VpnctlError("foreign_only must be a boolean")
    app_values.validate_profile_name(node["id"])


def _validate_upstreams(state):
    for name, upstream in state["upstreams"].items():
        app_values.validate_stable_name(name)
        if name in {"direct", "block", "api"}:
            raise app_errors.VpnctlError("upstream name is reserved")
        try:
            vpn_transports.validate_upstream(upstream)
        except ValueError as error:
            raise app_errors.VpnctlError(str(error)) from None
    if any(name not in state["upstreams"] for name in state.get("upstream_nodes", {})):
        raise app_errors.VpnctlError("node binding references an unknown upstream")


def _validate_policy(name, policy, upstreams):
    app_values.validate_stable_name(name)
    if policy["type"] not in {"direct", "upstream", "block", "balanced", "priority"}:
        raise app_errors.VpnctlError("unsupported routing policy")
    if policy["type"] not in {"upstream", "balanced", "priority"}:
        return
    members = policy.get("upstreams", [])
    if (
        not members
        or len(set(members)) != len(members)
        or any(member not in upstreams for member in members)
    ):
        raise app_errors.VpnctlError(
            "policy must reference distinct existing upstreams"
        )
    if policy["type"] == "upstream" and len(members) != 1:
        raise app_errors.VpnctlError("upstream policy requires one upstream")
    cooldown = policy.get("cooldown", 60)
    if (
        isinstance(cooldown, bool)
        or not isinstance(cooldown, (int, float))
        or not math.isfinite(cooldown)
        or cooldown < 0
    ):
        raise app_errors.VpnctlError("cooldown must be finite and nonnegative")
    try:
        vpn_health.select_route(policy, upstreams, {}, time.time())
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None


def _profile_route(profile, state):
    profile["outbound_mode"] = app_state_model.profile_outbound_mode(profile)
    route = profile.get(
        "route",
        "direct"
        if profile["outbound_mode"] == "direct"
        else app_settings.UPSTREAM_OUTBOUND_TAG,
    )
    profile["route"] = route
    policy = state["routing_policies"].get(route)
    if policy is None:
        raise app_errors.VpnctlError("profile references an unknown policy")
    if state["node"].get("foreign_only") and policy["type"] == "direct":
        raise app_errors.VpnctlError("foreign-only nodes cannot assign direct policies")
    if policy["type"] == "upstream" and not state["upstreams"][
        policy["upstreams"][0]
    ].get("enabled", True):
        raise app_errors.VpnctlError("profile references a disabled upstream")


def _validate_profiles(state, api_port):
    names, ports, emails, ids = set(), {}, {}, {}
    for profile in app_state_model.all_profiles(state):
        name = app_values.validate_profile_name(app_state_model.profile_label(profile))
        _profile_route(profile, state)
        if name in names:
            raise app_errors.VpnctlError(f"duplicate profile name: {name}")
        names.add(name)
        port = app_values.parse_port(profile.get("port", app_settings.DEFAULT_PORT))
        if port == api_port:
            raise app_errors.VpnctlError(
                f"profile {name} uses reserved API port {api_port}"
            )
        if port in ports:
            raise app_errors.VpnctlError(
                f"profile {name} uses duplicate port {port} already used by {ports[port]}"
            )
        ports[port] = name
        _validate_client_identities(profile, name, emails, ids)


def _validate_client_identities(profile, name, emails, ids):
    client_names = set()
    for client in profile.get("clients", []):
        client_name, client_id, email = (
            client.get("name", ""),
            client.get("id", ""),
            client.get("email", ""),
        )
        if client_name in client_names:
            raise app_errors.VpnctlError(
                f"duplicate client name in profile {name}: {client_name}"
            )
        client_names.add(client_name)
        if client_id in ids:
            raise app_errors.VpnctlError("duplicate client authentication identity")
        if email in emails:
            raise app_errors.VpnctlError(
                f"duplicate client email {email} in profiles {emails[email]} and {name}"
            )
        ids[client_id] = name
        emails[email] = name
