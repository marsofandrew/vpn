import copy
from pathlib import Path
from typing import Any

import vpn_transports
from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.state import model as app_state_model
from vpn_manager.state import validation as app_state_validation


def render_vless_inbound(
    state: dict[str, Any], profile: dict[str, Any]
) -> dict[str, Any]:
    reality_host, _ = app_values.split_host_port(profile["reality_target"])
    enabled_clients = _inbound_clients(state, profile)

    inbound = {
        "tag": app_state_model.profile_tag(profile),
        "listen": "0.0.0.0",
        "port": app_values.parse_port(profile.get("port", app_settings.DEFAULT_PORT)),
        "protocol": "vless",
        "settings": {
            "clients": enabled_clients,
            "decryption": "none",
        },
        "streamSettings": _reality_stream(profile, reality_host),
    }
    transport = profile.get("transport", {"type": "tcp", "settings": {}})
    if transport["type"] != "tcp" or profile.get("security"):
        security = profile.get("security") or {
            "type": "reality",
            "settings": {
                "target": profile["reality_target"],
                "server_name": reality_host,
                "private_key": profile["keys"]["private_key"],
                "short_ids": [profile["short_id"]],
            },
        }
        try:
            inbound["streamSettings"] = vpn_transports.render_stream(
                transport, security, server=True
            )
        except ValueError as error:
            raise app_errors.VpnctlError(str(error)) from None
    return inbound


def _inbound_clients(state, profile):
    enabled_clients = []
    for client in profile.get("clients", []):
        if client.get("enabled", True):
            enabled_clients.append(
                {
                    "id": client["id"],
                    "email": client["email"],
                    "flow": state.get("flow", app_settings.DEFAULT_FLOW)
                    if profile.get("transport", {}).get("type", "tcp") == "tcp"
                    else "",
                    "level": 0,
                }
            )
    return enabled_clients


def _reality_stream(profile, reality_host):
    return {
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
    }


def render_upstream_outbound(
    state: dict[str, Any], name: str = app_settings.UPSTREAM_OUTBOUND_TAG
) -> dict[str, Any]:
    try:
        return vpn_transports.render_outbound(state["upstreams"][name], name)
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None


def render_direct_outbound() -> dict[str, Any]:
    return {
        "tag": app_settings.OUTBOUND_DIRECT,
        "protocol": "freedom",
        "settings": {},
    }


def profile_outbound_tag(profile: dict[str, Any], state: dict[str, Any]) -> str:
    policy = state["routing_policies"][profile["route"]]
    if policy["type"] == "upstream":
        return policy["upstreams"][0]
    if policy["type"] in {"priority", "balanced"}:
        selected = policy.get("current_upstream")
        if (
            selected in policy["upstreams"]
            and state["upstreams"][selected].get("enabled", True)
            and state.get("health", {}).get(selected, {}).get("status") == "healthy"
        ):
            return selected
        return "block"
    return policy["type"]


def render_config(
    state: dict[str, Any], api_port: int = app_settings.DEFAULT_API_PORT
) -> dict[str, Any]:
    app_state_validation.validate_state(state, api_port)
    config: dict[str, Any] = copy.deepcopy(_RUNTIME_SETTINGS)
    config["inbounds"] = [
        render_vless_inbound(state, profile)
        for profile in app_state_model.all_profiles(state)
    ]
    config["inbounds"].append(_api_inbound(api_port))
    config["outbounds"] = _outbounds(state)
    config["routing"] = {"rules": _routing_rules(state)}
    return config


def _api_inbound(api_port):
    return {
        "tag": "api",
        "listen": "127.0.0.1",
        "port": api_port,
        "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    }


def _outbounds(state):
    guarded = state["node"].get("foreign_only") or any(
        state["routing_policies"][profile["route"]]["type"]
        in {"priority", "balanced", "block"}
        for profile in app_state_model.all_profiles(state)
    )
    outbounds = (
        [{"tag": "block", "protocol": "blackhole", "settings": {}}] if guarded else []
    )
    if not state["node"].get("foreign_only"):
        outbounds.append(render_direct_outbound())
    referenced = {
        member
        for profile in app_state_model.all_profiles(state)
        for member in state["routing_policies"][profile["route"]].get("upstreams", [])
    }
    outbounds.extend(
        render_upstream_outbound(state, name)
        for name in sorted(referenced)
        if state["upstreams"][name].get("enabled", True)
    )
    return outbounds


def _routing_rules(state):
    rules = [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]
    rules.extend(
        {
            "type": "field",
            "inboundTag": [app_state_model.profile_tag(profile)],
            "outboundTag": profile_outbound_tag(profile, state),
        }
        for profile in app_state_model.all_profiles(state)
    )
    return rules


def render_and_save_config(state: dict[str, Any], config_path: Path) -> None:
    destination = (
        config_path.with_name(config_path.name + ".pending")
        if config_path.exists()
        else config_path
    )
    app_files.write_json(destination, render_config(state))


def validate_config(config: dict[str, Any]) -> None:
    inbounds = [inbound["tag"] for inbound in config["inbounds"]]
    outbounds = [outbound["tag"] for outbound in config["outbounds"]]
    if len(set(inbounds)) != len(inbounds) or len(set(outbounds)) != len(outbounds):
        raise app_errors.VpnctlError("duplicate Xray tags")
    for rule in config["routing"]["rules"]:
        if not set(rule["inboundTag"]).issubset(inbounds):
            raise app_errors.VpnctlError("routing references an unknown inbound")
        if rule["outboundTag"] not in outbounds + [config["api"]["tag"]]:
            raise app_errors.VpnctlError("routing references an unknown outbound")


_RUNTIME_SETTINGS = {
    "log": {"access": "none", "loglevel": "warning"},
    "api": {
        "tag": "api",
        "services": ["HandlerService", "LoggerService", "StatsService"],
    },
    "policy": {
        "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
        "system": {
            "statsInboundUplink": True,
            "statsInboundDownlink": True,
            "statsOutboundUplink": True,
            "statsOutboundDownlink": True,
        },
    },
    "stats": {},
}
