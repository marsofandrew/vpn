import os
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import qrcode

import vpn_transports
from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings
from vpn_manager import values as app_values
from vpn_manager.state import model as app_state_model


def generate_vless_link(
    client: dict[str, Any], state: dict[str, Any], profile: dict[str, Any]
) -> str:
    if profile.get("transport", {}).get("type", "tcp") != "tcp" or profile.get(
        "security"
    ):
        return _extended_link(client, state, profile)
    reality_host, _ = app_values.split_host_port(profile["reality_target"])
    server_host = app_values.validate_server_host(state["server_host"])
    params = {
        "type": "tcp",
        "encryption": "none",
        "security": "reality",
        "pbk": profile["keys"]["public_key"],
        "fp": state.get("fingerprint", app_settings.DEFAULT_FINGERPRINT),
        "sni": reality_host,
        "sid": profile["short_id"],
        "spx": state.get("spider_x", app_settings.DEFAULT_SPIDER_X),
        "flow": state.get("flow", app_settings.DEFAULT_FLOW),
    }
    query = urlencode(params)
    label = quote(f"{app_state_model.profile_label(profile)}:{client['name']}")
    return f"vless://{client['id']}@{server_host}:{profile['port']}?{query}#{label}"


def _extended_link(client, state, profile):
    host, _ = app_values.split_host_port(profile["reality_target"])
    security = profile.get("security") or {
        "type": "reality",
        "settings": {
            "server_name": host,
            "public_key": profile["keys"]["public_key"],
            "short_id": profile["short_id"],
            "fingerprint": state.get("fingerprint", app_settings.DEFAULT_FINGERPRINT),
        },
    }
    security = {"type": security["type"], "settings": dict(security["settings"])}
    for field in (
        "certificates",
        "private_key",
        "short_ids",
        "target",
        "ech_server_keys",
    ):
        security["settings"].pop(field, None)
    if profile.get("client_ech_config_list"):
        security["settings"]["ech_config_list"] = profile["client_ech_config_list"]
    endpoint = {
        "protocol": "vless",
        "address": state["server_host"].strip("[]"),
        "port": profile["port"],
        "auth": {"id": client["id"], "encryption": "none", "flow": ""},
        "transport": profile["transport"],
        "security": security,
        "enabled": True,
    }
    try:
        return vpn_transports.export_link(
            endpoint, f"{app_state_model.profile_label(profile)}:{client['name']}"
        )
    except ValueError as error:
        raise app_errors.VpnctlError(str(error)) from None


def write_qr(link: str, client_name: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    qr_path = output_dir / f"{client_name}.png"
    image = qrcode.make(link)
    descriptor = os.open(qr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        image.save(handle, format="PNG")
    return qr_path
