#!/usr/bin/env python3
import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


STATE_VERSION = 2
DEFAULT_STATE_PATH = Path("data/vpn_state.json")
DEFAULT_CONFIG_PATH = Path("data/config.json")
DEFAULT_COMPOSE_FILE = Path("docker-compose.yaml")
DEFAULT_PROFILE_NAME = "default"
DEFAULT_PORT = 443
DEFAULT_API_PORT = 10085
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_FLOW = "xtls-rprx-vision"
DEFAULT_SPIDER_X = "/"
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
    port: int,
    client_names: list[str],
    quota_bytes: int | None,
    profile_name: str = DEFAULT_PROFILE_NAME,
) -> dict[str, Any]:
    now = utc_now()
    return {
        "version": STATE_VERSION,
        "created_at": now,
        "updated_at": now,
        "usage_period": current_usage_period(),
        "server_host": server_host,
        "default_domain": default_domain,
        "fingerprint": DEFAULT_FINGERPRINT,
        "flow": DEFAULT_FLOW,
        "spider_x": DEFAULT_SPIDER_X,
        "profiles": [
            create_profile(profile_name, reality_target, default_domain, port, client_names, quota_bytes)
        ],
    }


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


def validate_state(state: dict[str, Any], api_port: int = DEFAULT_API_PORT) -> None:
    profiles = all_profiles(state)
    if not profiles:
        raise VpnctlError("at least one profile is required")

    names: set[str] = set()
    ports: dict[int, str] = {}
    emails: dict[str, str] = {}
    ids: dict[str, str] = {}
    for profile in profiles:
        name = validate_profile_name(profile_label(profile))
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
            "profiles": [
                {
                    "name": DEFAULT_PROFILE_NAME,
                    "created_at": raw.get("created_at", now),
                    "updated_at": raw.get("updated_at", now),
                    "port": int(raw.get("port", DEFAULT_PORT)),
                    "reality_target": raw.get("reality_target") or raw.get("dest", "www.cloudflare.com:443"),
                    "short_id": raw["short_id"],
                    "keys": raw["keys"],
                    "clients": migrated_clients,
                }
            ],
        }
        validate_state(migrated)
        return migrated

    raise VpnctlError("state file is not a recognized vpnctl state format")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        legacy_path = Path("vpn_config.json")
        if legacy_path.exists():
            return migrate_legacy_state(load_json(legacy_path))
        raise VpnctlError(f"state file not found: {path}")
    return migrate_legacy_state(load_json(path))


def save_state(path: Path, state: dict[str, Any]) -> None:
    validate_state(state)
    state["updated_at"] = utc_now()
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
                    "flow": state.get("flow", DEFAULT_FLOW),
                    "level": 0,
                }
            )

    return {
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

    return {
        "log": {
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log",
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
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api",
                }
            ]
        },
        "stats": {},
    }


def render_and_save_config(state: dict[str, Any], config_path: Path) -> None:
    write_json(config_path, render_config(state))


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
    save_state(state_path, state)
    render_and_save_config(state, config_path)
    if restart and compose_file is not None:
        restart_xray(compose_file, state)


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
    reality_host, _ = split_host_port(profile["reality_target"])
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
    return f"vless://{client['id']}@{state['server_host']}:{profile['port']}?{query}#{label}"


def write_qr(link: str, client_name: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    qr_path = output_dir / f"{client_name}.png"
    image = qrcode.make(link)
    image.save(qr_path)
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
        )
    except subprocess.CalledProcessError as error:
        if is_docker_permission_error(error):
            raise docker_permission_error() from error
        raise


def restart_xray(compose_file: Path, state: dict[str, Any] | None = None) -> None:
    run_compose(compose_file, ["up", "-d", XRAY_SERVICE])


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
            f"\tclients={enabled_count}/{len(clients)}"
        )


def command_profile_add(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    ensure_monthly_period(state)
    profile_name = validate_profile_name(args.name)
    if find_profile(state, profile_name):
        raise VpnctlError(f"profile already exists: {profile_name}")
    quota_bytes = parse_size(args.quota)
    profile = create_profile(
        profile_name,
        args.reality_target,
        state["default_domain"],
        args.port,
        args.client or [],
        quota_bytes,
    )
    state["profiles"].append(profile)
    persist_state_and_config(state, args.state, args.config, args.compose_file, restart=not args.no_restart)
    print(f"Profile added: {profile_label(profile)} on port {profile['port']}")
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
    )
    save_state(args.state, state)
    render_and_save_config(state, args.config)
    print(f"State saved to {args.state}")
    print(f"Xray config rendered to {args.config}")
    profile = require_profile(state, args.profile)
    for client in profile["clients"]:
        print(f"Client {profile_label(profile)}/{client['name']}: {generate_vless_link(client, state, profile)}")


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
    stats = query_xray_stats(args.compose_file, reset=True, state=state)
    changed = False if period_changed else apply_usage_deltas(state, collect_usage_deltas(stats))
    disabled = enforce_quotas(state)
    if period_changed or changed or disabled:
        persist_state_and_config(
            state,
            args.state,
            args.config,
            args.compose_file,
            restart=(period_changed or bool(disabled)) and not args.no_restart,
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
        print(f"Monthly quota period rolled over to {state['usage_period']}. Xray counters were reset.")
    if not disabled:
        print("No clients exceeded quota.")


def command_usage(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    period_changed = ensure_monthly_period(state)
    if args.refresh:
        stats = query_xray_stats(args.compose_file, reset=True, state=state)
        if not period_changed and apply_usage_deltas(state, collect_usage_deltas(stats)):
            period_changed = True
    if period_changed:
        save_state(args.state, state)
        render_and_save_config(state, args.config)
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
    init_parser.add_argument("--reality-target", required=True, help="REALITY target, for example www.cloudflare.com:443.")
    init_parser.add_argument("--default-domain", help="Domain used in generated client emails. Defaults to server host.")
    init_parser.add_argument("--port", type=parse_port, default=DEFAULT_PORT, help="Public VLESS port.")
    init_parser.add_argument("--profile", default=DEFAULT_PROFILE_NAME, help="Initial VPN profile name.")
    init_parser.add_argument("--client", action="append", required=True, help="Initial client name. Repeatable.")
    init_parser.add_argument("--quota", help="Optional initial monthly quota for all created clients, for example 50GiB.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing state.")
    init_parser.set_defaults(func=command_init)

    render_parser = subparsers.add_parser("render", help="Render config from state.")
    render_parser.set_defaults(func=command_render)

    profile_parser = subparsers.add_parser("profile", help="Manage VPN profiles.")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command", required=True)
    profile_list_parser = profile_subparsers.add_parser("list", help="List VPN profiles.")
    profile_list_parser.set_defaults(func=command_profile_list)

    profile_add_parser = profile_subparsers.add_parser("add", help="Add a VPN profile on another port.")
    profile_add_parser.add_argument("name")
    profile_add_parser.add_argument("--port", type=parse_port, required=True, help="Public VLESS port for this profile.")
    profile_add_parser.add_argument("--reality-target", required=True, help="REALITY target, for example www.cloudflare.com:443.")
    profile_add_parser.add_argument("--client", action="append", help="Initial client name. Repeatable.")
    profile_add_parser.add_argument("--quota", help="Optional initial monthly quota for created clients, for example 50GiB.")
    profile_add_parser.add_argument("--no-restart", action="store_true")
    profile_add_parser.set_defaults(func=command_profile_add)

    profile_remove_parser = profile_subparsers.add_parser("remove", help="Remove a VPN profile and its clients.")
    profile_remove_parser.add_argument("name")
    profile_remove_parser.add_argument("--no-restart", action="store_true")
    profile_remove_parser.set_defaults(func=command_profile_remove)

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
    usage_parser.add_argument("--refresh", action="store_true", help="Pull and reset current Xray counters before printing.")
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
    try:
        args.func(args)
    except (VpnctlError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
