import argparse

from vpn_manager import errors as app_errors
from vpn_manager import settings as app_settings


def parse_size(value: str | None) -> int | None:
    if value is None:
        return None
    raw = value.strip().lower()
    if not raw:
        raise app_errors.VpnctlError("quota cannot be empty")

    number_part = ""
    unit_part = ""
    for char in raw:
        if char.isdigit() or char == ".":
            if unit_part:
                raise app_errors.VpnctlError(f"invalid quota size: {value}")
            number_part += char
        elif char.isalpha():
            unit_part += char
        elif char.isspace():
            continue
        else:
            raise app_errors.VpnctlError(f"invalid quota size: {value}")

    if not number_part:
        raise app_errors.VpnctlError(f"invalid quota size: {value}")
    unit = unit_part or "b"
    if unit not in app_settings.SIZE_UNITS:
        raise app_errors.VpnctlError(
            f"invalid quota unit '{unit_part}'. Use bytes, KB, MB, GB, KiB, MiB, GiB, or TiB."
        )
    return int(float(number_part) * app_settings.SIZE_UNITS[unit])


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
        raise app_errors.VpnctlError("server host cannot be empty")
    if "://" in raw:
        raise app_errors.VpnctlError("server host must not include a URL scheme")
    if any(char in raw for char in "/?#@"):
        raise app_errors.VpnctlError(
            "server host must be a hostname or IP address only"
        )
    if raw.startswith("[") or raw.endswith("]"):
        if not (raw.startswith("[") and raw.endswith("]") and ":" in raw[1:-1]):
            raise app_errors.VpnctlError("invalid bracketed IPv6 server host")
        return raw
    if ":" in raw:
        raise app_errors.VpnctlError(
            "server host must not include a port; profile ports are added to client links"
        )
    return raw


def validate_outbound_mode(mode: str | None) -> str:
    normalized = (mode or app_settings.OUTBOUND_DIRECT).strip().lower()
    if normalized not in app_settings.OUTBOUND_MODES:
        raise app_errors.VpnctlError("invalid outbound mode; use direct or proxy")
    return normalized


def validate_profile_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise app_errors.VpnctlError("profile name cannot be empty")
    if any(char.isspace() for char in normalized):
        raise app_errors.VpnctlError("profile name cannot contain whitespace")
    return normalized


def deduplicate_names(names: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        normalized = name.strip()
        if not normalized:
            raise app_errors.VpnctlError("client names cannot be empty")
        if normalized in seen:
            raise app_errors.VpnctlError(f"duplicate client name: {normalized}")
        seen.add(normalized)
        result.append(normalized)
    return result


def validate_stable_name(name: str) -> str:
    if not name or any(
        not (char.isascii() and (char.isalnum() or char in "_-")) for char in name
    ):
        raise app_errors.VpnctlError(
            "names must use ASCII letters, digits, underscores or hyphens"
        )
    return name
