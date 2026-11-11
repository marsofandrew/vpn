"""Credential-free infrastructure metadata, independent of VPN runtime state."""

import ipaddress
import re

INVENTORY_VERSION = 1
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_SECRET_FIELDS = {
    "auth",
    "authorization",
    "apikey",
    "credentials",
    "key",
    "keys",
    "password",
    "passwd",
    "passphrase",
    "privatekey",
    "psk",
    "secret",
    "token",
    "uuid",
    "username",
    "userinfo",
}


class InventoryError(ValueError):
    """Invalid inventory metadata; messages never include supplied values."""


def _reject_secret_fields(value: object) -> None:
    pending: list[tuple[object, frozenset[int]]] = [(value, frozenset())]
    while pending:
        item, ancestors = pending.pop()
        if not isinstance(item, (dict, list)):
            continue
        if id(item) in ancestors:
            raise InventoryError("inventory must not contain cyclic containers")
        ancestors = ancestors | {id(item)}
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise InventoryError("inventory field names must be strings")
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                if (
                    normalized in _SECRET_FIELDS
                    or normalized.endswith("uuid")
                    or any(
                        part in normalized
                        for part in (
                            "password",
                            "privatekey",
                            "secret",
                            "token",
                            "credential",
                        )
                    )
                ):
                    raise InventoryError("inventory must not contain secret fields")
                pending.append((child, ancestors))
        else:
            pending.extend((child, ancestors) for child in item)


def _object(value: object, required: set[str], optional: set[str], path: str) -> None:
    if not isinstance(value, dict):
        raise InventoryError(f"{path} must be an object")
    if not required <= value.keys():
        raise InventoryError(f"{path} is missing required fields")
    if value.keys() - required - optional:
        raise InventoryError(f"{path} contains unsupported fields")


def _identifier(value: object, path: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise InventoryError(f"{path} must be a 1-64 character lowercase identifier")


def _host(value: object, path: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise InventoryError(f"{path} must be a hostname or bare IP address")
    if any(char in value for char in "%/@:?#[]") or any(
        char.isspace() for char in value
    ):
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            raise InventoryError(
                f"{path} must be a hostname or bare IP address"
            ) from None
        if "%" in value:
            raise InventoryError(f"{path} must not contain an IPv6 zone ID")
        return
    try:
        ipaddress.IPv4Address(value)
        return
    except ValueError:
        pass
    labels = value.removesuffix(".").split(".")
    if all(char in "0123456789." for char in value) or any(
        _DNS_LABEL.fullmatch(label) is None for label in labels
    ):
        raise InventoryError(f"{path} must be a hostname or bare IP address")


def validate_inventory(inventory: dict) -> None:
    """Validate version-1 metadata without mutating it or contacting any host.

    Raise InventoryError (a ValueError) for invalid input. Unknown fields and
    credential fields at any depth are forbidden. Hosts are optional in either
    mode; the public/outbound declaration does not verify actual reachability.
    """
    _reject_secret_fields(inventory)
    _object(inventory, {"version", "nodes"}, set(), "inventory")
    if (
        type(inventory["version"]) is not int
        or inventory["version"] != INVENTORY_VERSION
    ):
        raise InventoryError("inventory.version must be integer 1")
    if not isinstance(inventory["nodes"], list):
        raise InventoryError("inventory.nodes must be an array")

    seen = set()
    for index, node in enumerate(inventory["nodes"]):
        path = f"inventory.nodes[{index}]"
        _object(node, {"id", "role", "connectivity"}, {"country", "transports"}, path)
        _identifier(node["id"], f"{path}.id")
        if node["id"] in seen:
            raise InventoryError(f"{path}.id must be unique")
        seen.add(node["id"])
        if not isinstance(node["role"], str) or node["role"] not in {
            "gateway",
            "exit",
            "both",
        }:
            raise InventoryError(f"{path}.role must be gateway, exit or both")
        if "country" in node:
            country = node["country"]
            if (
                not isinstance(country, str)
                or re.fullmatch(r"[A-Z]{2}", country) is None
            ):
                raise InventoryError(
                    f"{path}.country must be two uppercase ASCII letters"
                )
        connectivity = node["connectivity"]
        _object(connectivity, {"mode"}, {"host"}, f"{path}.connectivity")
        mode = connectivity["mode"]
        if not isinstance(mode, str) or mode not in {"public", "outbound"}:
            raise InventoryError(f"{path}.connectivity.mode must be public or outbound")
        if "host" in connectivity:
            _host(connectivity["host"], f"{path}.connectivity.host")
        if "transports" in node:
            transports = node["transports"]
            if not isinstance(transports, list):
                raise InventoryError(f"{path}.transports must be an array")
            for transport in transports:
                _identifier(transport, f"{path}.transports entry")
            if len(set(transports)) != len(transports):
                raise InventoryError(f"{path}.transports entries must be unique")


def validate_node_references(inventory: dict, node_ids: list[str]) -> None:
    """Validate external node IDs separately; repeated references are allowed."""
    validate_inventory(inventory)
    if not isinstance(node_ids, list):
        raise InventoryError("node references must be an array")
    known = {node["id"] for node in inventory["nodes"]}
    for index, node_id in enumerate(node_ids):
        _identifier(node_id, f"node references[{index}]")
        if node_id not in known:
            raise InventoryError(
                f"node references[{index}] does not identify an inventory node"
            )


def summary_nodes(inventory: dict) -> list[dict]:
    """Return fresh, allowlisted display rows in inventory order after validation."""
    validate_inventory(inventory)
    return [
        {
            "id": node["id"],
            "role": node["role"],
            "country": node.get("country"),
            "mode": node["connectivity"]["mode"],
            "host": node["connectivity"].get("host"),
            "transports": list(node.get("transports", [])),
        }
        for node in inventory["nodes"]
    ]


def example_inventory() -> dict:
    """Return a fresh, illustrative four-node inventory with no credentials."""
    return {
        "version": INVENTORY_VERSION,
        "nodes": [
            {
                "id": "ru-vps",
                "role": "gateway",
                "country": "RU",
                "connectivity": {"mode": "public", "host": "ru-vps.example.com"},
                "transports": ["vless-reality"],
            },
            {
                "id": "ru-home",
                "role": "gateway",
                "country": "RU",
                "connectivity": {"mode": "outbound"},
                "transports": [],
            },
            {
                "id": "ny-vps",
                "role": "both",
                "country": "US",
                "connectivity": {"mode": "public", "host": "ny-vps.example.com"},
                "transports": ["vless-reality"],
            },
            {
                "id": "pt-home",
                "role": "exit",
                "country": "PT",
                "connectivity": {"mode": "outbound"},
                "transports": [],
            },
        ],
    }
