"""Standalone subscription artifacts; no runtime control or HTTP hosting.

Client entries hold credentials and must be stored privately by the caller.
This module neither discovers local links nor checks runtime client registries.
"""

import base64
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import unquote, urlsplit

import vpn_transports


def _name(name: str) -> None:
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_-]+", name) is None:
        raise ValueError(
            "endpoint name must use nonempty ASCII letters, digits, underscores or hyphens"
        )


def _client(client: str) -> None:
    if (
        not isinstance(client, str)
        or not client.strip()
        or any(
            ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF
            for char in client
        )
    ):
        raise ValueError("client must be a nonempty string without control characters")


def _entries(state: dict) -> dict:
    if not isinstance(state, dict):
        raise ValueError("state must be an object")
    entries = state.get("client_entries", {})
    if not isinstance(entries, dict):
        raise ValueError("client_entries must be an object")
    return entries


def add_endpoint(state: dict, name: str, client: str, link: str) -> None:
    """Add name: {client, endpoint}, parsing before any mutation.

    Names are case-sensitive ASCII identifiers and are never normalized.
    Duplicate names are rejected across all clients. The client is an exact
    ownership label; the endpoint's authentication UUID comes from the link.
    """
    _name(name)
    _client(client)
    entries = _entries(state)
    if name in entries:
        raise ValueError("endpoint name already exists")
    endpoint = vpn_transports.parse_link(link)
    state.setdefault("client_entries", {})[name] = {
        "client": client,
        "endpoint": endpoint,
    }


def remove_endpoint(state: dict, name: str) -> None:
    """Remove exactly one named entry; missing names raise without mutation."""
    _name(name)
    entries = _entries(state)
    if name not in entries:
        raise ValueError("endpoint name does not exist")
    del entries[name]


def subscription_text(state: dict, client: str, local_links=()) -> str:
    """Return standard base64 of newline-separated canonical VLESS URLs.

    Explicit local URLs appear first in supplied order, retaining their labels.
    local_links must be a list or tuple, not a string or an implicit source.
    Matching enabled entries follow in name order, with endpoint names as labels.
    Disabled endpoints are validated but omitted; other clients' endpoints are
    not inspected. No state is mutated. Empty subscriptions are rejected.
    """
    _client(client)
    entries = _entries(state)
    if not isinstance(local_links, (list, tuple)):
        raise ValueError("local_links must be a list or tuple of explicit URLs")
    links = []
    for link in local_links:
        endpoint = vpn_transports.parse_link(link)
        label = unquote(urlsplit(link).fragment, errors="strict")
        links.append(vpn_transports.export_link(endpoint, label))
    for name in entries:
        _name(name)
    for name in sorted(entries):
        entry = entries[name]
        if not isinstance(entry, dict) or set(entry) != {"client", "endpoint"}:
            raise ValueError("client entry must contain only client and endpoint")
        _client(entry["client"])
        if entry["client"] != client:
            continue
        endpoint = entry["endpoint"]
        vpn_transports.validate_upstream(endpoint)
        if endpoint.get("enabled", True):
            links.append(vpn_transports.export_link(endpoint, name))
    if not links:
        raise ValueError(
            "subscription must contain at least one enabled endpoint or local link"
        )
    return base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")


def private_write(path, content: str) -> None:
    """Atomically publish UTF-8 text with mode 0600 and no backup artifacts.

    Write, flush and fsync a same-directory temporary file before replacement,
    then fsync the parent directory. Failures before replacement preserve the
    old destination. A directory-fsync failure after replacement propagates;
    the new file is already visible, but crash durability is then uncertain.
    """
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    encoded = content.encode("utf-8")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "wb")
        descriptor = None
        with handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
