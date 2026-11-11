import json
import os
import tempfile
from pathlib import Path
from typing import Any

from vpn_manager import errors as app_errors


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise app_errors.VpnctlError("JSON root must be an object")
    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    atomic_write(path, (json.dumps(data, indent=2) + "\n").encode("utf-8"))


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "wb")
        descriptor = None
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
