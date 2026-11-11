import copy
import fcntl
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager.state import migration as app_state_migration
from vpn_manager.state import validation as app_state_validation


@contextmanager
def state_lock(path: Path):
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def backup_path(path: Path) -> Path:
    return path.with_name(path.name + ".bak")


def load_state(path: Path) -> dict[str, Any]:
    backup = backup_path(path)
    if path.exists() or backup.exists():
        try:
            raw = app_files.load_json(path)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            previous = app_files.load_json(backup)
            state = app_state_migration.migrate_legacy_state(copy.deepcopy(previous))
            if previous.get("version") == 3:
                original = path.with_name(path.name + ".v3.bak")
                if not original.exists():
                    app_files.write_json(original, previous)
            app_files.write_json(path, state)
            print("Recovered state from validated backup.", file=sys.stderr)
            return state
        state = app_state_migration.migrate_legacy_state(raw)
        os.chmod(path, 0o600)
        return state
    if not path.exists():
        legacy_path = Path("vpn_config.json")
        if legacy_path.exists():
            return app_state_migration.migrate_legacy_state(
                app_files.load_json(legacy_path)
            )
        raise app_errors.VpnctlError(f"state file not found: {path}")
    return app_state_migration.migrate_legacy_state(app_files.load_json(path))


def save_state(path: Path, state: dict[str, Any]) -> None:
    app_state_validation.validate_state(state)
    state["updated_at"] = app_clock.utc_now()
    if path.exists():
        previous_raw = app_files.load_json(path)
        previous = app_state_migration.migrate_legacy_state(copy.deepcopy(previous_raw))
        if previous_raw.get("version") == 3:
            original = path.with_name(path.name + ".v3.bak")
            if not original.exists():
                app_files.write_json(original, previous_raw)
        app_files.write_json(backup_path(path), previous)
    app_files.write_json(path, state)


class JsonStateStore:
    def load(self, path: Path) -> dict[str, Any]:
        return load_state(path)

    def save(self, path: Path, state: dict[str, Any]) -> None:
        save_state(path, state)
