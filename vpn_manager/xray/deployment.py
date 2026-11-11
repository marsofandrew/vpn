"""Configuration transactions with explicit storage and runtime dependencies."""

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from vpn_manager import accounting, files
from vpn_manager.errors import VpnctlError
from vpn_manager.ports import Json, RuntimeControl, StateStore
from vpn_manager.state import storage
from vpn_manager.xray import rendering, runtime


def journal_path(state_path: Path) -> Path:
    return state_path.with_name(state_path.name + ".deploy")


def remove_journal(state_path: Path) -> None:
    journal_path(state_path).unlink()
    files.sync_directory(state_path.parent)


@dataclass
class DeploymentService:
    store: StateStore
    runtime: RuntimeControl
    sample: Callable[[Json, Path], None]

    def persist(self, state, state_path, config_path, compose_file=None, restart=False):
        accounting.ensure_monthly_period(state)
        candidate = rendering.render_config(state)
        if restart and compose_file is not None:
            self.deploy(state, state_path, config_path, compose_file, candidate)
        else:
            self.store.save(state_path, state)
            files.write_json(
                config_path.with_name(config_path.name + ".pending"), candidate
            )

    def deploy(
        self, state, state_path, config_path, compose_file, candidate, force=False
    ):
        if accounting.ensure_monthly_period(state):
            candidate = rendering.render_config(state)
        rendering.validate_config(candidate)
        previous_config = _previous_config(config_path, force)
        if previous_config == candidate and not force:
            os.chmod(config_path, 0o600)
            self.store.save(state_path, state)
            return
        self._preflight(compose_file, config_path, candidate, previous_config)
        previous_state = self._checkpoint(state, state_path, compose_file, force)
        _write_journal(
            state_path, config_path, compose_file, previous_state, previous_config
        )
        if previous_config is not None:
            files.write_json(storage.backup_path(config_path), previous_config)
        try:
            self._install(state, state_path, config_path, compose_file, candidate)
        except Exception:
            self._rollback(state_path, config_path, compose_file)

    def _preflight(self, compose_file, config_path, candidate, previous_config):
        self.runtime.check_mount(compose_file, config_path)
        if previous_config is not None:
            os.chmod(config_path, 0o600)
        candidate_path = config_path.with_name(config_path.name + ".candidate")
        files.write_json(candidate_path, candidate)
        try:
            self.runtime.validate(compose_file, candidate_path)
        finally:
            candidate_path.unlink(missing_ok=True)

    def _checkpoint(self, state, state_path, compose_file, force):
        previous_state = self.store.load(state_path)
        accounting.ensure_monthly_period(previous_state)
        if self.runtime.running(compose_file):
            try:
                self.sample(previous_state, compose_file)
            except (VpnctlError, OSError, ValueError, subprocess.SubprocessError):
                if not force:
                    raise
                print(
                    "Xray statistics unavailable; explicit recovery may lose unobserved traffic.",
                    file=sys.stderr,
                )
            else:
                self.store.save(state_path, previous_state)
                checkpoint = previous_state["accounting"]
                accounting.apply_usage_snapshot(
                    state, checkpoint["checkpoints"], checkpoint["epoch"]
                )
        return previous_state

    def _install(self, state, state_path, config_path, compose_file, candidate):
        files.write_json(config_path, candidate)
        self.runtime.restart(compose_file, state)
        self.runtime.verify(compose_file, candidate)
        self.store.save(state_path, state)
        remove_journal(state_path)

    def _rollback(self, state_path, config_path, compose_file):
        try:
            self.recover(state_path, config_path, compose_file)
        except Exception:
            raise VpnctlError(
                "Deployment and rollback failed; journal retained. Run restart to retry recovery."
            ) from None
        raise VpnctlError(
            "Deployment failed; previous configuration and state restored."
        ) from None

    def recover(self, state_path, config_path, compose_file):
        journal = files.load_json(journal_path(state_path))
        _validate_recovery_paths(journal, config_path, compose_file)
        self.runtime.check_mount(compose_file, config_path)
        if journal["config"] is None:
            self.runtime.stop(compose_file)
            config_path.unlink(missing_ok=True)
        else:
            files.write_json(config_path, journal["config"])
            self.runtime.restart(compose_file)
            self.runtime.verify(compose_file, journal["config"])
        files.write_json(state_path, journal["state"])
        files.write_json(storage.backup_path(state_path), journal["state"])
        remove_journal(state_path)


def _previous_config(config_path, force):
    try:
        return files.load_json(config_path) if config_path.exists() else None
    except (ValueError, OSError):
        if not force:
            raise
        backup = storage.backup_path(config_path)
        return files.load_json(backup) if backup.exists() else None


def _validate_recovery_paths(journal, config_path, compose_file):
    for field, path in (("config_path", config_path), ("compose_file", compose_file)):
        resolved = str(path.resolve())
        if journal.get(field, resolved) != resolved:
            raise VpnctlError(
                "Recovery requires the original --config and --compose-file paths"
            )


def _write_journal(state_path, config_path, compose_file, state, config):
    files.write_json(
        journal_path(state_path),
        {
            "state": state,
            "config": config,
            "config_path": str(config_path.resolve()),
            "compose_file": str(compose_file.resolve()),
        },
    )


def default_service():
    return DeploymentService(
        storage.JsonStateStore(), runtime.ComposeRuntime(), accounting.sample_usage
    )


def deploy_config(state, state_path, config_path, compose_file, candidate, force=False):
    default_service().deploy(
        state, state_path, config_path, compose_file, candidate, force
    )


def recover_deployment(state_path, config_path, compose_file):
    default_service().recover(state_path, config_path, compose_file)


def persist_state_and_config(
    state, state_path, config_path, compose_file=None, restart=False
):
    default_service().persist(state, state_path, config_path, compose_file, restart)
