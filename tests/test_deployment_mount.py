import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_manager import accounting as app_accounting
from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import deployment as app_xray_deployment
from vpn_manager.xray import rendering as app_xray_rendering
from vpn_manager.xray import runtime as app_xray_runtime


class DeploymentMountTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.compose = self.root / "compose.json"
        self.config = self.root / "config.json"
        self.state_path = self.root / "state.json"
        self.mount = {
            "type": "bind",
            "source": str(self.config),
            "target": "/etc/xray/config.json",
            "read_only": True,
        }

    def manifest(self, volumes):
        return {"services": {"xray": {"volumes": volumes}}}

    def validate(self, manifest):
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(manifest))
        with patch.object(
            app_xray_runtime, "run_compose", return_value=result
        ) as compose:
            app_xray_runtime.validate_config_mount(self.compose, self.config)
        compose.assert_called_once_with(
            self.compose, ["config", "--format", "json"], capture=True
        )

    def test_matching_absolute_relative_and_symlink_sources(self):
        self.validate(self.manifest([self.mount]))
        self.validate(self.manifest([dict(self.mount, source="config.json")]))
        alias = self.root / "config-alias.json"
        alias.symlink_to(self.config)
        self.validate(self.manifest([dict(self.mount, source=str(alias))]))

    def test_wrong_missing_named_duplicate_or_writable_mount_is_rejected(self):
        invalid = [
            self.manifest([]),
            self.manifest([dict(self.mount, source=str(self.root / "other.json"))]),
            self.manifest([dict(self.mount, target="/etc/xray/other.json")]),
            self.manifest([dict(self.mount, type="volume")]),
            self.manifest([dict(self.mount, source="")]),
            self.manifest([dict(self.mount, read_only=False)]),
            self.manifest([self.mount, self.mount]),
            self.manifest(["unresolved:volume:ro"]),
            {"services": {}},
            {"services": []},
        ]
        for manifest in invalid:
            with (
                self.subTest(manifest=manifest),
                self.assertRaises(app_errors.VpnctlError),
            ):
                self.validate(manifest)

    def test_mount_mismatch_does_not_install_sample_or_change_files(self):
        state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        app_state_storage.save_state(self.state_path, state)
        app_files.write_json(self.config, app_xray_rendering.render_config(state))
        before = {
            path: path.read_bytes() for path in self.root.iterdir() if path.is_file()
        }
        state["profiles"][0]["clients"][0]["enabled"] = False
        manifest = self.manifest(
            [dict(self.mount, source=str(self.root / "old-config.json"))]
        )
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(manifest))
        with (
            patch.object(app_xray_runtime, "run_compose", return_value=result),
            patch.object(app_accounting, "sample_usage") as sample,
            patch.object(app_xray_runtime, "validate_native") as native,
            patch.object(app_xray_runtime, "restart_xray") as restart,
        ):
            with self.assertRaises(app_errors.VpnctlError):
                app_xray_deployment.deploy_config(
                    state,
                    self.state_path,
                    self.config,
                    self.compose,
                    app_xray_rendering.render_config(state),
                )
            sample.assert_not_called()
            native.assert_not_called()
            restart.assert_not_called()
        self.assertEqual(
            before,
            {path: path.read_bytes() for path in self.root.iterdir() if path.is_file()},
        )

    def test_invalid_compose_json_has_a_safe_error(self):
        result = subprocess.CompletedProcess(
            [], 0, stdout="private credentials, not JSON"
        )
        with patch.object(app_xray_runtime, "run_compose", return_value=result):
            with self.assertRaises(app_errors.VpnctlError) as failure:
                app_xray_runtime.validate_config_mount(self.compose, self.config)
        self.assertNotIn("private credentials", str(failure.exception))

    def test_recovery_mount_mismatch_preserves_the_journal_and_files(self):
        state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        app_state_storage.save_state(self.state_path, state)
        config = app_xray_rendering.render_config(state)
        app_files.write_json(self.config, config)
        app_files.write_json(
            app_xray_deployment.journal_path(self.state_path),
            {"state": state, "config": config},
        )
        before = {path: path.read_bytes() for path in self.root.iterdir()}
        result = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(self.manifest([]))
        )
        with (
            patch.object(app_xray_runtime, "run_compose", return_value=result),
            patch.object(app_xray_runtime, "restart_xray") as restart,
        ):
            with self.assertRaises(app_errors.VpnctlError):
                app_xray_deployment.recover_deployment(
                    self.state_path, self.config, self.compose
                )
            restart.assert_not_called()
        self.assertEqual(
            before, {path: path.read_bytes() for path in self.root.iterdir()}
        )
