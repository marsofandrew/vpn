import copy
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager import values as app_values
from vpn_manager.cli import entrypoint as app_cli_entrypoint
from vpn_manager.cli import exports as app_cli_exports
from vpn_manager.cli import parser as app_cli_parser
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import storage as app_state_storage
from vpn_manager.state import validation as app_state_validation


class StabilizationValidationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state_path = self.root / "state.json"
        self.config_path = self.root / "config.json"
        self.compose = self.root / "compose.yaml"
        self.state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        app_state_storage.save_state(self.state_path, self.state)

    def test_missing_v4_section_rejects_without_restoring_backup(self):
        app_files.write_json(app_state_storage.backup_path(self.state_path), self.state)
        malformed = copy.deepcopy(self.state)
        malformed.pop("node")
        app_files.write_json(self.state_path, malformed)
        primary = self.state_path.read_bytes()
        backup = app_state_storage.backup_path(self.state_path).read_bytes()
        errors = StringIO()
        with redirect_stderr(errors):
            result = app_cli_entrypoint.main(
                ["--state", str(self.state_path), "profile", "list"]
            )
        self.assertEqual(result, 1)
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(self.state_path.read_bytes(), primary)
        self.assertEqual(
            app_state_storage.backup_path(self.state_path).read_bytes(), backup
        )

    def test_malformed_legacy_state_is_rejected_without_backup_recovery(self):
        for malformed in (
            {"version": 3, "profiles": [None]},
            {"version": 2, "profiles": "private-value"},
        ):
            with self.subTest(version=malformed["version"]):
                app_files.write_json(self.state_path, malformed)
                app_files.write_json(
                    app_state_storage.backup_path(self.state_path), self.state
                )
                previous = self.state_path.read_bytes()
                with self.assertRaises(app_errors.VpnctlError) as failure:
                    app_state_storage.load_state(self.state_path)
                self.assertNotIn("private-value", str(failure.exception))
                self.assertEqual(self.state_path.read_bytes(), previous)
                self.assertFalse(
                    self.state_path.with_name("state.json.v3.bak").exists()
                )

    def test_validation_errors_do_not_echo_authentication_values(self):
        duplicate = copy.deepcopy(self.state)
        original = duplicate["profiles"][0]["clients"][0]
        second = copy.deepcopy(original)
        second.update(name="other", email="other@example.com")
        duplicate["profiles"][0]["clients"].append(second)
        with self.assertRaises(app_errors.VpnctlError) as failure:
            app_state_validation.validate_state(duplicate)
        self.assertNotIn(original["id"], str(failure.exception))
        with self.assertRaises(app_errors.VpnctlError) as failure:
            app_values.validate_outbound_mode(
                "vless://secret-authentication@example.com"
            )
        self.assertNotIn("secret-authentication", str(failure.exception))

    def test_invalid_xhttp_link_data_has_a_controlled_error(self):
        profile = self.state["profiles"][0]
        profile["transport"] = {
            "type": "xhttp",
            "settings": {"path": "/", "mode": "stream-one"},
        }
        profile["clients"][0]["id"] = "private-invalid-identity"
        with self.assertRaises(app_errors.VpnctlError) as failure:
            app_exports_links.generate_vless_link(
                profile["clients"][0], self.state, profile
            )
        self.assertNotIn("private-invalid-identity", str(failure.exception))

    def test_subscription_cannot_replace_runtime_artifacts_or_symlinks(self):
        paths = app_cli_exports.protected_runtime_paths(
            self.state_path, self.config_path, self.compose
        )
        for index, target in enumerate(sorted(paths)):
            with self.subTest(target=target.name):
                if target != self.state_path.resolve():
                    target.write_bytes(b"original-private-artifact")
                previous = target.read_bytes()
                for output in (target, self.root / f"alias-{index}"):
                    if output != target:
                        output.symlink_to(target)
                    args = app_cli_parser.build_parser().parse_args(
                        [
                            "--state",
                            str(self.state_path),
                            "--config",
                            str(self.config_path),
                            "--compose-file",
                            str(self.compose),
                            "subscription",
                            "phone",
                            "--output",
                            str(output),
                        ]
                    )
                    with self.assertRaisesRegex(
                        app_errors.VpnctlError, "cannot overwrite"
                    ):
                        app_cli_exports.command_subscription(args)
                    self.assertEqual(target.read_bytes(), previous)

    def test_invalid_v3_backup_is_not_archived_during_recovery(self):
        self.state_path.write_text("{interrupted", encoding="utf-8")
        app_files.write_json(
            app_state_storage.backup_path(self.state_path),
            {"version": 3, "profiles": [None]},
        )
        with self.assertRaises(app_errors.VpnctlError):
            app_state_storage.load_state(self.state_path)
        self.assertFalse(self.state_path.with_name("state.json.v3.bak").exists())
        self.assertEqual(self.state_path.read_text(), "{interrupted")
