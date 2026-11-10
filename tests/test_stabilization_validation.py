import copy
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import tempfile
import unittest

import vpnctl


class StabilizationValidationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state_path = self.root / "state.json"
        self.config_path = self.root / "config.json"
        self.compose = self.root / "compose.yaml"
        self.state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
        vpnctl.save_state(self.state_path, self.state)

    def test_missing_v4_section_rejects_without_restoring_backup(self):
        vpnctl.write_json(vpnctl.backup_path(self.state_path), self.state)
        malformed = copy.deepcopy(self.state)
        malformed.pop("node")
        vpnctl.write_json(self.state_path, malformed)
        primary = self.state_path.read_bytes()
        backup = vpnctl.backup_path(self.state_path).read_bytes()
        errors = StringIO()
        with redirect_stderr(errors):
            result = vpnctl.main(["--state", str(self.state_path), "profile", "list"])
        self.assertEqual(result, 1)
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(self.state_path.read_bytes(), primary)
        self.assertEqual(vpnctl.backup_path(self.state_path).read_bytes(), backup)

    def test_malformed_legacy_state_is_rejected_without_backup_recovery(self):
        for malformed in ({"version": 3, "profiles": [None]}, {"version": 2, "profiles": "private-value"}):
            with self.subTest(version=malformed["version"]):
                vpnctl.write_json(self.state_path, malformed)
                vpnctl.write_json(vpnctl.backup_path(self.state_path), self.state)
                previous = self.state_path.read_bytes()
                with self.assertRaises(vpnctl.VpnctlError) as failure:
                    vpnctl.load_state(self.state_path)
                self.assertNotIn("private-value", str(failure.exception))
                self.assertEqual(self.state_path.read_bytes(), previous)
                self.assertFalse(self.state_path.with_name("state.json.v3.bak").exists())

    def test_validation_errors_do_not_echo_authentication_values(self):
        duplicate = copy.deepcopy(self.state)
        original = duplicate["profiles"][0]["clients"][0]
        second = copy.deepcopy(original)
        second.update(name="other", email="other@example.com")
        duplicate["profiles"][0]["clients"].append(second)
        with self.assertRaises(vpnctl.VpnctlError) as failure:
            vpnctl.validate_state(duplicate)
        self.assertNotIn(original["id"], str(failure.exception))
        with self.assertRaises(vpnctl.VpnctlError) as failure:
            vpnctl.validate_outbound_mode("vless://secret-authentication@example.com")
        self.assertNotIn("secret-authentication", str(failure.exception))

    def test_subscription_cannot_replace_runtime_artifacts_or_symlinks(self):
        paths = vpnctl.protected_runtime_paths(self.state_path, self.config_path, self.compose)
        for index, target in enumerate(sorted(paths)):
            with self.subTest(target=target.name):
                if target != self.state_path.resolve():
                    target.write_bytes(b"original-private-artifact")
                previous = target.read_bytes()
                for output in (target, self.root / f"alias-{index}"):
                    if output != target:
                        output.symlink_to(target)
                    args = vpnctl.build_parser().parse_args([
                        "--state", str(self.state_path), "--config", str(self.config_path),
                        "--compose-file", str(self.compose), "subscription", "phone", "--output", str(output),
                    ])
                    with self.assertRaisesRegex(vpnctl.VpnctlError, "cannot overwrite"):
                        vpnctl.command_subscription(args)
                    self.assertEqual(target.read_bytes(), previous)

    def test_invalid_v3_backup_is_not_archived_during_recovery(self):
        self.state_path.write_text("{interrupted", encoding="utf-8")
        vpnctl.write_json(vpnctl.backup_path(self.state_path), {"version": 3, "profiles": [None]})
        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.load_state(self.state_path)
        self.assertFalse(self.state_path.with_name("state.json.v3.bak").exists())
        self.assertEqual(self.state_path.read_text(), "{interrupted")

