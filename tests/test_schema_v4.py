import copy
import tempfile
import unittest
from pathlib import Path

from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager import keys as app_keys
from vpn_manager.cli import entrypoint as app_cli_entrypoint
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import importing as app_state_importing
from vpn_manager.state import migration as app_state_migration
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import rendering as app_xray_rendering


class SchemaV4Tests(unittest.TestCase):
    def legacy(self):
        state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], 5000
        )
        state["version"] = 3
        state.pop("node")
        state.pop("upstreams")
        state.pop("routing_policies")
        state["upstream"] = None
        for profile in state["profiles"]:
            profile.pop("route")
            profile.pop("transport")
        state["accounting"] = {
            "epoch": "old",
            "checkpoints": {"phone@example.com": {"uplink": 12}},
        }
        state["profiles"][0]["clients"][0]["used_uplink_bytes"] = 12
        return state

    def test_migration_preserves_identity_quota_usage_and_checkpoint(self):
        legacy = self.legacy()
        previous = copy.deepcopy(legacy)
        migrated = app_state_migration.migrate_legacy_state(legacy)
        self.assertEqual(migrated["version"], 4)
        self.assertEqual(migrated["accounting"], previous["accounting"])
        for field in ("keys", "short_id", "port", "clients", "reality_target"):
            self.assertEqual(
                migrated["profiles"][0][field], previous["profiles"][0][field]
            )
        self.assertEqual(migrated["profiles"][0]["route"], "direct")

    def test_original_v3_backup_is_retained_before_first_v4_save(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            legacy = self.legacy()
            app_files.write_json(path, legacy)
            migrated = app_state_storage.load_state(path)
            app_state_storage.save_state(path, migrated)
            app_state_storage.save_state(path, migrated)
            self.assertEqual(
                app_files.load_json(path.with_name("state.json.v3.bak")), legacy
            )

    def test_unknown_version_is_rejected(self):
        legacy = self.legacy()
        legacy["version"] = 99
        with self.assertRaises(app_errors.VpnctlError):
            app_state_migration.migrate_legacy_state(legacy)

    def test_unsupported_primary_is_not_replaced_by_an_older_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            previous = self.legacy()
            app_files.write_json(app_state_storage.backup_path(path), previous)
            unsupported = copy.deepcopy(previous)
            unsupported["version"] = 99
            app_files.write_json(path, unsupported)
            with self.assertRaises(app_errors.VpnctlError):
                app_state_storage.load_state(path)
            self.assertEqual(app_files.load_json(path), unsupported)

    def test_xhttp_profile_import_and_export_preserve_transport(self):
        state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        profile = state["profiles"][0]
        profile["transport"] = {
            "type": "xhttp",
            "settings": {
                "path": "/entry",
                "host": "entry.example.com",
                "mode": "stream-one",
            },
        }
        rendered = app_xray_rendering.render_config(state)
        imported = app_state_importing.import_state_from_xray_config(
            rendered, state["server_host"]
        )
        self.assertEqual(imported["profiles"][0]["transport"], profile["transport"])
        self.assertIn(
            "type=xhttp",
            app_exports_links.generate_vless_link(
                profile["clients"][0], state, profile
            ),
        )
        self.assertEqual(app_xray_rendering.render_config(imported), rendered)

    def test_import_rejects_unknown_route_instead_of_exiting_locally(self):
        state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        config = app_xray_rendering.render_config(state)
        config["routing"]["rules"][1]["outboundTag"] = "unrepresentable"
        with self.assertRaises(app_errors.VpnctlError):
            app_state_importing.import_state_from_xray_config(config, "vpn.example.com")

    def test_named_upstreams_cli_route_and_disable_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            config = Path(directory) / "config.json"
            state = app_state_creation.create_state(
                "vpn.example.com",
                "example.com:443",
                "example.com",
                8443,
                ["phone"],
                None,
            )
            app_state_storage.save_state(path, state)
            common = ["--state", str(path), "--config", str(config)]
            public_key = app_keys.generate_reality_keys()["public_key"]
            link = (
                f"vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
                f"?security=reality&type=tcp&pbk={public_key}&sni=example.com&sid=abc123"
            )
            self.assertEqual(
                app_cli_entrypoint.main(
                    common
                    + ["upstream", "add", "ny-direct", "--link", link, "--no-restart"]
                ),
                0,
            )
            self.assertEqual(
                app_cli_entrypoint.main(
                    common
                    + [
                        "route",
                        "set",
                        "default",
                        "--policy",
                        "ny-direct",
                        "--no-restart",
                    ]
                ),
                0,
            )
            self.assertNotEqual(
                app_cli_entrypoint.main(
                    common + ["upstream", "disable", "ny-direct", "--no-restart"]
                ),
                0,
            )
            self.assertNotEqual(
                app_cli_entrypoint.main(
                    common + ["upstream", "remove", "ny-direct", "--no-restart"]
                ),
                0,
            )
            loaded = app_state_storage.load_state(path)
            self.assertEqual(
                app_xray_rendering.render_config(loaded)["routing"]["rules"][1][
                    "outboundTag"
                ],
                "ny-direct",
            )
