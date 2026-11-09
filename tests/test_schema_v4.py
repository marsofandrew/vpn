import copy
import tempfile
import unittest
from pathlib import Path

import vpnctl


class SchemaV4Tests(unittest.TestCase):
    def legacy(self):
        state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], 5000)
        state["version"] = 3
        state.pop("node")
        state.pop("upstreams")
        state.pop("routing_policies")
        state["upstream"] = None
        for profile in state["profiles"]:
            profile.pop("route")
            profile.pop("transport")
        state["accounting"] = {"epoch": "old", "checkpoints": {"phone@example.com": {"uplink": 12}}}
        state["profiles"][0]["clients"][0]["used_uplink_bytes"] = 12
        return state

    def test_migration_preserves_identity_quota_usage_and_checkpoint(self):
        legacy = self.legacy()
        previous = copy.deepcopy(legacy)
        migrated = vpnctl.migrate_legacy_state(legacy)
        self.assertEqual(migrated["version"], 4)
        self.assertEqual(migrated["accounting"], previous["accounting"])
        for field in ("keys", "short_id", "port", "clients", "reality_target"):
            self.assertEqual(migrated["profiles"][0][field], previous["profiles"][0][field])
        self.assertEqual(migrated["profiles"][0]["route"], "direct")

    def test_original_v3_backup_is_retained_before_first_v4_save(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            legacy = self.legacy()
            vpnctl.write_json(path, legacy)
            migrated = vpnctl.load_state(path)
            vpnctl.save_state(path, migrated)
            vpnctl.save_state(path, migrated)
            self.assertEqual(vpnctl.load_json(path.with_name("state.json.v3.bak")), legacy)

    def test_unknown_version_is_rejected(self):
        legacy = self.legacy()
        legacy["version"] = 99
        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.migrate_legacy_state(legacy)

    def test_xhttp_profile_import_and_export_preserve_transport(self):
        state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
        profile = state["profiles"][0]
        profile["transport"] = {"type": "xhttp", "settings": {"path": "/entry", "host": "entry.example.com", "mode": "stream-one"}}
        rendered = vpnctl.render_config(state)
        imported = vpnctl.import_state_from_xray_config(rendered, state["server_host"])
        self.assertEqual(imported["profiles"][0]["transport"], profile["transport"])
        self.assertIn("type=xhttp", vpnctl.generate_vless_link(profile["clients"][0], state, profile))
        self.assertEqual(vpnctl.render_config(imported), rendered)

    def test_import_rejects_unknown_route_instead_of_exiting_locally(self):
        state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
        config = vpnctl.render_config(state)
        config["routing"]["rules"][1]["outboundTag"] = "unrepresentable"
        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.import_state_from_xray_config(config, "vpn.example.com")

    def test_named_upstreams_cli_route_and_disable_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            config = Path(directory) / "config.json"
            state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
            vpnctl.save_state(path, state)
            common = ["--state", str(path), "--config", str(config)]
            public_key = vpnctl.generate_reality_keys()["public_key"]
            link = (f"vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
                    f"?security=reality&type=tcp&pbk={public_key}&sni=example.com&sid=abc123")
            self.assertEqual(vpnctl.main(common + ["upstream", "add", "ny-direct", "--link", link, "--no-restart"]), 0)
            self.assertEqual(vpnctl.main(common + ["route", "set", "default", "--policy", "ny-direct", "--no-restart"]), 0)
            self.assertNotEqual(vpnctl.main(common + ["upstream", "disable", "ny-direct", "--no-restart"]), 0)
            self.assertNotEqual(vpnctl.main(common + ["upstream", "remove", "ny-direct", "--no-restart"]), 0)
            loaded = vpnctl.load_state(path)
            self.assertEqual(vpnctl.render_config(loaded)["routing"]["rules"][1]["outboundTag"], "ny-direct")
