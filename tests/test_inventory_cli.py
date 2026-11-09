from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

import vpnctl


class InventoryCliTests(unittest.TestCase):
    def test_inventory_creation_is_independent_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "inventory.json"
            state = root / "absent-state.json"
            common = ["--state", str(state)]
            with redirect_stdout(StringIO()):
                self.assertEqual(vpnctl.main(common + ["inventory", "example", "--file", str(inventory)]), 0)
                self.assertEqual(vpnctl.main(common + ["inventory", "validate", "--file", str(inventory)]), 0)
            self.assertFalse(state.exists())
            previous = inventory.read_bytes()
            self.assertNotEqual(vpnctl.main(common + ["inventory", "example", "--file", str(inventory)]), 0)
            self.assertEqual(inventory.read_bytes(), previous)
            rows = vpnctl.vpn_inventory.summary_nodes(vpnctl.load_json(inventory))
            self.assertEqual(next(row["role"] for row in rows if row["id"] == "ru-home"), "gateway")

    def test_binding_uses_exit_nodes_and_preserves_runtime_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            inventory = root / "inventory.json"
            state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
            state["node"] = {"id": "ru-vps", "role": "gateway"}
            state["upstreams"]["ny"] = vpnctl.vpn_transports.parse_link(
                "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443"
                "?security=tls&type=xhttp&sni=cdn.example.com")
            vpnctl.save_state(state_path, state)
            vpnctl.write_json(inventory, vpnctl.vpn_inventory.example_inventory())
            common = ["--state", str(state_path)]
            with redirect_stdout(StringIO()):
                self.assertEqual(vpnctl.main(common + ["upstream", "bind", "ny", "--node", "ny-vps", "--inventory", str(inventory)]), 0)
                self.assertEqual(vpnctl.main(common + ["inventory", "validate", "--file", str(inventory), "--with-runtime"]), 0)
            self.assertNotEqual(vpnctl.main(common + ["upstream", "bind", "ny", "--node", "ru-home", "--inventory", str(inventory)]), 0)
            saved = vpnctl.load_state(state_path)
            self.assertEqual(saved["upstream_nodes"], {"ny": "ny-vps"})
            self.assertEqual(saved["profiles"], state["profiles"])
