import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import vpn_inventory
import vpn_transports
from vpn_manager import files as app_files
from vpn_manager.cli import entrypoint as app_cli_entrypoint
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import storage as app_state_storage


class InventoryCliTests(unittest.TestCase):
    def test_inventory_creation_is_independent_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "inventory.json"
            state = root / "absent-state.json"
            common = ["--state", str(state)]
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    app_cli_entrypoint.main(
                        common + ["inventory", "example", "--file", str(inventory)]
                    ),
                    0,
                )
                self.assertEqual(
                    app_cli_entrypoint.main(
                        common + ["inventory", "validate", "--file", str(inventory)]
                    ),
                    0,
                )
            self.assertFalse(state.exists())
            previous = inventory.read_bytes()
            self.assertNotEqual(
                app_cli_entrypoint.main(
                    common + ["inventory", "example", "--file", str(inventory)]
                ),
                0,
            )
            self.assertEqual(inventory.read_bytes(), previous)
            rows = vpn_inventory.summary_nodes(app_files.load_json(inventory))
            self.assertEqual(
                next(row["role"] for row in rows if row["id"] == "ru-home"), "gateway"
            )

    def test_binding_uses_exit_nodes_and_preserves_runtime_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            inventory = root / "inventory.json"
            state = app_state_creation.create_state(
                "vpn.example.com",
                "example.com:443",
                "example.com",
                8443,
                ["phone"],
                None,
            )
            state["node"] = {"id": "ru-vps", "role": "gateway"}
            state["upstreams"]["ny"] = vpn_transports.parse_link(
                "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443"
                "?security=tls&type=xhttp&sni=cdn.example.com"
            )
            app_state_storage.save_state(state_path, state)
            app_files.write_json(inventory, vpn_inventory.example_inventory())
            common = ["--state", str(state_path)]
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    app_cli_entrypoint.main(
                        common
                        + [
                            "upstream",
                            "bind",
                            "ny",
                            "--node",
                            "ny-vps",
                            "--inventory",
                            str(inventory),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    app_cli_entrypoint.main(
                        common
                        + [
                            "inventory",
                            "validate",
                            "--file",
                            str(inventory),
                            "--with-runtime",
                        ]
                    ),
                    0,
                )
            self.assertNotEqual(
                app_cli_entrypoint.main(
                    common
                    + [
                        "upstream",
                        "bind",
                        "ny",
                        "--node",
                        "ru-home",
                        "--inventory",
                        str(inventory),
                    ]
                ),
                0,
            )
            saved = app_state_storage.load_state(state_path)
            self.assertEqual(saved["upstream_nodes"], {"ny": "ny-vps"})
            self.assertEqual(saved["profiles"], state["profiles"])
