import base64
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager.cli import entrypoint as app_cli_entrypoint
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import runtime as app_xray_runtime


class SubscriptionCliTests(unittest.TestCase):
    def test_ech_client_link_never_contains_server_keys(self):
        state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        profile = state["profiles"][0]
        profile["transport"] = {
            "type": "xhttp",
            "settings": {"path": "/entry", "mode": "packet-up"},
        }
        profile["security"] = {
            "type": "tls",
            "settings": {
                "server_name": "cdn.example.com",
                "ech_server_keys": "AQIDBA==",
                "certificates": [
                    {"certificateFile": "/cert.pem", "keyFile": "/key.pem"}
                ],
            },
        }
        profile["client_ech_config_list"] = "BAUGBw=="
        link = app_exports_links.generate_vless_link(
            profile["clients"][0], state, profile
        )
        self.assertEqual(parse_qs(urlparse(link).query)["ech"], ["BAUGBw=="])
        self.assertNotIn("AQIDBA", link)
        self.assertNotIn("key.pem", link)

    def test_ech_deployment_rejects_older_native_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate.json"
            app_files.write_json(
                candidate,
                {
                    "outbounds": [
                        {"streamSettings": {"tlsSettings": {"echConfigList": "AQ=="}}}
                    ]
                },
            )
            with patch.object(
                app_xray_runtime,
                "run_compose",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout="Xray 25.3.6 (Xray)"
                ),
            ):
                with self.assertRaisesRegex(app_errors.VpnctlError, "pinned Xray"):
                    app_xray_runtime.validate_native(Path("compose.yaml"), candidate)
            with patch.object(
                app_xray_runtime,
                "run_compose",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout="Xray 26.10.31 (Xray)"
                ),
            ):
                app_xray_runtime.validate_native(Path("compose.yaml"), candidate)

    def test_remote_entries_export_without_changing_local_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            config_path = root / "config.json"
            output = root / "phone.txt"
            state = app_state_creation.create_state(
                "ru.example.com",
                "example.com:443",
                "example.com",
                8443,
                ["phone"],
                None,
            )
            app_state_storage.save_state(state_path, state)
            local_client = state["profiles"][0]["clients"][0].copy()
            common = ["--state", str(state_path), "--config", str(config_path)]
            link = (
                "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443"
                "?type=xhttp&security=tls&sni=cdn.example.com&path=%2Fentry&mode=packet-up"
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(
                    app_cli_entrypoint.main(
                        common
                        + [
                            "endpoint",
                            "add",
                            "ny-cdn",
                            "--client",
                            "phone",
                            "--link",
                            link,
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    app_cli_entrypoint.main(
                        common + ["subscription", "phone", "--output", str(output)]
                    ),
                    0,
                )
            entries = base64.b64decode(output.read_text()).decode().splitlines()
            self.assertEqual(len(entries), 2)
            self.assertIn(local_client["id"], entries[0])
            self.assertIn("cdn.example.com:443", entries[1])
            self.assertNotIn("vless://", stdout.getvalue())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                app_state_storage.load_state(state_path)["profiles"][0]["clients"][0],
                local_client,
            )
            self.assertNotEqual(
                app_cli_entrypoint.main(
                    common + ["subscription", "phone", "--output", str(state_path)]
                ),
                0,
            )
