import base64
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
from urllib.parse import parse_qs, urlparse

import vpnctl


class SubscriptionCliTests(unittest.TestCase):
    def test_ech_client_link_never_contains_server_keys(self):
        state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
        profile = state["profiles"][0]
        profile["transport"] = {"type": "xhttp", "settings": {"path": "/entry", "mode": "packet-up"}}
        profile["security"] = {"type": "tls", "settings": {
            "server_name": "cdn.example.com", "ech_server_keys": "AQIDBA==",
            "certificates": [{"certificateFile": "/cert.pem", "keyFile": "/key.pem"}],
        }}
        profile["client_ech_config_list"] = "BAUGBw=="
        link = vpnctl.generate_vless_link(profile["clients"][0], state, profile)
        self.assertEqual(parse_qs(urlparse(link).query)["ech"], ["BAUGBw=="])
        self.assertNotIn("AQIDBA", link)
        self.assertNotIn("key.pem", link)

    def test_ech_deployment_rejects_older_native_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate.json"
            vpnctl.write_json(candidate, {"outbounds": [{"streamSettings": {"tlsSettings": {"echConfigList": "AQ=="}}}]})
            with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="Xray 25.3.6 (Xray)")):
                with self.assertRaisesRegex(vpnctl.VpnctlError, "pinned Xray"):
                    vpnctl.validate_native(Path("compose.yaml"), candidate)
            with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="Xray 26.3.27 (Xray)")):
                vpnctl.validate_native(Path("compose.yaml"), candidate)

    def test_remote_entries_export_without_changing_local_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            config_path = root / "config.json"
            output = root / "phone.txt"
            state = vpnctl.create_state("ru.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
            vpnctl.save_state(state_path, state)
            local_client = state["profiles"][0]["clients"][0].copy()
            common = ["--state", str(state_path), "--config", str(config_path)]
            link = ("vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443"
                    "?type=xhttp&security=tls&sni=cdn.example.com&path=%2Fentry&mode=packet-up")
            stdout = StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(vpnctl.main(common + ["endpoint", "add", "ny-cdn", "--client", "phone", "--link", link]), 0)
                self.assertEqual(vpnctl.main(common + ["subscription", "phone", "--output", str(output)]), 0)
            entries = base64.b64decode(output.read_text()).decode().splitlines()
            self.assertEqual(len(entries), 2)
            self.assertIn(local_client["id"], entries[0])
            self.assertIn("cdn.example.com:443", entries[1])
            self.assertNotIn("vless://", stdout.getvalue())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(vpnctl.load_state(state_path)["profiles"][0]["clients"][0], local_client)
            self.assertNotEqual(vpnctl.main(common + ["subscription", "phone", "--output", str(state_path)]), 0)
