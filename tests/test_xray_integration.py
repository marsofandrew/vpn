import copy
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vpnctl


@unittest.skipUnless(os.environ.get("XRAY_INTEGRATION") == "1", "set XRAY_INTEGRATION=1 for Docker tests")
class XrayIntegrationTests(unittest.TestCase):
    def test_native_validation_recreation_accounting_and_rollback(self):
        with tempfile.TemporaryDirectory(prefix="vpnctl-integration-") as directory:
            root = Path(directory)
            state_path = root / "state.json"
            config_path = root / "config.json"
            compose = root / "compose.json"
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            state = vpnctl.create_state("127.0.0.1", "example.com:443", "example.com", port, ["test"], 1000)
            vpnctl.save_state(state_path, state)
            config = vpnctl.render_config(state)
            vpnctl.write_json(config_path, config)
            image = os.environ.get("XRAY_TEST_IMAGE", "ghcr.io/xtls/xray-core:26.10.31")
            vpnctl.write_json(compose, {"services": {"xray": {
                "image": image, "entrypoint": ["xray"],
                "command": ["run", "-config", "/etc/xray/config.json"],
                "read_only": True, "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "volumes": [f"{config_path}:/etc/xray/config.json:ro"],
                "ports": [f"127.0.0.1:{port}:{port}", "127.0.0.1:10085:10085"],
            }}})
            try:
                vpnctl.deploy_config(state, state_path, config_path, compose, config, force=True)
                first_epoch = vpnctl.runtime_epoch(compose)
                vpnctl.sample_usage(state, compose)
                vpnctl.save_state(state_path, state)
                state["profiles"][0]["clients"][0]["enabled"] = False
                changed = vpnctl.render_config(state)
                vpnctl.deploy_config(state, state_path, config_path, compose, changed)
                self.assertNotEqual(first_epoch, vpnctl.runtime_epoch(compose))
                self.assertEqual(vpnctl.load_json(config_path), changed)
                second_epoch = vpnctl.runtime_epoch(compose)
                invalid = copy.deepcopy(changed)
                invalid["inbounds"][0]["protocol"] = "invalid"
                with self.assertRaises(subprocess.CalledProcessError):
                    vpnctl.deploy_config(state, state_path, config_path, compose, invalid)
                self.assertEqual(second_epoch, vpnctl.runtime_epoch(compose))
                self.assertEqual(vpnctl.load_json(config_path), changed)
                verify = vpnctl.verify_xray
                checks = 0

                def fail_once(compose_file, candidate):
                    nonlocal checks
                    checks += 1
                    if checks == 1:
                        raise vpnctl.VpnctlError("injected health failure")
                    verify(compose_file, candidate)

                state["profiles"][0]["clients"][0]["enabled"] = True
                with patch.object(vpnctl, "verify_xray", side_effect=fail_once):
                    with self.assertRaisesRegex(vpnctl.VpnctlError, "restored"):
                        vpnctl.deploy_config(state, state_path, config_path, compose, vpnctl.render_config(state))
                self.assertEqual(vpnctl.load_json(config_path), changed)
                vpnctl.verify_xray(compose, changed)
                recovered = vpnctl.load_state(state_path)
                key = vpnctl.generate_reality_keys()["public_key"]
                recovered["upstreams"]["ny"] = vpnctl.vpn_transports.parse_link(
                    "vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
                    f"?type=tcp&security=reality&pbk={key}&sid=abcd&sni=example.com")
                recovered["routing_policies"]["failover"] = {"type": "priority", "upstreams": ["ny"]}
                recovered["profiles"][0]["route"] = "failover"
                recovered["node"]["foreign_only"] = True
                blocked = vpnctl.render_config(recovered)
                self.assertNotIn("freedom", [item["protocol"] for item in blocked["outbounds"]])
                vpnctl.deploy_config(recovered, state_path, config_path, compose, blocked)
                vpnctl.verify_xray(compose, blocked)
            finally:
                vpnctl.run_compose(compose, ["down", "--remove-orphans"], capture=True)
