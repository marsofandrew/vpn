import copy
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vpn_transports
from vpn_manager import accounting, files, keys
from vpn_manager.errors import VpnctlError
from vpn_manager.state import creation, storage
from vpn_manager.xray import deployment, rendering, runtime


def compose_config(config_path, port):
    return {
        "services": {
            "xray": {
                "image": os.environ.get(
                    "XRAY_TEST_IMAGE", "ghcr.io/xtls/xray-core:26.10.31"
                ),
                "entrypoint": ["xray"],
                "command": ["run", "-config", "/etc/xray/config.json"],
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "volumes": [f"{config_path}:/etc/xray/config.json:ro"],
                "ports": [f"127.0.0.1:{port}:{port}", "127.0.0.1:10085:10085"],
            }
        }
    }


@unittest.skipUnless(
    os.environ.get("XRAY_INTEGRATION") == "1", "set XRAY_INTEGRATION=1 for Docker tests"
)
class XrayIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="vpnctl-integration-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.state_path, self.config_path = root / "state.json", root / "config.json"
        self.compose = root / "compose.json"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.state = creation.create_state(
            "127.0.0.1", "example.com:443", "example.com", port, ["test"], 1000
        )
        storage.save_state(self.state_path, self.state)
        config = rendering.render_config(self.state)
        files.write_json(self.config_path, config)
        files.write_json(self.compose, compose_config(self.config_path, port))
        self.addCleanup(
            runtime.run_compose,
            self.compose,
            ["down", "--remove-orphans"],
            capture=True,
        )
        self.deploy(config, force=True)

    def deploy(self, config, force=False):
        deployment.deploy_config(
            self.state, self.state_path, self.config_path, self.compose, config, force
        )

    def changed_configuration(self):
        self.state["profiles"][0]["clients"][0]["enabled"] = False
        changed = rendering.render_config(self.state)
        self.deploy(changed)
        return changed

    def test_config_change_recreates_and_checkpoints(self):
        first_epoch = runtime.runtime_epoch(self.compose)
        accounting.sample_usage(self.state, self.compose)
        storage.save_state(self.state_path, self.state)
        changed = self.changed_configuration()
        self.assertNotEqual(first_epoch, runtime.runtime_epoch(self.compose))
        self.assertEqual(files.load_json(self.config_path), changed)

    def test_invalid_native_candidate_preserves_running_instance(self):
        changed = self.changed_configuration()
        epoch = runtime.runtime_epoch(self.compose)
        invalid = copy.deepcopy(changed)
        invalid["inbounds"][0]["protocol"] = "invalid"
        with self.assertRaises(subprocess.CalledProcessError):
            self.deploy(invalid)
        self.assertEqual(epoch, runtime.runtime_epoch(self.compose))
        self.assertEqual(files.load_json(self.config_path), changed)

    def test_failed_health_check_rolls_back(self):
        changed = self.changed_configuration()
        verify = runtime.verify_xray
        checks = 0

        def fail_once(compose_file, candidate):
            nonlocal checks
            checks += 1
            if checks == 1:
                raise VpnctlError("injected health failure")
            verify(compose_file, candidate)

        self.state["profiles"][0]["clients"][0]["enabled"] = True
        with patch.object(runtime, "verify_xray", side_effect=fail_once):
            with self.assertRaisesRegex(VpnctlError, "restored"):
                self.deploy(rendering.render_config(self.state))
        self.assertEqual(files.load_json(self.config_path), changed)
        runtime.verify_xray(self.compose, changed)

    def test_foreign_only_configuration_keeps_unhealthy_route_blocked(self):
        self.changed_configuration()
        self.state = storage.load_state(self.state_path)
        key = keys.generate_reality_keys()["public_key"]
        self.state["upstreams"]["ny"] = vpn_transports.parse_link(
            "vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
            f"?type=tcp&security=reality&pbk={key}&sid=abcd&sni=example.com"
        )
        self.state["routing_policies"]["failover"] = {
            "type": "priority",
            "upstreams": ["ny"],
        }
        self.state["profiles"][0]["route"] = "failover"
        self.state["node"]["foreign_only"] = True
        blocked = rendering.render_config(self.state)
        self.assertNotIn("freedom", [item["protocol"] for item in blocked["outbounds"]])
        self.deploy(blocked)
        runtime.verify_xray(self.compose, blocked)
