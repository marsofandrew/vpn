import copy
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vpn_transports
from vpn_manager import accounting as app_accounting
from vpn_manager import errors as app_errors
from vpn_manager import files as app_files
from vpn_manager import keys as app_keys
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import deployment as app_xray_deployment
from vpn_manager.xray import rendering as app_xray_rendering
from vpn_manager.xray import runtime as app_xray_runtime


@unittest.skipUnless(
    os.environ.get("XRAY_INTEGRATION") == "1", "set XRAY_INTEGRATION=1 for Docker tests"
)
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
            state = app_state_creation.create_state(
                "127.0.0.1", "example.com:443", "example.com", port, ["test"], 1000
            )
            app_state_storage.save_state(state_path, state)
            config = app_xray_rendering.render_config(state)
            app_files.write_json(config_path, config)
            image = os.environ.get("XRAY_TEST_IMAGE", "ghcr.io/xtls/xray-core:26.10.31")
            app_files.write_json(
                compose,
                {
                    "services": {
                        "xray": {
                            "image": image,
                            "entrypoint": ["xray"],
                            "command": ["run", "-config", "/etc/xray/config.json"],
                            "read_only": True,
                            "cap_drop": ["ALL"],
                            "security_opt": ["no-new-privileges:true"],
                            "volumes": [f"{config_path}:/etc/xray/config.json:ro"],
                            "ports": [
                                f"127.0.0.1:{port}:{port}",
                                "127.0.0.1:10085:10085",
                            ],
                        }
                    }
                },
            )
            try:
                app_xray_deployment.deploy_config(
                    state, state_path, config_path, compose, config, force=True
                )
                first_epoch = app_xray_runtime.runtime_epoch(compose)
                app_accounting.sample_usage(state, compose)
                app_state_storage.save_state(state_path, state)
                state["profiles"][0]["clients"][0]["enabled"] = False
                changed = app_xray_rendering.render_config(state)
                app_xray_deployment.deploy_config(
                    state, state_path, config_path, compose, changed
                )
                self.assertNotEqual(
                    first_epoch, app_xray_runtime.runtime_epoch(compose)
                )
                self.assertEqual(app_files.load_json(config_path), changed)
                second_epoch = app_xray_runtime.runtime_epoch(compose)
                invalid = copy.deepcopy(changed)
                invalid["inbounds"][0]["protocol"] = "invalid"
                with self.assertRaises(subprocess.CalledProcessError):
                    app_xray_deployment.deploy_config(
                        state, state_path, config_path, compose, invalid
                    )
                self.assertEqual(second_epoch, app_xray_runtime.runtime_epoch(compose))
                self.assertEqual(app_files.load_json(config_path), changed)
                verify = app_xray_runtime.verify_xray
                checks = 0

                def fail_once(compose_file, candidate):
                    nonlocal checks
                    checks += 1
                    if checks == 1:
                        raise app_errors.VpnctlError("injected health failure")
                    verify(compose_file, candidate)

                state["profiles"][0]["clients"][0]["enabled"] = True
                with patch.object(
                    app_xray_runtime, "verify_xray", side_effect=fail_once
                ):
                    with self.assertRaisesRegex(app_errors.VpnctlError, "restored"):
                        app_xray_deployment.deploy_config(
                            state,
                            state_path,
                            config_path,
                            compose,
                            app_xray_rendering.render_config(state),
                        )
                self.assertEqual(app_files.load_json(config_path), changed)
                app_xray_runtime.verify_xray(compose, changed)
                recovered = app_state_storage.load_state(state_path)
                key = app_keys.generate_reality_keys()["public_key"]
                recovered["upstreams"]["ny"] = vpn_transports.parse_link(
                    "vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
                    f"?type=tcp&security=reality&pbk={key}&sid=abcd&sni=example.com"
                )
                recovered["routing_policies"]["failover"] = {
                    "type": "priority",
                    "upstreams": ["ny"],
                }
                recovered["profiles"][0]["route"] = "failover"
                recovered["node"]["foreign_only"] = True
                blocked = app_xray_rendering.render_config(recovered)
                self.assertNotIn(
                    "freedom", [item["protocol"] for item in blocked["outbounds"]]
                )
                app_xray_deployment.deploy_config(
                    recovered, state_path, config_path, compose, blocked
                )
                app_xray_runtime.verify_xray(compose, blocked)
            finally:
                app_xray_runtime.run_compose(
                    compose, ["down", "--remove-orphans"], capture=True
                )
