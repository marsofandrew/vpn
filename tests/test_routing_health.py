import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import vpn_monitor
import vpn_transports
from vpn_manager import clock as app_clock
from vpn_manager import errors as app_errors
from vpn_manager import keys as app_keys
from vpn_manager.cli import entrypoint as app_cli_entrypoint
from vpn_manager.health.service import HealthService
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import storage as app_state_storage
from vpn_manager.xray import rendering as app_xray_rendering
from vpn_manager.xray.deployment import default_service


class RoutingHealthTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "state.json"
        self.config = Path(directory.name) / "config.json"
        self.state = app_state_creation.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        key = app_keys.generate_reality_keys()["public_key"]
        direct = vpn_transports.parse_link(
            "vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
            f"?security=reality&type=tcp&sni=example.com&pbk={key}&sid=abcdef"
        )
        cdn = vpn_transports.parse_link(
            "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443"
            "?security=tls&type=xhttp&sni=cdn.example.com&path=%2Fentry&mode=packet-up"
        )
        self.state["upstreams"] = {"ny-direct": direct, "ny-cdn": cdn}
        self.state["routing_policies"]["foreign"] = {
            "type": "priority",
            "upstreams": ["ny-direct", "ny-cdn"],
            "cooldown": 60,
        }
        self.state["profiles"][0].update(route="foreign", outbound_mode="proxy")
        self.state["node"]["foreign_only"] = True
        self.state["health_settings"] = {
            name: {"interval": 30, "fail_threshold": 3, "success_threshold": 3}
            for name in self.state["upstreams"]
        }
        app_state_storage.save_state(self.path, self.state)
        self.now = 1000

    def probe(self, primary, cdn):
        self.now += 30
        results = [
            {"success": primary, "exit_ip_verified": primary, "latency_ms": 5},
            {"success": cdn, "exit_ip_verified": cdn, "latency_ms": 30},
        ]
        state = app_state_storage.load_state(self.path)
        service = HealthService(
            Mock(side_effect=results), lambda: self.now, app_clock.utc_now
        )
        service.check(state)
        default_service().persist(state, self.path, self.config)
        return app_state_storage.load_state(self.path)

    def selected(self, state):
        return state["routing_policies"]["foreign"].get("current_upstream")

    def test_invalid_health_observation_state_has_a_controlled_error(self):
        self.state["health"] = {"ny-direct": {"status": "invalid"}}
        app_state_storage.save_state(self.path, self.state)
        previous = self.path.read_bytes()
        output = StringIO()
        with (
            redirect_stderr(output),
            patch.object(
                vpn_monitor,
                "probe_upstream",
                return_value={"success": True, "exit_ip_verified": True},
            ),
        ):
            result = app_cli_entrypoint.main(
                [
                    "--state",
                    str(self.path),
                    "--config",
                    str(self.config),
                    "health",
                    "check",
                    "--no-restart",
                ]
            )
        self.assertEqual(result, 1)
        self.assertIn("invalid health status", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assertEqual(self.path.read_bytes(), previous)

    def test_loss_recovery_hysteresis_cooldown_and_both_failed(self):
        for _ in range(3):
            state = self.probe(True, True)
        self.assertEqual(self.selected(state), "ny-direct")
        for _ in range(2):
            self.assertEqual(self.selected(self.probe(False, True)), "ny-direct")
        self.assertEqual(self.selected(self.probe(False, True)), "ny-cdn")
        for _ in range(3):
            state = self.probe(False, False)
        self.assertIsNone(self.selected(state))
        blocked = app_xray_rendering.render_config(state)
        self.assertEqual(blocked["routing"]["rules"][1]["outboundTag"], "block")
        for _ in range(3):
            state = self.probe(False, True)
        self.assertEqual(self.selected(state), "ny-cdn")
        for _ in range(3):
            state = self.probe(True, True)
        self.assertEqual(self.selected(state), "ny-cdn")
        state = self.probe(True, True)
        self.assertEqual(self.selected(state), "ny-cdn")
        state = self.probe(True, True)
        self.assertEqual(self.selected(state), "ny-direct")
        self.assertTrue(state["route_events"])

    def test_foreign_only_has_no_freedom_or_dns_ipv6_exceptions(self):
        config = app_xray_rendering.render_config(self.state)
        self.assertEqual(config["outbounds"][0]["protocol"], "blackhole")
        self.assertNotIn(
            "freedom", [outbound["protocol"] for outbound in config["outbounds"]]
        )
        profile_rule = config["routing"]["rules"][1]
        self.assertEqual(set(profile_rule), {"type", "inboundTag", "outboundTag"})
        self.assertEqual(profile_rule["outboundTag"], "block")
        self.state["profiles"][0]["route"] = "direct"
        with self.assertRaises(app_errors.VpnctlError):
            app_xray_rendering.render_config(self.state)

    def test_balanced_policy_selects_healthy_lowest_latency(self):
        self.state["routing_policies"]["foreign"]["type"] = "balanced"
        self.state["health_settings"] = {
            name: {"interval": 30, "success_threshold": 1}
            for name in self.state["upstreams"]
        }
        app_state_storage.save_state(self.path, self.state)
        self.assertEqual(self.selected(self.probe(True, True)), "ny-direct")

    def test_disabled_or_unknown_selected_route_is_blocked(self):
        self.state["routing_policies"]["foreign"]["current_upstream"] = "ny-direct"
        self.state["health"] = {"ny-direct": {"status": "healthy"}}
        self.state["upstreams"]["ny-direct"]["enabled"] = False
        config = app_xray_rendering.render_config(self.state)
        self.assertEqual(config["routing"]["rules"][1]["outboundTag"], "block")
        self.assertNotIn("ny-direct", [item["tag"] for item in config["outbounds"]])

    def test_health_check_normalizes_month_before_persistence(self):
        self.state["usage_period"] = "2000-01"
        self.state["profiles"][0]["clients"][0]["used_uplink_bytes"] = 100
        app_state_storage.save_state(self.path, self.state)
        self.probe(True, True)
        saved = app_state_storage.load_state(self.path)
        self.assertEqual(saved["usage_period"], app_clock.current_usage_period())
        self.assertEqual(saved["profiles"][0]["clients"][0]["used_uplink_bytes"], 0)
