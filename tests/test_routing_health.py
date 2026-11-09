from contextlib import redirect_stdout
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vpnctl


class RoutingHealthTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "state.json"
        self.config = Path(directory.name) / "config.json"
        self.state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None)
        key = vpnctl.generate_reality_keys()["public_key"]
        direct = vpnctl.vpn_transports.parse_link(
            "vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
            f"?security=reality&type=tcp&sni=example.com&pbk={key}&sid=abcdef")
        cdn = vpnctl.vpn_transports.parse_link(
            "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443"
            "?security=tls&type=xhttp&sni=cdn.example.com&path=%2Fentry&mode=packet-up")
        self.state["upstreams"] = {"ny-direct": direct, "ny-cdn": cdn}
        self.state["routing_policies"]["foreign"] = {"type": "priority", "upstreams": ["ny-direct", "ny-cdn"], "cooldown": 60}
        self.state["profiles"][0].update(route="foreign", outbound_mode="proxy")
        self.state["node"]["foreign_only"] = True
        self.state["health_settings"] = {name: {"interval": 30, "fail_threshold": 3, "success_threshold": 3}
                                         for name in self.state["upstreams"]}
        vpnctl.save_state(self.path, self.state)
        self.now = 1000

    def probe(self, primary, cdn):
        self.now += 30
        results = [{"success": primary, "exit_ip_verified": primary, "latency_ms": 5},
                   {"success": cdn, "exit_ip_verified": cdn, "latency_ms": 30}]
        with redirect_stdout(StringIO()), patch.object(vpnctl.vpn_monitor, "probe_upstream", side_effect=results), \
                patch.object(vpnctl.time, "time", return_value=self.now):
            self.assertEqual(vpnctl.main(["--state", str(self.path), "--config", str(self.config), "health", "check", "--no-restart"]), 0)
        return vpnctl.load_state(self.path)

    def selected(self, state):
        return state["routing_policies"]["foreign"].get("current_upstream")

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
        blocked = vpnctl.render_config(state)
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
        config = vpnctl.render_config(self.state)
        self.assertEqual(config["outbounds"][0]["protocol"], "blackhole")
        self.assertNotIn("freedom", [outbound["protocol"] for outbound in config["outbounds"]])
        profile_rule = config["routing"]["rules"][1]
        self.assertEqual(set(profile_rule), {"type", "inboundTag", "outboundTag"})
        self.assertEqual(profile_rule["outboundTag"], "block")
        self.state["profiles"][0]["route"] = "direct"
        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.render_config(self.state)

    def test_balanced_policy_selects_healthy_lowest_latency(self):
        self.state["routing_policies"]["foreign"]["type"] = "balanced"
        self.state["health_settings"] = {name: {"interval": 30, "success_threshold": 1} for name in self.state["upstreams"]}
        vpnctl.save_state(self.path, self.state)
        self.assertEqual(self.selected(self.probe(True, True)), "ny-direct")

    def test_disabled_or_unknown_selected_route_is_blocked(self):
        self.state["routing_policies"]["foreign"]["current_upstream"] = "ny-direct"
        self.state["health"] = {"ny-direct": {"status": "healthy"}}
        self.state["upstreams"]["ny-direct"]["enabled"] = False
        config = vpnctl.render_config(self.state)
        self.assertEqual(config["routing"]["rules"][1]["outboundTag"], "block")
        self.assertNotIn("ny-direct", [item["tag"] for item in config["outbounds"]])

    def test_health_check_normalizes_month_before_persistence(self):
        self.state["usage_period"] = "2000-01"
        self.state["profiles"][0]["clients"][0]["used_uplink_bytes"] = 100
        vpnctl.save_state(self.path, self.state)
        self.probe(True, True)
        saved = vpnctl.load_state(self.path)
        self.assertEqual(saved["usage_period"], vpnctl.current_usage_period())
        self.assertEqual(saved["profiles"][0]["clients"][0]["used_uplink_bytes"], 0)
