import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import vpnctl


class VpnctlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_current_usage_period = vpnctl.current_usage_period

    def tearDown(self) -> None:
        vpnctl.current_usage_period = self.original_current_usage_period

    def test_render_config_contains_vless_reality_stats_and_api(self) -> None:
        state = vpnctl.create_state(
            server_host="vpn.example.com",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=None,
        )

        config = vpnctl.render_config(state)

        inbound = config["inbounds"][0]
        self.assertEqual(inbound["protocol"], "vless")
        self.assertEqual(inbound["streamSettings"]["security"], "reality")
        self.assertEqual(inbound["streamSettings"]["realitySettings"]["target"], "www.cloudflare.com:443")
        self.assertEqual(inbound["settings"]["clients"][0]["email"], "phone@example.com")
        self.assertEqual(config["stats"], {})
        self.assertEqual(config["api"]["services"], ["HandlerService", "LoggerService", "StatsService"])
        self.assertIs(config["policy"]["levels"]["0"]["statsUserUplink"], True)

    def test_disabled_clients_are_not_rendered(self) -> None:
        state = vpnctl.create_state(
            server_host="vpn.example.com",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone", "laptop"],
            quota_bytes=None,
        )
        state["clients"][0]["enabled"] = False
        state["clients"][0]["disabled_reason"] = "manual"

        clients = vpnctl.render_config(state)["inbounds"][0]["settings"]["clients"]

        self.assertEqual([client["email"] for client in clients], ["laptop@example.com"])

    def test_vless_link_has_reality_parameters(self) -> None:
        state = vpnctl.create_state(
            server_host="203.0.113.10",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=None,
        )
        client = state["clients"][0]

        link = vpnctl.generate_vless_link(client, state)
        parsed = urlparse(link)
        query = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, "vless")
        self.assertEqual(parsed.hostname, "203.0.113.10")
        self.assertEqual(parsed.port, 443)
        self.assertEqual(query["security"], ["reality"])
        self.assertEqual(query["type"], ["tcp"])
        self.assertEqual(query["pbk"], [state["keys"]["public_key"]])
        self.assertEqual(query["sid"], [state["short_id"]])
        self.assertEqual(query["sni"], ["www.cloudflare.com"])
        self.assertEqual(query["flow"], ["xtls-rprx-vision"])

    def test_quota_enforcement_accumulates_xray_stats_and_disables_client(self) -> None:
        state = vpnctl.create_state(
            server_host="vpn.example.com",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=vpnctl.parse_size("1KiB"),
        )
        client = state["clients"][0]
        response = {
            "stat": [
                {"name": f"user>>>{client['email']}>>>traffic>>>uplink", "value": 600},
                {"name": f"user>>>{client['email']}>>>traffic>>>downlink", "value": 600},
            ]
        }

        changed = vpnctl.apply_usage_deltas(state, vpnctl.collect_usage_deltas(response))
        disabled = vpnctl.enforce_quotas(state)

        self.assertIs(changed, True)
        self.assertEqual(disabled, [client])
        self.assertIs(client["enabled"], False)
        self.assertEqual(client["disabled_reason"], "quota_exceeded")
        self.assertEqual(client["used_uplink_bytes"], 600)
        self.assertEqual(client["used_downlink_bytes"], 600)

    def test_new_state_has_current_monthly_usage_period(self) -> None:
        vpnctl.current_usage_period = lambda: "2026-05"

        state = vpnctl.create_state(
            server_host="vpn.example.com",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=vpnctl.parse_size("1GiB"),
        )

        self.assertEqual(state["usage_period"], "2026-05")

    def test_monthly_rollover_resets_usage_and_reenables_quota_disabled_clients(self) -> None:
        vpnctl.current_usage_period = lambda: "2026-05"
        state = vpnctl.create_state(
            server_host="vpn.example.com",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=vpnctl.parse_size("1GiB"),
        )
        client = state["clients"][0]
        state["usage_period"] = "2026-04"
        client["enabled"] = False
        client["disabled_reason"] = "quota_exceeded"
        client["used_uplink_bytes"] = 10
        client["used_downlink_bytes"] = 20

        changed = vpnctl.ensure_monthly_period(state)

        self.assertIs(changed, True)
        self.assertEqual(state["usage_period"], "2026-05")
        self.assertIs(client["enabled"], True)
        self.assertIsNone(client["disabled_reason"])
        self.assertEqual(client["used_uplink_bytes"], 0)
        self.assertEqual(client["used_downlink_bytes"], 0)

    def test_monthly_rollover_keeps_manually_disabled_clients_disabled(self) -> None:
        vpnctl.current_usage_period = lambda: "2026-05"
        state = vpnctl.create_state(
            server_host="vpn.example.com",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=vpnctl.parse_size("1GiB"),
        )
        client = state["clients"][0]
        state["usage_period"] = "2026-04"
        client["enabled"] = False
        client["disabled_reason"] = "manual"
        client["used_uplink_bytes"] = 10
        client["used_downlink_bytes"] = 20

        changed = vpnctl.ensure_monthly_period(state)

        self.assertIs(changed, True)
        self.assertEqual(state["usage_period"], "2026-05")
        self.assertIs(client["enabled"], False)
        self.assertEqual(client["disabled_reason"], "manual")
        self.assertEqual(client["used_uplink_bytes"], 0)
        self.assertEqual(client["used_downlink_bytes"], 0)

    def test_legacy_state_migration_adds_current_monthly_period(self) -> None:
        vpnctl.current_usage_period = lambda: "2026-05"
        state = vpnctl.migrate_legacy_state(
            {
                "version": 1,
                "clients": [],
                "keys": {"private_key": "priv", "public_key": "pub"},
                "short_id": "short",
                "default_domain": "example.com",
            }
        )

        self.assertEqual(state["usage_period"], "2026-05")

    def test_init_command_writes_state_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            config_path = Path(tmp_dir) / "config.json"
            output = StringIO()

            with redirect_stdout(output):
                exit_code = vpnctl.main(
                    [
                        "--state",
                        str(state_path),
                        "--config",
                        str(config_path),
                        "init",
                        "--server-host",
                        "vpn.example.com",
                        "--reality-target",
                        "www.cloudflare.com:443",
                        "--default-domain",
                        "example.com",
                        "--client",
                        "phone",
                        "--quota",
                        "2GiB",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("vless://", output.getvalue())
            state = json.loads(state_path.read_text())
            config = json.loads(config_path.read_text())
            self.assertEqual(state["clients"][0]["quota_bytes"], 2 * 1024**3)
            self.assertEqual(config["inbounds"][0]["settings"]["clients"][0]["email"], "phone@example.com")


if __name__ == "__main__":
    unittest.main()
