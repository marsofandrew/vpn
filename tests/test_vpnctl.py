import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import vpnctl


def default_profile(state):
    return state["profiles"][0]


def default_client(state):
    return default_profile(state)["clients"][0]


class VpnctlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_current_usage_period = vpnctl.current_usage_period
        self.original_run_compose = vpnctl.run_compose

    def tearDown(self) -> None:
        vpnctl.current_usage_period = self.original_current_usage_period
        vpnctl.run_compose = self.original_run_compose

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
        default_profile(state)["clients"][0]["enabled"] = False
        default_profile(state)["clients"][0]["disabled_reason"] = "manual"

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
        profile = default_profile(state)
        client = default_client(state)

        link = vpnctl.generate_vless_link(client, state, profile)
        parsed = urlparse(link)
        query = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, "vless")
        self.assertEqual(parsed.hostname, "203.0.113.10")
        self.assertEqual(parsed.port, 443)
        self.assertEqual(query["security"], ["reality"])
        self.assertEqual(query["type"], ["tcp"])
        self.assertEqual(query["pbk"], [profile["keys"]["public_key"]])
        self.assertEqual(query["sid"], [profile["short_id"]])
        self.assertEqual(query["sni"], ["www.cloudflare.com"])
        self.assertEqual(query["flow"], ["xtls-rprx-vision"])

    def test_custom_port_is_rendered_and_used_in_links(self) -> None:
        state = vpnctl.create_state(
            server_host="203.0.113.10",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=8443,
            client_names=["phone"],
            quota_bytes=None,
        )

        config = vpnctl.render_config(state)
        profile = default_profile(state)
        link = vpnctl.generate_vless_link(default_client(state), state, profile)

        self.assertEqual(config["inbounds"][0]["port"], 8443)
        self.assertEqual(urlparse(link).port, 8443)

    def test_second_profile_renders_another_inbound_and_link(self) -> None:
        state = vpnctl.create_state(
            server_host="203.0.113.10",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=None,
        )
        profile = vpnctl.create_profile(
            name="backup",
            reality_target="www.microsoft.com:443",
            default_domain="example.com",
            port=8443,
            client_names=["tablet"],
            quota_bytes=None,
        )
        state["profiles"].append(profile)

        config = vpnctl.render_config(state)
        link = vpnctl.generate_vless_link(profile["clients"][0], state, profile)
        parsed = urlparse(link)
        query = parse_qs(parsed.query)

        self.assertEqual([inbound["port"] for inbound in config["inbounds"][:2]], [443, 8443])
        self.assertEqual(config["inbounds"][1]["tag"], "vless_reality_backup")
        self.assertEqual(config["inbounds"][1]["streamSettings"]["realitySettings"]["target"], "www.microsoft.com:443")
        self.assertEqual(config["inbounds"][1]["settings"]["clients"][0]["email"], "backup-tablet@example.com")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(query["sni"], ["www.microsoft.com"])

    def test_duplicate_profile_ports_are_rejected(self) -> None:
        state = vpnctl.create_state(
            server_host="203.0.113.10",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=None,
        )
        state["profiles"].append(
            vpnctl.create_profile(
                name="backup",
                reality_target="www.microsoft.com:443",
                default_domain="example.com",
                port=443,
                client_names=[],
                quota_bytes=None,
            )
        )

        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.render_config(state)

    def test_invalid_port_is_rejected(self) -> None:
        for port in (0, 65536, "not-a-port"):
            with self.subTest(port=port):
                with self.assertRaises(Exception):
                    vpnctl.parse_port(port)

    def test_compose_command_does_not_require_single_state_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            config_path = Path(tmp_dir) / "config.json"
            state = vpnctl.create_state(
                server_host="203.0.113.10",
                reality_target="www.cloudflare.com:443",
                default_domain="example.com",
                port=8443,
                client_names=["phone"],
                quota_bytes=None,
            )
            vpnctl.save_state(state_path, state)
            captured = {}

            def fake_run_compose(compose_file: Path, args: list[str], capture: bool = False, port: int | None = None):
                captured["compose_file"] = compose_file
                captured["args"] = args
                captured["capture"] = capture
                captured["port"] = port

            vpnctl.run_compose = fake_run_compose
            args = type(
                "Args",
                (),
                {
                    "state": state_path,
                    "config": config_path,
                    "compose_file": Path("docker-compose.yaml"),
                },
            )()

            vpnctl.command_compose(args, ["up", "-d"])

            self.assertIsNone(captured["port"])
            self.assertEqual(captured["args"], ["up", "-d"])

    def test_quota_enforcement_accumulates_xray_stats_and_disables_client(self) -> None:
        state = vpnctl.create_state(
            server_host="vpn.example.com",
            reality_target="www.cloudflare.com:443",
            default_domain="example.com",
            port=443,
            client_names=["phone"],
            quota_bytes=vpnctl.parse_size("1KiB"),
        )
        client = default_client(state)
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
        client = default_client(state)
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
        client = default_client(state)
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

    def test_legacy_state_migration_preserves_client_usage_and_quota(self) -> None:
        vpnctl.current_usage_period = lambda: "2026-05"
        state = vpnctl.migrate_legacy_state(
            {
                "version": 1,
                "usage_period": "2026-04",
                "clients": [
                    {
                        "name": "phone",
                        "id": "client-id",
                        "email": "phone@example.com",
                        "enabled": False,
                        "quota_bytes": 100,
                        "used_uplink_bytes": 10,
                        "used_downlink_bytes": 20,
                        "disabled_reason": "manual",
                    }
                ],
                "keys": {"private_key": "priv", "public_key": "pub"},
                "short_id": "short",
                "default_domain": "example.com",
            }
        )

        client = default_client(state)
        self.assertEqual(state["usage_period"], "2026-04")
        self.assertEqual(default_profile(state)["port"], vpnctl.DEFAULT_PORT)
        self.assertIs(client["enabled"], False)
        self.assertEqual(client["quota_bytes"], 100)
        self.assertEqual(client["used_uplink_bytes"], 10)
        self.assertEqual(client["used_downlink_bytes"], 20)

    def test_docker_socket_permission_error_is_detected(self) -> None:
        error = subprocess.CalledProcessError(
            returncode=1,
            cmd=["docker", "compose", "up", "-d"],
            stderr=(
                "unable to get image 'ghcr.io/xtls/xray-core:latest': permission denied "
                "while trying to connect to the docker API at unix:///var/run/docker.sock"
            ),
        )

        self.assertIs(vpnctl.is_docker_permission_error(error), True)
        self.assertIn("/var/run/docker.sock", str(vpnctl.docker_permission_error()))

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
            self.assertEqual(default_client(state)["quota_bytes"], 2 * 1024**3)
            self.assertEqual(config["inbounds"][0]["settings"]["clients"][0]["email"], "phone@example.com")

    def test_profile_add_and_scoped_client_remove_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            config_path = Path(tmp_dir) / "config.json"
            compose_path = Path(tmp_dir) / "docker-compose.yaml"
            compose_path.write_text("services: {}\n")
            calls = []

            def fake_run_compose(compose_file: Path, args: list[str], capture: bool = False, port: int | None = None):
                calls.append((compose_file, args, capture, port))

            vpnctl.run_compose = fake_run_compose
            output = StringIO()

            with redirect_stdout(output):
                self.assertEqual(
                    vpnctl.main(
                        [
                            "--state",
                            str(state_path),
                            "--config",
                            str(config_path),
                            "--compose-file",
                            str(compose_path),
                            "init",
                            "--server-host",
                            "vpn.example.com",
                            "--reality-target",
                            "www.cloudflare.com:443",
                            "--default-domain",
                            "example.com",
                            "--client",
                            "phone",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    vpnctl.main(
                        [
                            "--state",
                            str(state_path),
                            "--config",
                            str(config_path),
                            "--compose-file",
                            str(compose_path),
                            "profile",
                            "add",
                            "backup",
                            "--port",
                            "8443",
                            "--reality-target",
                            "www.microsoft.com:443",
                            "--client",
                            "tablet",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    vpnctl.main(
                        [
                            "--state",
                            str(state_path),
                            "--config",
                            str(config_path),
                            "--compose-file",
                            str(compose_path),
                            "client",
                            "remove",
                            "tablet",
                            "--profile",
                            "backup",
                        ]
                    ),
                    0,
                )

            state = json.loads(state_path.read_text())
            config = json.loads(config_path.read_text())
            backup = next(profile for profile in state["profiles"] if profile["name"] == "backup")
            self.assertEqual(backup["clients"], [])
            self.assertEqual([inbound["port"] for inbound in config["inbounds"][:2]], [443, 8443])
            self.assertEqual([call[1] for call in calls], [["up", "-d", vpnctl.XRAY_SERVICE], ["up", "-d", vpnctl.XRAY_SERVICE]])


if __name__ == "__main__":
    unittest.main()
