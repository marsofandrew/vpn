"""Real local traffic and stabilization; dedicated credential rejection is deferred.

XRAY_INTEGRATION=1 python3 -m unittest discover -s tests -p test_stabilization_integration.py -v

Requires native Linux, a local Docker daemon, and free gateway API port 10085.
Only ghcr.io/xtls/xray-core:26.10.31 is used, regardless of XRAY_TEST_IMAGE.
"""

import copy
import json
import os
import socket
import socketserver
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from stabilization_fixture import (
    BODY,
    IMAGE,
    FaultProxy,
    StabilizationFixture,
    fixture_tls_roots,
    require_runtime,
)

import vpn_transports
from vpn_manager import accounting as app_accounting
from vpn_manager import files as app_files
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import creation as app_state_creation
from vpn_manager.state import model as app_state_model
from vpn_manager.xray import rendering as app_xray_rendering
from vpn_manager.xray import runtime as app_xray_runtime


class StabilizationHelperTests(unittest.TestCase):
    def test_configs_exist_privately_before_any_container_and_pin_topology(self):
        with tempfile.TemporaryDirectory(prefix="stabilization-helper-") as directory:
            fixture = self._config_fixture(directory)
            with (
                patch.dict(
                    os.environ,
                    {"XRAY_TEST_IMAGE": "forbidden.example/alternate:latest"},
                ),
                patch("stabilization_fixture.command") as docker,
            ):
                fixture.make_configs()
                docker.assert_not_called()
            state = fixture.state()
            gateway = app_files.load_json(fixture.config_path)
            self.assertEqual(gateway, app_xray_rendering.render_config(state))
            app_xray_rendering.validate_config(gateway)
            services = app_files.load_json(fixture.compose_file)["services"]
            self.assertEqual(
                {service["image"] for service in services.values()}, {IMAGE}
            )
            self.assertEqual(
                {service["user"] for service in services.values()}, {"0:0"}
            )
            self.assertEqual(services["xray"]["network_mode"], "host")
            self.assertEqual(services["client"]["network_mode"], "host")
            self.assertNotIn("network_mode", services["ny"])
            self.assertIn(
                f"{fixture.config_path}:/etc/xray/config.json:ro",
                services["xray"]["volumes"],
            )
            self.assertEqual(
                services["xray"]["environment"]["SSL_CERT_FILE"], "/work/cert.pem"
            )
            for binding in services["ny"]["ports"]:
                self.assertTrue(binding.startswith("127.0.0.1:"))
            ny = app_files.load_json(fixture.root / "ny.json")
            self.assertEqual(
                [inbound["streamSettings"]["security"] for inbound in ny["inbounds"]],
                ["reality", "tls"],
            )
            self.assertEqual(
                [inbound["streamSettings"]["network"] for inbound in ny["inbounds"]],
                ["tcp", "xhttp"],
            )
            self.assertNotIn("api", ny)
            self.assertFalse(
                state["upstreams"]["ny-tls"]["security"]["settings"]["allow_insecure"]
            )
            for path in fixture.root.iterdir():
                self.assertTrue(path.is_file(), path.name)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

    def _config_fixture(self, directory):
        fixture = StabilizationFixture.__new__(StabilizationFixture)
        fixture.root = Path(directory)
        fixture.project = "xray-stabilization-unit"
        fixture.compose_file = fixture.root / "compose.json"
        fixture.config_path = fixture.root / "gateway.json"
        fixture.state_path = fixture.root / "state.json"
        (
            fixture.gateway_port,
            fixture.ny_tcp_port,
            fixture.ny_tls_port,
            fixture.socks_port,
        ) = range(24443, 24447)
        fixture.proxy = SimpleNamespace(port=24447)
        fixture.reality_target = "origin.example.test:24448"
        return fixture

    def test_fixture_trust_override_changes_only_tls_flag_and_restores_renderer(self):
        state = app_state_creation.create_state(
            "127.0.0.1",
            "origin.example.test:24448",
            "fixture.test",
            24443,
            ["fixture"],
            None,
        )
        profile = state["profiles"][0]
        reality = vpn_transports.parse_link(
            app_exports_links.generate_vless_link(profile["clients"][0], state, profile)
        )
        tls = vpn_transports.parse_link(
            f"vless://{profile['clients'][0]['id']}@127.0.0.1:24445"
            "?security=tls&type=xhttp&sni=origin.example.test&path=%2Fstabilization&mode=stream-one"
        )
        inputs = copy.deepcopy((reality, tls))
        renderer = vpn_transports.render_outbound
        baseline_reality = renderer(reality, "ny-primary")
        baseline_tls = renderer(tls, "ny-tls")
        expected_tls = copy.deepcopy(baseline_tls)
        expected_tls["streamSettings"]["tlsSettings"]["useSystemCA"] = True
        state["upstreams"] = {"ny-tls": tls}
        state["routing_policies"]["ny-tls"] = {
            "type": "upstream",
            "upstreams": ["ny-tls"],
        }
        profile.update(route="ny-tls", outbound_mode="proxy")
        baseline_config = app_xray_rendering.render_config(state)
        expected_config = copy.deepcopy(baseline_config)
        next(
            outbound
            for outbound in expected_config["outbounds"]
            if outbound["tag"] == "ny-tls"
        )["streamSettings"]["tlsSettings"]["useSystemCA"] = True
        with fixture_tls_roots():
            self.assertEqual(
                vpn_transports.render_outbound(reality, "ny-primary"), baseline_reality
            )
            outbound = vpn_transports.render_outbound(tls, "ny-tls")
            self.assertEqual(outbound, expected_tls)
            self.assertIs(
                outbound["streamSettings"]["tlsSettings"]["allowInsecure"], False
            )
            self.assertEqual(app_xray_rendering.render_config(state), expected_config)
        self.assertIs(vpn_transports.render_outbound, renderer)
        self.assertEqual(renderer(tls, "ny-tls"), baseline_tls)
        self.assertEqual(app_xray_rendering.render_config(state), baseline_config)
        self.assertEqual((reality, tls), inputs)

    def test_explicit_non_linux_request_has_clear_skip_before_docker(self):
        with (
            patch("stabilization_fixture.platform.system", return_value="Darwin"),
            patch("stabilization_fixture.command") as docker,
        ):
            with self.assertRaisesRegex(
                unittest.SkipTest, "Linux host.*host networking"
            ):
                require_runtime()
            docker.assert_not_called()

    def test_linux_official_image_pull_failure_is_error_without_fallback(self):
        def docker(args, timeout=45):
            if args[1:3] == ["context", "inspect"]:
                output = [
                    {"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}
                ]
            elif args[1] == "info":
                output = {"OSType": "linux", "OperatingSystem": "Linux"}
            elif args[1:3] == ["image", "inspect"] or args[1] == "pull":
                raise subprocess.CalledProcessError(1, args, stderr="GHCR 403")
            else:
                return subprocess.CompletedProcess(args, 0, stdout="Docker Compose v2")
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(output))

        with (
            patch("stabilization_fixture.platform.system", return_value="Linux"),
            patch("stabilization_fixture.shutil.which", return_value="/usr/bin/docker"),
            patch.dict(os.environ, {"DOCKER_HOST": "unix:///var/run/docker.sock"}),
            patch("stabilization_fixture.command", side_effect=docker) as calls,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "official image.*no fallback.*GHCR 403"
            ):
                require_runtime()
        pulls = [
            call.args[0] for call in calls.call_args_list if call.args[0][1] == "pull"
        ]
        self.assertEqual(pulls, [["docker", "pull", IMAGE]])

    def test_fault_proxy_closes_live_primary_and_recovers_without_docker(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    while True:
                        data = self.request.recv(1024)
                        if not data:
                            return
                        self.request.sendall(data)
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), Echo)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        proxy = FaultProxy(server.server_address)
        self.addCleanup(proxy.close)
        with socket.create_connection(
            ("127.0.0.1", proxy.port), timeout=2
        ) as connection:
            connection.sendall(b"before")
            self.assertEqual(StabilizationFixture.read_exact(connection, 6), b"before")
            proxy.set_enabled(False)
            self.assertEqual(connection.recv(1), b"")
        with socket.create_connection(
            ("127.0.0.1", proxy.port), timeout=2
        ) as connection:
            self.assertEqual(connection.recv(1), b"")
        proxy.set_enabled(True)
        with socket.create_connection(
            ("127.0.0.1", proxy.port), timeout=2
        ) as connection:
            connection.sendall(b"after")
            self.assertEqual(StabilizationFixture.read_exact(connection, 5), b"after")


@unittest.skipUnless(
    os.environ.get("XRAY_INTEGRATION") == "1",
    "set XRAY_INTEGRATION=1 for local Linux stabilization integration tests",
)
class StabilizationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_runtime()

    def setUp(self):
        self.fixture = StabilizationFixture(self)

    def assert_private_files(self):
        for path in self.fixture.root.iterdir():
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

    def assert_selected(self, state, selected):
        self.assertEqual(
            state["routing_policies"]["foreign"].get("current_upstream"), selected
        )
        deployed = app_files.load_json(self.fixture.config_path)
        rules = [
            rule
            for rule in deployed["routing"]["rules"]
            if app_state_model.profile_tag(state["profiles"][0]) in rule["inboundTag"]
        ]
        self.assertEqual([rule["outboundTag"] for rule in rules], [selected or "block"])
        self.assertNotIn(
            "freedom", [outbound["protocol"] for outbound in deployed["outbounds"]]
        )

    def test_real_transfers_polling_restart_checkpoint_epoch_and_quota_cutoff(self):
        first, epoch = self._initial_usage()
        restarted, next_epoch = self._restart_with_unpolled_usage(first, epoch)
        after_transfer = self._new_epoch_traffic(restarted, next_epoch)
        self._quota_cutoff(after_transfer, next_epoch)

    def _initial_usage(self):
        fixture = self.fixture
        fixture.assert_traffic_route("ny-primary")
        first = fixture.settled_usage(minimum_downlink=len(BODY))
        usage = fixture.usage(first)
        epoch = app_xray_runtime.runtime_epoch(fixture.compose_file)
        self.assertEqual(first["accounting"]["epoch"], epoch)
        email = first["profiles"][0]["clients"][0]["email"]
        checkpoint = first["accounting"]["checkpoints"][email]
        self.assertGreaterEqual(checkpoint["downlink"], len(BODY))
        for _ in range(2):
            repeated = fixture.cli("usage", "--refresh")
            self.assertEqual(
                fixture.usage(repeated), usage, "repeated polling counted traffic twice"
            )
            self.assertEqual(repeated["accounting"], first["accounting"])

        return first, epoch

    def _restart_with_unpolled_usage(self, first, epoch):
        fixture = self.fixture
        usage = fixture.usage(first)
        email = first["profiles"][0]["clients"][0]["email"]
        checkpoint = first["accounting"]["checkpoints"][email]
        fixture.transfer()
        raw = app_accounting.collect_usage_deltas(
            app_xray_runtime.query_xray_stats(
                fixture.compose_file, reset=False, state=fixture.state()
            )
        )[email]
        self.assertGreaterEqual(raw["downlink"] - checkpoint["downlink"], len(BODY))
        restarted = fixture.cli("restart")
        next_epoch = app_xray_runtime.runtime_epoch(fixture.compose_file)
        self.assertNotEqual(
            epoch, next_epoch, "restart did not create a new gateway epoch"
        )
        self.assertEqual(
            restarted["accounting"]["epoch"],
            epoch,
            "restart must retain the final pre-restart checkpoint",
        )
        self.assertGreaterEqual(
            restarted["accounting"]["checkpoints"][email]["downlink"], raw["downlink"]
        )
        self.assertGreaterEqual(
            fixture.usage(restarted)[1] - usage[1],
            len(BODY),
            "restart lost traffic not previously polled",
        )
        return restarted, next_epoch

    def _new_epoch_traffic(self, restarted, next_epoch):
        fixture = self.fixture
        after_restart = fixture.settled_usage(
            minimum_downlink=fixture.usage(restarted)[1]
        )
        self.assertEqual(after_restart["accounting"]["epoch"], next_epoch)
        self.assertEqual(
            fixture.usage(after_restart),
            fixture.usage(restarted),
            "new epoch recounted the old checkpoint",
        )
        fixture.transfer()
        after_transfer = fixture.settled_usage(
            minimum_downlink=fixture.usage(after_restart)[1] + len(BODY)
        )
        self.assertGreaterEqual(
            fixture.usage(after_transfer)[1] - fixture.usage(after_restart)[1],
            len(BODY),
        )
        self.assertEqual(
            app_xray_runtime.runtime_epoch(fixture.compose_file), next_epoch
        )

        return after_transfer

    def _quota_cutoff(self, after_transfer, next_epoch):
        fixture = self.fixture
        fixture.cli(
            "quota",
            "set",
            "fixture",
            "--quota",
            str(sum(fixture.usage(after_transfer)) + len(BODY) // 2),
        )
        fixture.transfer()
        enforced = fixture.cli("quota", "enforce")
        client = enforced["profiles"][0]["clients"][0]
        self.assertFalse(client["enabled"])
        self.assertEqual(client["disabled_reason"], "quota_exceeded")
        self.assertGreaterEqual(sum(fixture.usage(enforced)), client["quota_bytes"])
        self.assertNotEqual(
            app_xray_runtime.runtime_epoch(fixture.compose_file), next_epoch
        )
        deployed = app_files.load_json(fixture.config_path)
        inbound = next(
            item for item in deployed["inbounds"] if item["protocol"] == "vless"
        )
        self.assertEqual(inbound["settings"]["clients"], [])
        fixture.assert_blocked()
        self.assert_private_files()

    def test_real_monitor_failover_both_unavailable_block_and_restore_cooldown(self):
        primary_epoch = self._initial_healthy_paths()
        self._primary_path_loss(primary_epoch)
        fallback_epoch = self._both_unavailable_and_fallback_recovery()
        self._primary_recovery_cooldown(fallback_epoch)

    def _initial_healthy_paths(self):
        fixture = self.fixture
        fixture.configure_health(cooldown=30)
        self.assert_selected(fixture.health_check(), None)
        healthy = fixture.health_check()
        self.assert_selected(healthy, "ny-primary")
        for name in ("ny-primary", "ny-tls"):
            health = healthy["health"][name]
            self.assertEqual(health["status"], "healthy")
            self.assertTrue(health["exit_ip_verified"])
            self.assertEqual(health["body_bytes"], len(BODY))
        fixture.assert_traffic_route("ny-primary")
        primary_epoch = app_xray_runtime.runtime_epoch(fixture.compose_file)

        return primary_epoch

    def _primary_path_loss(self, primary_epoch):
        fixture = self.fixture
        fixture.proxy.set_enabled(False)
        once = fixture.health_check()
        self.assert_selected(once, "ny-primary")
        self.assertEqual(once["health"]["ny-primary"]["consecutive_failures"], 1)
        self.assertEqual(
            app_xray_runtime.runtime_epoch(fixture.compose_file), primary_epoch
        )
        failed = fixture.health_check()
        self.assert_selected(failed, "ny-tls")
        self.assertEqual(failed["health"]["ny-primary"]["status"], "unhealthy")
        self.assertNotEqual(
            app_xray_runtime.runtime_epoch(fixture.compose_file), primary_epoch
        )
        fixture.assert_traffic_route("ny-tls")

    def _both_unavailable_and_fallback_recovery(self):
        fixture = self.fixture
        fixture.compose("stop", "--timeout", "3", "ny")
        fixture.health_check()
        blocked = fixture.health_check()
        self.assert_selected(blocked, None)
        self.assertTrue(
            all(
                record["status"] == "unhealthy" for record in blocked["health"].values()
            )
        )
        fixture.assert_blocked()

        fixture.compose("start", "ny")
        fixture.wait_ny()
        fixture.health_check()
        fallback = fixture.health_check()
        self.assert_selected(fallback, "ny-tls")
        fixture.assert_traffic_route("ny-tls")
        fallback_epoch = app_xray_runtime.runtime_epoch(fixture.compose_file)

        return fallback_epoch

    def _primary_recovery_cooldown(self, fallback_epoch):
        fixture = self.fixture
        fixture.proxy.set_enabled(True)
        self.assert_selected(fixture.health_check(), "ny-tls")
        restored = fixture.health_check()
        self.assertEqual(restored["health"]["ny-primary"]["status"], "healthy")
        self.assert_selected(restored, "ny-tls")
        self.assertEqual(
            app_xray_runtime.runtime_epoch(fixture.compose_file), fallback_epoch
        )
        fixture.assert_traffic_route("ny-tls")
        self._wait_restore_cooldown(restored)
        recovered = fixture.health_check()
        self.assert_selected(recovered, "ny-primary")
        self.assertNotEqual(
            app_xray_runtime.runtime_epoch(fixture.compose_file), fallback_epoch
        )
        fixture.assert_traffic_route("ny-primary")
        events = [
            (event["from"], event["to"])
            for event in recovered["route_events"]
            if event["policy"] == "foreign"
        ]
        self.assertEqual(
            events,
            [
                (None, "ny-primary"),
                ("ny-primary", "ny-tls"),
                ("ny-tls", "block"),
                (None, "ny-tls"),
                ("ny-tls", "ny-primary"),
            ],
        )
        self.assert_private_files()

    def _wait_restore_cooldown(self, restored):
        cooldown_end = restored["health"]["ny-primary"]["restored_at"] + 30
        deadline = time.monotonic() + 32
        while time.time() <= cooldown_end:
            self.assertLess(
                time.monotonic(),
                deadline,
                "restore cooldown wait exceeded its deadline",
            )
            time.sleep(min(0.2, max(0.01, cooldown_end - time.time())))


if __name__ == "__main__":
    unittest.main()
