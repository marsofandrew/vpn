"""All network, Docker, transport, and health operations are mocked."""

import copy
import importlib
import json
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_manager.health import monitor


class MonitorTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.compose_file = self.directory / "compose.yaml"
        self.upstream = {"address": "exit.example", "uuid": "SECRET-CREDENTIAL"}
        self.settings = {
            "download_url": "https://download.example/sample",
            "egress_url": "https://egress.example/ip",
            "expected_exit_ips": ["203.0.113.7"],
        }
        self.transport = types.ModuleType("vpn_transports")
        self.transport.PINNED_XRAY_VERSION = "26.10.31"
        self.outbound = {
            "tag": "probe_exit",
            "protocol": "vless",
            "settings": {"credential": "SECRET-CREDENTIAL"},
        }
        self.transport.render_outbound = Mock(return_value=self.outbound)
        self.modules_patch = patch.dict(sys.modules, {"vpn_transports": self.transport})
        self.modules_patch.start()
        self.addCleanup(self.modules_patch.stop)
        self.socket = self.mock("socket.socket")
        self.listener = self.socket.return_value.__enter__.return_value
        self.listener.getsockname.return_value = ("127.0.0.1", 45678)
        self.connect = self.mock("socket.create_connection")
        self.docker = self.mock("subprocess.run")
        self.docker.return_value = subprocess.CompletedProcess(
            [], 0, stdout="Xray 26.10.31 (Xray, Penetrates Everything.)\n", stderr=""
        )
        self.probe = self.mock("vpn_health.probe_path")
        self.health_result = {
            "success": True,
            "error": None,
            "exit_ip_verified": True,
            "latency_ms": 12.5,
        }
        self.probe.return_value = self.health_result
        self.sleep = self.mock("time.sleep")
        self.fsync = self.mock("os.fsync", wraps=monitor.os.fsync)
        self.compose_config = {"services": {"xray": {"network_mode": "host"}}}
        self.run_compose = Mock(side_effect=self.compose)
        self.names = []
        self.files = []
        self.configs = []

    def mock(self, name, **kwargs):
        patcher = patch("vpn_manager.health.monitor." + name, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def compose(self, compose_file, args, capture=False):
        self.assertEqual(compose_file, self.compose_file)
        self.assertTrue(capture)
        if args == ["config", "--format", "json"]:
            return subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(self.compose_config)
            )
        self.assertEqual(
            args[:6], ["run", "--rm", "-d", "--no-deps", "--name", args[5]]
        )
        name = args[5]
        self.assertRegex(name, r"^vpn-probe-[0-9a-f]{32}$")
        path = Path(args[7].removesuffix(":/etc/xray/probe.json:ro"))
        self.assertEqual(args[6], "-v")
        self.assertEqual(args[7], str(path) + ":/etc/xray/probe.json:ro")
        self.assertEqual(args[8:], ["xray", "run", "-config", "/etc/xray/probe.json"])
        self.assertEqual(path.parent, self.directory.resolve())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertTrue(self.fsync.called)
        self.names.append(name)
        self.files.append(path)
        self.configs.append(json.loads(path.read_text()))
        return subprocess.CompletedProcess([], 0, stdout="container-id", stderr="")

    def call(self):
        return monitor.probe_upstream(
            self.upstream,
            self.settings,
            self.compose_file,
            self.directory,
            self.run_compose,
        )

    def assert_cleaned(self):
        self.assertTrue(self.names)
        cleanup_calls = [
            call
            for call in self.docker.call_args_list
            if call.args[0][:3] == ["docker", "rm", "-f"]
        ]
        self.assertEqual(len(cleanup_calls), len(self.names))
        for call, name in zip(cleanup_calls, self.names):
            self.assertEqual(call.args, (["docker", "rm", "-f", name],))
            self.assertEqual(
                call.kwargs,
                {
                    "check": True,
                    "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL,
                    "timeout": 10,
                },
            )
        for call in self.docker.call_args_list:
            if call not in cleanup_calls:
                self.assertIn(call.args[0][2], self.names)
                self.assertEqual(
                    call.args, (["docker", "exec", call.args[0][2], "xray", "version"],)
                )
                self.assertEqual(
                    call.kwargs,
                    {
                        "check": True,
                        "capture_output": True,
                        "text": True,
                        "timeout": min(self.settings.get("timeout", 15), 10),
                    },
                )
        self.assertTrue(all(not path.exists() for path in self.files))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_success_private_config_exact_launch_and_cleanup(self):
        before = copy.deepcopy((self.upstream, self.settings))
        self.assertEqual(self.call(), self.health_result)
        self.transport.render_outbound.assert_called_once_with(
            self.upstream, "probe_exit"
        )
        self.listener.bind.assert_called_once_with(("127.0.0.1", 0))
        self.assertTrue(self.socket.return_value.__exit__.called)
        self.assertEqual(
            self.configs,
            [
                {
                    "log": {"access": "none", "loglevel": "warning"},
                    "inbounds": [
                        {
                            "tag": "probe_socks",
                            "listen": "127.0.0.1",
                            "port": 45678,
                            "protocol": "socks",
                            "settings": {"auth": "noauth", "udp": False},
                        }
                    ],
                    "outbounds": [self.outbound],
                }
            ],
        )
        self.probe.assert_called_once_with(
            "127.0.0.1",
            45678,
            self.settings["download_url"],
            self.settings["egress_url"],
            self.settings["expected_exit_ips"],
            bytes_required=131072,
            timeout=15,
        )
        self.assertEqual((self.upstream, self.settings), before)
        self.assertEqual(self.docker.call_count, 1)
        self.assert_cleaned()

    def test_ech_checks_pinned_runtime_before_any_probe_traffic(self):
        self.upstream["security"] = {
            "type": "tls",
            "settings": {"ech_config_list": "ECH-CONFIG"},
        }
        self.settings["timeout"] = 4.5

        def docker(args, **kwargs):
            if args[1] == "exec":
                self.connect.assert_not_called()
                self.probe.assert_not_called()
                self.assertTrue(self.files[-1].exists())
            else:
                self.probe.assert_called_once()
            return subprocess.CompletedProcess(args, 0, stdout="Xray 26.10.31 (Xray)\n")

        self.docker.side_effect = docker
        self.assertEqual(self.call(), self.health_result)
        self.assertEqual(self.docker.call_count, 2)
        self.assert_cleaned()

    def test_ech_runtime_mismatch_or_missing_banner_fails_closed_and_cleans_up(self):
        self.upstream["security"] = {
            "type": "tls",
            "settings": {"ech_config_list": "ECH-CONFIG"},
        }
        for banner in (
            "Xray 26.10.30 (Xray)",
            "Xray 26.10.310 (Xray)",
            "Xray 26.10.31-custom (Xray)",
            "Xray 26x10x31 (Xray)",
            "version 26.10.31",
            "Xray 126.10.31 (Xray)",
            "",
            None,
            "SECRET-CREDENTIAL",
        ):
            with self.subTest(banner=banner):
                self.docker.return_value = subprocess.CompletedProcess(
                    [], 0, stdout=banner
                )
                self.assertEqual(
                    self.call(),
                    {
                        "success": False,
                        "error": "runtime_version_mismatch",
                        "exit_ip_verified": False,
                    },
                )
                self.connect.assert_not_called()
                self.probe.assert_not_called()
                self.assert_cleaned()

    def test_ech_version_command_failure_or_timeout_cleans_up(self):
        self.upstream["security"] = {
            "type": "tls",
            "settings": {"ech_config_list": "ECH-CONFIG"},
        }
        for error in (
            subprocess.CalledProcessError(1, "docker", stderr="SECRET-CREDENTIAL"),
            subprocess.TimeoutExpired("SECRET-CREDENTIAL", 10),
            OSError("SECRET-CREDENTIAL"),
        ):
            with self.subTest(error=type(error)):

                def docker(args, **kwargs):
                    if args[1] == "exec":
                        raise error
                    return subprocess.CompletedProcess(args, 0)

                self.docker.side_effect = docker
                self.assertEqual(self.call()["error"], "runtime_version_mismatch")
                self.connect.assert_not_called()
                self.probe.assert_not_called()
                self.assert_cleaned()

    def test_ech_version_failure_survives_cleanup_failure(self):
        self.upstream["security"] = {
            "type": "tls",
            "settings": {"ech_config_list": "ECH-CONFIG"},
        }
        self.docker.side_effect = OSError("SECRET-CREDENTIAL")
        self.assertEqual(self.call()["error"], "runtime_version_mismatch")
        self.probe.assert_not_called()
        self.assert_cleaned()

    def test_empty_or_missing_ech_configuration_skips_runtime_check(self):
        for security in (
            {},
            {"type": "tls", "settings": {}},
            {"type": "tls", "settings": {"ech_config_list": ""}},
        ):
            with self.subTest(security=security):
                self.upstream["security"] = security
                self.assertEqual(self.call(), self.health_result)
                self.assertEqual(self.docker.call_count, len(self.names))
                self.assert_cleaned()

    def test_explicit_measurement_settings(self):
        self.settings.update(bytes_required=262144, timeout=4.5)
        self.assertTrue(self.call()["success"])
        self.assertEqual(
            self.probe.call_args.kwargs, {"bytes_required": 262144, "timeout": 4.5}
        )
        self.assert_cleaned()

    def test_health_failure_metrics_are_preserved_and_cleanup_runs(self):
        self.health_result.update(
            success=False,
            error="exit_ip_mismatch",
            body_bytes=131072,
            exit_ip_verified=False,
        )
        self.assertEqual(self.call(), self.health_result)
        self.assert_cleaned()

    def test_probe_exception_is_redacted_and_cleanup_runs(self):
        self.probe.side_effect = RuntimeError("SECRET-CREDENTIAL")
        self.assertEqual(
            self.call(),
            {"success": False, "error": "probe_failed", "exit_ip_verified": False},
        )
        self.assert_cleaned()

    def test_host_networking_required_before_any_setup(self):
        for network in (None, "bridge", "service:other", "HOST", 1):
            with self.subTest(network=network):
                self.compose_config["services"]["xray"] = {"network_mode": network}
                self.assertEqual(self.call()["error"], "host_network_required")
        self.run_compose.assert_called_with(
            self.compose_file, ["config", "--format", "json"], capture=True
        )
        self.transport.render_outbound.assert_not_called()
        self.socket.assert_not_called()
        self.docker.assert_not_called()
        self.probe.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_missing_host_mode_is_rejected(self):
        self.compose_config["services"]["xray"] = {}
        self.assertEqual(self.call()["error"], "host_network_required")
        self.socket.assert_not_called()

    def test_bad_compose_configuration_is_safe(self):
        for output in ("SECRET-CREDENTIAL", "null", "[]", "{}", '{"services": {}}'):
            with self.subTest(output=output):
                self.run_compose.side_effect = None
                self.run_compose.return_value = subprocess.CompletedProcess(
                    [], 0, stdout=output
                )
                self.assertEqual(self.call()["error"], "compose_config_failed")
        self.socket.assert_not_called()
        self.docker.assert_not_called()

    def test_compose_config_exception_or_nonzero_does_not_launch(self):
        self.run_compose.side_effect = RuntimeError("SECRET-CREDENTIAL")
        self.assertEqual(self.call()["error"], "compose_config_failed")
        self.run_compose.side_effect = None
        self.run_compose.return_value = subprocess.CompletedProcess(
            [], 1, stdout="SECRET-CREDENTIAL"
        )
        self.assertEqual(self.call()["error"], "compose_config_failed")
        self.socket.assert_not_called()
        self.docker.assert_not_called()

    def test_transport_failure_is_safe_and_has_no_runtime_side_effects(self):
        self.transport.render_outbound.side_effect = ValueError("SECRET-CREDENTIAL")
        self.assertEqual(self.call()["error"], "invalid_upstream")
        self.socket.assert_not_called()
        self.docker.assert_not_called()

    def test_launch_failure_still_removes_exact_named_container(self):
        def compose(compose_file, args, capture=False):
            completed = self.compose(compose_file, args, capture)
            if args[0] == "run":
                raise subprocess.CalledProcessError(1, args, stderr="SECRET-CREDENTIAL")
            return completed

        self.run_compose.side_effect = compose
        self.assertEqual(self.call()["error"], "probe_start_failed")
        self.probe.assert_not_called()
        self.assert_cleaned()

    def test_launch_nonzero_still_cleans_up(self):
        def compose(compose_file, args, capture=False):
            completed = self.compose(compose_file, args, capture)
            if args[0] == "run":
                completed.returncode = 1
            return completed

        self.run_compose.side_effect = compose
        self.assertEqual(self.call()["error"], "probe_start_failed")
        self.probe.assert_not_called()
        self.assert_cleaned()

    def test_listener_retries_until_ready(self):
        connection = self.connect.return_value
        self.connect.side_effect = [
            ConnectionRefusedError("SECRET-CREDENTIAL"),
            connection,
        ]
        self.assertTrue(self.call()["success"])
        self.assertEqual(self.connect.call_count, 2)
        self.sleep.assert_called_once()
        self.assert_cleaned()

    def test_listener_deadline_is_bounded_and_cleans_up(self):
        self.settings["timeout"] = 2
        self.mock("time.monotonic", side_effect=[100, 100, 101, 102])
        self.connect.side_effect = ConnectionRefusedError("SECRET-CREDENTIAL")
        self.assertEqual(self.call()["error"], "probe_start_timeout")
        self.connect.assert_called_once_with(("127.0.0.1", 45678), timeout=0.2)
        self.probe.assert_not_called()
        self.assert_cleaned()

    def test_large_measurement_timeout_does_not_extend_startup_past_ten_seconds(self):
        self.settings["timeout"] = 300
        self.mock("time.monotonic", side_effect=[100, 110])
        self.assertEqual(self.call()["error"], "probe_start_timeout")
        self.connect.assert_not_called()
        self.probe.assert_not_called()
        self.assert_cleaned()

    def test_invalid_timeout_fails_without_compose_or_connections(self):
        for timeout in (None, True, "15", 0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout):
                self.settings["timeout"] = timeout
                self.assertEqual(self.call()["error"], "invalid_configuration")
        self.run_compose.assert_not_called()
        self.socket.assert_not_called()

    def test_fsync_failure_removes_file_without_launch(self):
        self.fsync.side_effect = OSError("SECRET-CREDENTIAL")
        self.assertEqual(self.call()["error"], "probe_setup_failed")
        self.assertEqual(self.run_compose.call_count, 1)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.docker.assert_not_called()

    def test_cleanup_error_is_safe_and_file_is_still_removed(self):
        self.docker.side_effect = subprocess.TimeoutExpired("SECRET-CREDENTIAL", 10)
        self.assertEqual(self.call()["error"], "probe_cleanup_failed")
        self.assert_cleaned()

    def test_cleanup_failure_preserves_original_failure(self):
        self.probe.side_effect = RuntimeError("SECRET-CREDENTIAL")
        self.docker.side_effect = OSError("SECRET-CREDENTIAL")
        self.assertEqual(self.call()["error"], "probe_failed")
        self.assert_cleaned()

    def test_names_and_temporary_files_are_unique_and_existing_files_are_untouched(
        self,
    ):
        existing = self.directory / "config.json"
        existing.write_text("existing config")
        self.assertTrue(self.call()["success"])
        self.assertTrue(self.call()["success"])
        self.assertEqual(len(set(self.names)), 2)
        self.assertEqual(len(set(self.files)), 2)
        self.assertEqual(existing.read_text(), "existing config")
        existing.unlink()
        self.assert_cleaned()

    def test_import_is_passive(self):
        importlib.reload(monitor)
        self.run_compose.assert_not_called()
        self.socket.assert_not_called()
        self.connect.assert_not_called()
        self.docker.assert_not_called()
        self.probe.assert_not_called()
        self.transport.render_outbound.assert_not_called()


if __name__ == "__main__":
    unittest.main()
