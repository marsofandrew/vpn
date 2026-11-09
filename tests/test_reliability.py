import copy
import configparser
import json
import multiprocessing
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vpnctl


def increment_state(path, ready):
    with vpnctl.state_lock(path):
        state = vpnctl.load_state(path)
        ready.set()
        state["counter"] = state.get("counter", 0) + 1
        vpnctl.save_state(path, state)


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state_path = Path(directory.name) / "state.json"
        self.config_path = Path(directory.name) / "config.json"
        self.compose = Path(directory.name) / "compose.yaml"
        self.state = vpnctl.create_state("vpn.example.com", "example.com:443", "example.com",
                                         8443, ["phone"], 1000)
        vpnctl.save_state(self.state_path, self.state)
        self.config = vpnctl.render_config(self.state)
        vpnctl.write_json(self.config_path, self.config)

    def client(self, state=None):
        return (state or self.state)["profiles"][0]["clients"][0]

    def snapshot(self, uplink, downlink=0, epoch="first"):
        vpnctl.apply_usage_snapshot(self.state,
                                   {self.client()["email"]: {"uplink": uplink, "downlink": downlink}}, epoch)

    def test_atomic_replace_failure_preserves_destination_and_cleans_temp(self):
        with patch.object(vpnctl.os, "replace", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                vpnctl.write_json(self.config_path, {"broken": True})
        self.assertEqual(vpnctl.load_json(self.config_path), self.config)
        self.assertEqual(list(self.config_path.parent.glob(".config.json.*")), [])

    def test_files_and_backup_are_private_and_valid(self):
        self.state["counter"] = 1
        vpnctl.save_state(self.state_path, self.state)
        for path in [self.state_path, vpnctl.backup_path(self.state_path), self.config_path]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("counter", vpnctl.load_json(vpnctl.backup_path(self.state_path)))

    def test_corrupt_and_missing_state_recover_backup(self):
        vpnctl.save_state(self.state_path, self.state)
        self.state_path.write_text("{interrupted")
        self.assertEqual(vpnctl.load_state(self.state_path)["profiles"], self.state["profiles"])
        self.state_path.unlink()
        self.assertEqual(vpnctl.load_state(self.state_path)["profiles"], self.state["profiles"])

    def test_invalid_primary_and_backup_are_rejected(self):
        self.state_path.write_text("{}")
        vpnctl.write_json(vpnctl.backup_path(self.state_path), {})
        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.load_state(self.state_path)

    def test_lock_serializes_process_updates(self):
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        processes = [context.Process(target=increment_state, args=(self.state_path, ready)) for _ in range(4)]
        with vpnctl.state_lock(self.state_path):
            for process in processes:
                process.start()
            self.assertFalse(ready.wait(0.3))
        for process in processes:
            process.join(10)
            if process.is_alive():
                process.terminate()
                self.fail("lock was not released")
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(vpnctl.load_state(self.state_path)["counter"], 4)

    def test_installed_quota_service_runs_as_installing_operator(self):
        installer = (Path(__file__).resolve().parents[1] / "scripts" / "install-host.sh").read_text()
        user_assignment = next(line for line in installer.splitlines() if line.startswith("INSTALL_USER="))
        service_template = installer.split('<<SERVICE\n', 1)[1].split('\nSERVICE', 1)[0]
        for sudo_user, login_user in [("vpn-operator", "root"), (None, "vpn-operator")]:
            with self.subTest(sudo_user=sudo_user):
                environment = dict(os.environ, USER=login_user, SERVICE_NAME="vpnctl-quota",
                                   REPO_DIR=str(self.state_path.parent), PYTHON_BIN="/usr/bin/python3")
                environment.pop("SUDO_USER", None)
                if sudo_user is not None:
                    environment["SUDO_USER"] = sudo_user
                rendered = subprocess.run(
                    ["/bin/bash"], input=f"{user_assignment}\ncat <<SERVICE\n{service_template}\nSERVICE\n",
                    env=environment, check=True, capture_output=True, text=True,
                )
                unit = configparser.ConfigParser(interpolation=None)
                unit.read_string(rendered.stdout)
                self.assertEqual(unit["Service"].get("User"), "vpn-operator")
                self.assertIn("docker", unit["Service"].get("SupplementaryGroups", "").split())

    def test_repeated_snapshot_and_normal_process_crash_do_not_double_count(self):
        self.snapshot(100, 200)
        vpnctl.save_state(self.state_path, self.state)
        self.snapshot(140, 250)
        self.state = vpnctl.load_state(self.state_path)
        self.snapshot(140, 250)
        self.snapshot(140, 250)
        self.assertEqual(self.client()["used_uplink_bytes"], 140)
        self.assertEqual(self.client()["used_downlink_bytes"], 250)

    def test_epoch_change_counts_even_if_new_counter_is_larger(self):
        self.snapshot(100)
        self.snapshot(250, epoch="restarted")
        self.assertEqual(self.client()["used_uplink_bytes"], 350)

    def test_decreased_counter_and_disabled_client(self):
        self.snapshot(100)
        self.client()["enabled"] = False
        self.snapshot(20)
        self.client()["enabled"] = True
        self.snapshot(30)
        self.assertEqual(self.client()["used_uplink_bytes"], 130)

    def test_rollover_and_manual_reset_keep_counter_baseline(self):
        self.snapshot(100)
        with patch.object(vpnctl, "current_usage_period", return_value="2099-02"):
            vpnctl.ensure_monthly_period(self.state)
        self.snapshot(130)
        self.assertEqual(self.client()["used_uplink_bytes"], 30)
        self.client()["used_uplink_bytes"] = 0
        self.snapshot(140)
        self.assertEqual(self.client()["used_uplink_bytes"], 10)

    def test_restart_during_poll_leaves_checkpoint_unchanged(self):
        previous = copy.deepcopy(self.state)
        with patch.object(vpnctl, "runtime_epoch", side_effect=["old", "new"]), \
                patch.object(vpnctl, "query_xray_stats", return_value={"stat": []}) as query:
            with self.assertRaises(vpnctl.VpnctlError):
                vpnctl.sample_usage(self.state, self.compose)
            self.assertFalse(query.call_args.kwargs["reset"])
        self.assertEqual(self.state, previous)

    def deploy(self, candidate=None, force=False):
        vpnctl.deploy_config(self.state, self.state_path, self.config_path, self.compose,
                             candidate or vpnctl.render_config(self.state), force=force)

    def test_unchanged_configuration_skips_native_validation_and_restart(self):
        self.client()["quota_bytes"] = 2000
        with patch.object(vpnctl, "run_compose") as compose:
            self.deploy()
            compose.assert_not_called()

    def test_native_rejection_preserves_config_and_state(self):
        previous = self.state_path.read_bytes()
        self.client()["enabled"] = False
        with patch.object(vpnctl, "validate_native", side_effect=vpnctl.VpnctlError("invalid")), \
                patch.object(vpnctl, "restart_xray") as restart:
            with self.assertRaises(vpnctl.VpnctlError):
                self.deploy()
            restart.assert_not_called()
        self.assertEqual(self.state_path.read_bytes(), previous)
        self.assertEqual(vpnctl.load_json(self.config_path), self.config)

    def test_health_failure_rolls_back_config_and_state(self):
        self.client()["enabled"] = False
        with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="")), \
                patch.object(vpnctl, "validate_native"), \
                patch.object(vpnctl, "restart_xray") as restart, \
                patch.object(vpnctl, "verify_xray", side_effect=[vpnctl.VpnctlError("unhealthy"), None]):
            with self.assertRaisesRegex(vpnctl.VpnctlError, "restored"):
                self.deploy()
            self.assertEqual(restart.call_count, 2)
        self.assertEqual(vpnctl.load_json(self.config_path), self.config)
        self.assertTrue(self.client(vpnctl.load_state(self.state_path))["enabled"])
        self.assertFalse(vpnctl.journal_path(self.state_path).exists())

    def test_pre_restart_poll_does_not_double_count_already_observed_traffic(self):
        self.snapshot(100)
        self.client()["enabled"] = False
        email = self.client()["email"]

        def sample(state, compose):
            vpnctl.apply_usage_snapshot(state, {email: {"uplink": 120, "downlink": 0}}, "first")

        with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="running")), \
                patch.object(vpnctl, "sample_usage", side_effect=sample), \
                patch.object(vpnctl, "validate_native"), patch.object(vpnctl, "restart_xray"), \
                patch.object(vpnctl, "verify_xray"):
            self.deploy()
        self.assertEqual(self.client(vpnctl.load_state(self.state_path))["used_uplink_bytes"], 120)

    def test_rollover_deployment_rollback_preserves_observed_new_month_usage(self):
        self.state["usage_period"] = "2099-01"
        self.snapshot(100, 200)
        self.client().update(quota_bytes=100, enabled=False, disabled_reason="quota_exceeded")
        vpnctl.save_state(self.state_path, self.state)
        previous_config = vpnctl.render_config(self.state)
        vpnctl.write_json(self.config_path, previous_config)
        email = self.client()["email"]
        stats = {"stat": [
            {"name": f"user>>>{email}>>>traffic>>>uplink", "value": 120},
            {"name": f"user>>>{email}>>>traffic>>>downlink", "value": 230},
        ]}
        args = vpnctl.build_parser().parse_args([
            "--state", str(self.state_path), "--config", str(self.config_path),
            "--compose-file", str(self.compose), "quota", "enforce",
        ])
        with patch.object(vpnctl, "current_usage_period", return_value="2099-02"), \
                patch.object(vpnctl, "runtime_epoch", return_value="first"), \
                patch.object(vpnctl, "query_xray_stats", return_value=stats), \
                patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="running")), \
                patch.object(vpnctl, "validate_native"), patch.object(vpnctl, "restart_xray") as restart, \
                patch.object(vpnctl, "verify_xray", side_effect=[vpnctl.VpnctlError("unhealthy"), None]):
            with self.assertRaisesRegex(vpnctl.VpnctlError, "restored"):
                vpnctl.command_quota_enforce(args)
            self.assertEqual(restart.call_count, 2)
            restored = vpnctl.load_state(self.state_path)
            self.assertEqual(restored["usage_period"], "2099-02")
            self.assertEqual(self.client(restored)["used_uplink_bytes"], 20)
            self.assertEqual(self.client(restored)["used_downlink_bytes"], 30)
            self.assertFalse(vpnctl.ensure_monthly_period(restored))
        self.assertEqual(vpnctl.load_json(self.config_path), previous_config)
        self.assertFalse(vpnctl.journal_path(self.state_path).exists())
        self.assertEqual(restored["accounting"]["checkpoints"][email], {"uplink": 120, "downlink": 230})
        next_stats = {"stat": [
            {"name": f"user>>>{email}>>>traffic>>>uplink", "value": 5},
            {"name": f"user>>>{email}>>>traffic>>>downlink", "value": 7},
        ]}
        with patch.object(vpnctl, "current_usage_period", return_value="2099-02"), \
                patch.object(vpnctl, "runtime_epoch", return_value="rollback-process"), \
                patch.object(vpnctl, "query_xray_stats", return_value=next_stats):
            vpnctl.sample_usage(restored, self.compose)
            vpnctl.sample_usage(restored, self.compose)
        self.assertEqual(self.client(restored)["used_uplink_bytes"], 25)
        self.assertEqual(self.client(restored)["used_downlink_bytes"], 37)

    def test_rollback_failure_retains_journal_for_recovery(self):
        self.client()["enabled"] = False
        with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="")), \
                patch.object(vpnctl, "validate_native"), patch.object(vpnctl, "restart_xray"), \
                patch.object(vpnctl, "verify_xray", side_effect=vpnctl.VpnctlError("unhealthy")):
            with self.assertRaisesRegex(vpnctl.VpnctlError, "journal retained"):
                self.deploy()
        self.assertTrue(vpnctl.journal_path(self.state_path).exists())

    def test_explicit_restart_can_recover_an_unresponsive_statistics_api(self):
        self.client()["enabled"] = False
        with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="running")), \
                patch.object(vpnctl, "sample_usage", side_effect=vpnctl.VpnctlError("API unavailable")), \
                patch.object(vpnctl, "validate_native"), patch.object(vpnctl, "restart_xray") as restart, \
                patch.object(vpnctl, "verify_xray"):
            with self.assertRaisesRegex(vpnctl.VpnctlError, "API unavailable"):
                self.deploy()
            restart.assert_not_called()
            self.deploy(force=True)
            restart.assert_called_once()

    def test_explicit_restart_repairs_corrupt_config_with_or_without_backup(self):
        self.client()["enabled"] = False
        candidate = vpnctl.render_config(self.state)
        for has_backup in [True, False]:
            with self.subTest(has_backup=has_backup):
                self.config_path.write_text("{interrupted")
                backup = vpnctl.backup_path(self.config_path)
                backup.unlink(missing_ok=True)
                if has_backup:
                    vpnctl.write_json(backup, self.config)
                with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="")), \
                        patch.object(vpnctl, "validate_native") as validate, \
                        patch.object(vpnctl, "restart_xray") as restart, \
                        patch.object(vpnctl, "verify_xray") as verify:
                    self.deploy(force=True)
                    validate.assert_called_once()
                    restart.assert_called_once()
                    verify.assert_called_once_with(self.compose, candidate)
                self.assertEqual(vpnctl.load_json(self.config_path), candidate)
                self.assertFalse(self.client(vpnctl.load_state(self.state_path))["enabled"])
                self.assertFalse(vpnctl.journal_path(self.state_path).exists())
                if has_backup:
                    self.assertEqual(vpnctl.load_json(backup), self.config)

    def test_corrupt_config_recovery_rolls_back_to_backup_or_stops_without_one(self):
        self.client()["enabled"] = False
        for has_backup in [True, False]:
            with self.subTest(has_backup=has_backup):
                self.config_path.write_text("{interrupted")
                backup = vpnctl.backup_path(self.config_path)
                backup.unlink(missing_ok=True)
                if has_backup:
                    vpnctl.write_json(backup, self.config)
                with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="")) as compose, \
                        patch.object(vpnctl, "validate_native"), \
                        patch.object(vpnctl, "restart_xray") as restart, \
                        patch.object(vpnctl, "verify_xray", side_effect=[vpnctl.VpnctlError("unhealthy"), None]):
                    with self.assertRaisesRegex(vpnctl.VpnctlError, "restored"):
                        self.deploy(force=True)
                    if has_backup:
                        self.assertEqual(vpnctl.load_json(self.config_path), self.config)
                        self.assertEqual(restart.call_count, 2)
                    else:
                        self.assertFalse(self.config_path.exists())
                        restart.assert_called_once()
                        compose.assert_any_call(self.compose, ["stop", vpnctl.XRAY_SERVICE], capture=True)
                self.assertTrue(self.client(vpnctl.load_state(self.state_path))["enabled"])
                self.assertFalse(vpnctl.journal_path(self.state_path).exists())

    def test_automatic_deployment_rejects_corrupt_config_without_using_backup(self):
        self.config_path.write_text("{interrupted")
        vpnctl.write_json(vpnctl.backup_path(self.config_path), self.config)
        previous_state = self.state_path.read_bytes()
        with patch.object(vpnctl, "validate_native") as validate, \
                patch.object(vpnctl, "restart_xray") as restart:
            with self.assertRaises(json.JSONDecodeError):
                self.deploy()
            validate.assert_not_called()
            restart.assert_not_called()
        self.assertEqual(self.config_path.read_text(), "{interrupted")
        self.assertEqual(self.state_path.read_bytes(), previous_state)
        self.assertFalse(vpnctl.journal_path(self.state_path).exists())

    def test_interrupted_deployment_is_recovered_before_next_command(self):
        vpnctl.write_json(vpnctl.journal_path(self.state_path), {"state": self.state, "config": self.config})
        vpnctl.write_json(self.config_path, {"interrupted": True})
        with patch.object(vpnctl, "restart_xray"), patch.object(vpnctl, "verify_xray"):
            vpnctl.recover_deployment(self.state_path, self.config_path, self.compose)
        self.assertEqual(vpnctl.load_json(self.config_path), self.config)
        self.assertFalse(vpnctl.journal_path(self.state_path).exists())

    def test_invalid_references_and_duplicate_tags_are_rejected(self):
        config = copy.deepcopy(self.config)
        config["routing"]["rules"][1]["outboundTag"] = "missing"
        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.validate_config(config)
        config = copy.deepcopy(self.config)
        config["inbounds"].append(config["inbounds"][0])
        with self.assertRaises(vpnctl.VpnctlError):
            vpnctl.validate_config(config)

    def test_offline_change_does_not_replace_active_configuration(self):
        self.client()["enabled"] = False
        vpnctl.persist_state_and_config(self.state, self.state_path, self.config_path)
        self.assertEqual(vpnctl.load_json(self.config_path), self.config)
        pending = self.config_path.with_name("config.json.pending")
        self.assertEqual(vpnctl.load_json(pending)["inbounds"][0]["settings"]["clients"], [])
