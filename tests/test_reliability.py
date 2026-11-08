import copy
import multiprocessing
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

    def test_rollback_failure_retains_journal_for_recovery(self):
        self.client()["enabled"] = False
        with patch.object(vpnctl, "run_compose", return_value=subprocess.CompletedProcess([], 0, stdout="")), \
                patch.object(vpnctl, "validate_native"), patch.object(vpnctl, "restart_xray"), \
                patch.object(vpnctl, "verify_xray", side_effect=vpnctl.VpnctlError("unhealthy")):
            with self.assertRaisesRegex(vpnctl.VpnctlError, "journal retained"):
                self.deploy()
        self.assertTrue(vpnctl.journal_path(self.state_path).exists())

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
