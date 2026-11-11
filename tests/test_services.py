import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from vpn_manager import accounting, clock, files
from vpn_manager.errors import VpnctlError
from vpn_manager.state.storage import JsonStateStore
from vpn_manager.xray.deployment import DeploymentService
from vpn_manager.xray.runtime import ComposeRuntime, XrayStatistics


def synthetic_state():
    path = Path(__file__).parent / "fixtures" / "synthetic_state.json"
    return json.loads(path.read_text())


class UsageServiceTests(unittest.TestCase):
    def setUp(self):
        self.state = synthetic_state()
        self.stats = Mock(spec=XrayStatistics)
        self.stats.epoch.return_value = "synthetic-epoch"
        self.calendar = Mock(spec=clock.SystemCalendar)
        self.calendar.period.return_value = self.state["usage_period"]
        self.service = accounting.UsageService(self.stats, self.calendar)

    def test_injected_statistics_repeated_read_is_not_counted_twice(self):
        email = self.state["profiles"][0]["clients"][0]["email"]
        self.stats.read.return_value = {
            "stat": [
                {
                    "name": f"user>>>{email}>>>traffic>>>uplink",
                    "value": 150,
                }
            ]
        }
        self.service.sample(self.state, Path("compose.yaml"))
        self.service.sample(self.state, Path("compose.yaml"))
        self.assertEqual(
            self.state["profiles"][0]["clients"][0]["used_uplink_bytes"], 150
        )

    def test_epoch_change_preserves_state_and_exception_contract(self):
        before = copy.deepcopy(self.state)
        self.stats.epoch.side_effect = ["old", "new"]
        self.stats.read.return_value = {"stat": []}
        with self.assertRaisesRegex(VpnctlError, "restarted during statistics read"):
            self.service.sample(self.state, Path("compose.yaml"))
        self.assertEqual(self.state, before)


class DeploymentServiceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state_path = self.root / "state.json"
        self.config_path = self.root / "config.json"
        self.compose = self.root / "compose.yaml"
        self.state = synthetic_state()
        self.store = Mock(spec=JsonStateStore)
        self.store.load.return_value = copy.deepcopy(self.state)
        self.runtime = Mock(spec=ComposeRuntime)
        self.runtime.running.return_value = False
        self.service = DeploymentService(self.store, self.runtime, Mock())
        self.old_config = {
            "inbounds": [],
            "outbounds": [],
            "api": {"tag": "api"},
            "routing": {"rules": []},
        }
        files.write_json(self.config_path, self.old_config)

    def test_noop_never_calls_runtime(self):
        self.service.deploy(
            self.state, self.state_path, self.config_path, self.compose, self.old_config
        )
        self.assertEqual(self.runtime.mock_calls, [])
        self.store.save.assert_called_once_with(self.state_path, self.state)

    def test_invalid_native_candidate_preserves_config_and_state(self):
        self.runtime.validate.side_effect = VpnctlError("invalid candidate")
        candidate = dict(self.old_config, stats={})
        with self.assertRaisesRegex(VpnctlError, "invalid candidate"):
            self.service.deploy(
                self.state, self.state_path, self.config_path, self.compose, candidate
            )
        self.assertEqual(files.load_json(self.config_path), self.old_config)
        self.store.save.assert_not_called()
        self.runtime.restart.assert_not_called()
        self.assertFalse(self.config_path.with_suffix(".json.candidate").exists())
