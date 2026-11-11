import argparse
import copy
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_manager.cli import composition, entrypoint, parser
from vpn_manager.state.storage import JsonStateStore
from vpn_manager.xray.deployment import DeploymentService


def command_parsers(root):
    yield root
    for action in root._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                yield from command_parsers(child)


class CliDispatchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.common = [
            "--state",
            str(self.root / "state.json"),
            "--config",
            str(self.root / "config.json"),
        ]
        self.store = Mock(spec=JsonStateStore)
        self.usage = Mock()
        self.transactions = Mock(spec=DeploymentService)
        factory = patch.object(
            composition,
            "services",
            return_value=(self.store, self.usage, self.transactions),
        )
        factory.start()
        self.addCleanup(factory.stop)

    def test_all_parser_handlers_have_complete_bindings(self):
        bindings = composition.handlers(self.store, self.usage, self.transactions)
        for command in command_parsers(parser.build_parser()):
            handler = command._defaults.get("func")
            if handler is not None:
                with self.subTest(command=command.prog):
                    inspect.signature(bindings[handler]).bind(argparse.Namespace())

    def test_readonly_compose_dispatch_keeps_arguments_and_does_not_load_state(self):
        cases = (
            (["status"], ["ps"]),
            (["logs", "-f"], ["logs", "-f", "xray"]),
            (
                ["validate"],
                [
                    "run",
                    "--rm",
                    "xray",
                    "run",
                    "-test",
                    "-config",
                    "/etc/xray/config.json",
                ],
            ),
        )
        with patch.object(composition.xray_runtime, "run_compose") as compose:
            for command, expected in cases:
                self.assertEqual(entrypoint.main([*self.common, *command]), 0)
                self.assertEqual(compose.call_args.args[1], expected)
        self.store.load.assert_not_called()
        self.transactions.deploy.assert_not_called()

    def test_up_and_restart_dispatch_to_transactional_deployment(self):
        fixture = Path(__file__).parent / "fixtures/synthetic_state.json"
        state = json.loads(fixture.read_text())
        for command in ("up", "restart"):
            self.store.load.return_value = copy.deepcopy(state)
            self.assertEqual(entrypoint.main([*self.common, command]), 0)
            self.assertEqual(self.transactions.deploy.call_args.kwargs, {"force": True})
            self.assertEqual(
                self.transactions.deploy.call_args.args[0]["profiles"],
                state["profiles"],
            )
        self.assertEqual(self.transactions.deploy.call_count, 2)
