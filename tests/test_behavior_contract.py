"""Behavior snapshots use synthetic identities and never load deployment state."""

import argparse
import copy
import io
import json
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import vpnctl


FIXTURES = Path(__file__).parent / "fixtures"


def normalized(value):
    if isinstance(value, Path):
        return str(value)
    if callable(value):
        return value.__name__
    return value


def parser_contract(parser):
    actions = []
    children = {}
    for action in parser._actions:
        actions.append({
            "options": action.option_strings, "dest": action.dest,
            "default": normalized(action.default), "required": action.required,
            "nargs": action.nargs, "choices": list(action.choices or []),
            "type": normalized(action.type),
        })
        if isinstance(action, argparse._SubParsersAction):
            children = {name: parser_contract(child) for name, child in action.choices.items()}
    return {"help": parser.format_help(), "actions": actions, "children": children}


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class BehaviorContractTests(unittest.TestCase):
    def test_cli_help_options_defaults_and_handlers(self):
        with patch("sys.argv", ["vpnctl.py"]):
            parser = vpnctl.build_parser()
        self.assertEqual(parser_contract(parser), fixture("cli_contract.json"))

    def test_render_and_link_contract(self):
        state = fixture("synthetic_state.json")
        self.assertEqual(vpnctl.render_config(state), fixture("config_contract.json"))
        profile = state["profiles"][0]
        link = vpnctl.generate_vless_link(profile["clients"][0], state, profile)
        self.assertEqual(link, fixture("link_contract.json")["link"])

    def test_v3_migration_preserves_metadata_identity_and_checkpoints(self):
        state = fixture("synthetic_state.json")
        legacy = copy.deepcopy(state)
        legacy["version"] = 3
        for field in ("node", "upstreams", "routing_policies"):
            legacy.pop(field)
        for profile in legacy["profiles"]:
            profile.pop("transport")
            profile.pop("route")
        self.assertEqual(vpnctl.migrate_legacy_state(legacy), state)

    def test_invalid_route_has_stable_safe_error(self):
        state = fixture("synthetic_state.json")
        state["profiles"][0]["route"] = "missing"
        with self.assertRaisesRegex(vpnctl.VpnctlError, "^profile references an unknown policy$"):
            vpnctl.validate_state(state)

    def test_argument_error_exit_and_application_error_exit(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                vpnctl.main(["--unknown"])
            self.assertEqual(raised.exception.code, 2)
            with patch.object(vpnctl, "load_state", side_effect=vpnctl.VpnctlError("fixture")):
                self.assertEqual(vpnctl.main(["inventory", "validate", "--with-runtime", "--file", "missing"]), 1)
