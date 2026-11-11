from vpn_manager import errors as app_errors
from vpn_manager.cli import entrypoint as app_cli_entrypoint
from vpn_manager.cli import parser as app_cli_parser
from vpn_manager.exports import links as app_exports_links
from vpn_manager.state import migration as app_state_migration
from vpn_manager.state import storage as app_state_storage
from vpn_manager.state import validation as app_state_validation
from vpn_manager.xray import rendering as app_xray_rendering

"""Behavior snapshots use synthetic identities and never load deployment state."""

import argparse
import copy
import io
import json
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

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
        actions.append(
            {
                "options": action.option_strings,
                "dest": action.dest,
                "default": normalized(action.default),
                "required": action.required,
                "nargs": action.nargs,
                "choices": list(action.choices or []),
                "type": normalized(action.type),
            }
        )
        if isinstance(action, argparse._SubParsersAction):
            children = {
                name: parser_contract(child) for name, child in action.choices.items()
            }
    return {"help": parser.format_help(), "actions": actions, "children": children}


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class BehaviorContractTests(unittest.TestCase):
    def test_cli_help_options_defaults_and_handlers(self):
        with patch("sys.argv", ["vpnctl.py"]):
            parser = app_cli_parser.build_parser()
        self.assertEqual(parser_contract(parser), fixture("cli_contract.json"))

    def test_render_and_link_contract(self):
        state = fixture("synthetic_state.json")
        self.assertEqual(
            app_xray_rendering.render_config(state), fixture("config_contract.json")
        )
        profile = state["profiles"][0]
        link = app_exports_links.generate_vless_link(
            profile["clients"][0], state, profile
        )
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
        self.assertEqual(app_state_migration.migrate_legacy_state(legacy), state)

    def test_invalid_route_has_stable_safe_error(self):
        state = fixture("synthetic_state.json")
        state["profiles"][0]["route"] = "missing"
        with self.assertRaisesRegex(
            app_errors.VpnctlError, "^profile references an unknown policy$"
        ):
            app_state_validation.validate_state(state)

    def test_argument_error_exit_and_application_error_exit(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                app_cli_entrypoint.main(["--unknown"])
            self.assertEqual(raised.exception.code, 2)
            with patch.object(
                app_state_storage,
                "load_state",
                side_effect=app_errors.VpnctlError("fixture"),
            ):
                self.assertEqual(
                    app_cli_entrypoint.main(
                        ["inventory", "validate", "--with-runtime", "--file", "missing"]
                    ),
                    1,
                )
