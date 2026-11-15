import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from vpn_manager.cli import entrypoint, parser
from vpn_manager.clock import current_usage_period
from vpn_manager.errors import VpnctlError
from vpn_manager.exports import links
from vpn_manager.files import write_json
from vpn_manager.state.storage import save_state
from vpn_manager.transports.links import parse_link
from vpn_manager.transports.rendering import render_outbound
from vpn_manager.xray import runtime


def synthetic_state():
    path = Path(__file__).parent / "fixtures/synthetic_state.json"
    state = json.loads(path.read_text())
    state["usage_period"] = current_usage_period()
    return state


def configure_tls(profile):
    profile["transport"] = {
        "type": "xhttp",
        "settings": {"path": "/test", "mode": "auto"},
    }
    profile["security"] = {
        "type": "tls",
        "settings": {
            "server_name": "cdn.example.invalid",
            "certificates": [{"certificateFile": "/cert.pem", "keyFile": "/key.pem"}],
        },
    }


class LinkFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.state = synthetic_state()
        self.profile = self.state["profiles"][0]
        self.client = self.profile["clients"][0]

    def link(self, **options):
        return links.generate_vless_link(
            self.client, self.state, self.profile, **options
        )

    def test_override_changes_only_fp_and_preserves_all_input(self):
        before = copy.deepcopy(self.state)
        original = urlsplit(self.link())
        exported = urlsplit(self.link(fingerprint="safari"))
        expected = parse_qs(original.query)
        expected["fp"] = ["safari"]
        self.assertEqual(parse_qs(exported.query), expected)
        self.assertEqual(exported._replace(query=""), original._replace(query=""))
        self.assertEqual(self.state, before)
        self.assertEqual(parse_qs(urlsplit(self.link()).query)["fp"], ["chrome"])

    def test_omitted_override_preserves_custom_state_default(self):
        self.state["fingerprint"] = "firefox"
        self.assertEqual(parse_qs(urlsplit(self.link()).query)["fp"], ["firefox"])
        self.assertEqual(
            parse_qs(urlsplit(self.link(fingerprint="safari")).query)["fp"], ["safari"]
        )
        self.assertEqual(self.state["fingerprint"], "firefox")

    def test_tcp_and_xhttp_reality_overrides_round_trip_to_native_settings(self):
        for network in ("tcp", "xhttp"):
            settings = (
                {} if network == "tcp" else {"path": "/test", "mode": "stream-one"}
            )
            self.profile["transport"] = {"type": network, "settings": settings}
            for fingerprint in ("safari", "firefox", "Chrome"):
                with self.subTest(network=network, fingerprint=fingerprint):
                    upstream = parse_link(self.link(fingerprint=fingerprint))
                    native = render_outbound(upstream, "exit")
                    self.assertEqual(
                        native["streamSettings"]["realitySettings"]["fingerprint"],
                        fingerprint.lower(),
                    )

    def test_invalid_override_raises_safe_error_without_mutation(self):
        before = copy.deepcopy(self.state)
        for value in (
            "",
            "unsafe",
            "hellogolang",
            "SECRET-CREDENTIAL",
            "safari&pbk=SECRET-CREDENTIAL",
        ):
            with self.subTest(kind=value):
                with self.assertRaises(VpnctlError) as caught:
                    self.link(fingerprint=value)
                self.assertNotIn("SECRET-CREDENTIAL", str(caught.exception))
        self.assertEqual(self.state, before)

    def test_tls_override_is_rejected_and_default_tls_link_is_unchanged(self):
        configure_tls(self.profile)
        before = copy.deepcopy(self.state)
        original = self.link()
        with self.assertRaisesRegex(
            VpnctlError, "fingerprint overrides require REALITY"
        ):
            self.link(fingerprint="safari")
        self.assertEqual(self.link(), original)
        self.assertNotIn("fp", parse_qs(urlsplit(original).query))
        self.assertEqual(self.state, before)


class LinkFingerprintCliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.state_path, self.config_path = (
            self.root / "state.json",
            self.root / "config.json",
        )
        self.state = synthetic_state()
        save_state(self.state_path, self.state)
        self.config_path.write_text('{"existing": true}\n')
        self.common = [
            "--state",
            str(self.state_path),
            "--config",
            str(self.config_path),
            "link",
            "fixture",
        ]

    def invoke(self, *options):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = entrypoint.main([*self.common, *options])
        return code, output.getvalue(), errors.getvalue()

    def test_parser_preserves_default_and_accepts_both_flag_names(self):
        for options, expected in (
            ([], None),
            (["--fingerprint", "safari"], "safari"),
            (["--fp", "firefox"], "firefox"),
        ):
            with self.subTest(options=options):
                args = parser.build_parser().parse_args(["link", "fixture", *options])
                self.assertEqual(args.fingerprint, expected)

    def test_cli_export_is_temporary_and_does_not_touch_state_config_or_runtime(self):
        before = (self.state_path.read_bytes(), self.config_path.read_bytes())
        with patch.object(
            runtime,
            "run_compose",
            side_effect=AssertionError("runtime must not be called"),
        ):
            code, output, error = self.invoke("--fingerprint", "safari")
            self.assertEqual((code, error), (0, ""))
            self.assertEqual(parse_qs(urlsplit(output.strip()).query)["fp"], ["safari"])
            code, output, error = self.invoke()
            self.assertEqual((code, error), (0, ""))
            self.assertEqual(parse_qs(urlsplit(output.strip()).query)["fp"], ["chrome"])
        self.assertEqual(
            (self.state_path.read_bytes(), self.config_path.read_bytes()), before
        )

    def test_qr_receives_the_same_overridden_link_that_is_printed(self):
        with patch.object(
            links, "write_qr", return_value=self.root / "fixture.png"
        ) as qr:
            code, output, error = self.invoke("--fp", "safari", "--qr")
        self.assertEqual((code, error), (0, ""))
        printed = output.splitlines()[0]
        self.assertEqual(qr.call_args.args[0], printed)
        self.assertEqual(parse_qs(urlsplit(printed).query)["fp"], ["safari"])

    def test_invalid_override_does_not_roll_usage_or_write_pending_config(self):
        self.state["usage_period"] = "2000-01"
        write_json(self.state_path, self.state)
        before = (self.state_path.read_bytes(), self.config_path.read_bytes())
        code, output, error = self.invoke("--fingerprint", "SECRET-CREDENTIAL")
        self.assertEqual((code, output), (1, ""))
        self.assertNotIn("SECRET-CREDENTIAL", error)
        self.assertIn("fingerprint is unsupported", error)
        self.assertEqual(
            (self.state_path.read_bytes(), self.config_path.read_bytes()), before
        )
        self.assertFalse(self.config_path.with_name("config.json.pending").exists())

    def test_cli_rejects_tls_override_without_printing_a_link(self):
        configure_tls(self.state["profiles"][0])
        save_state(self.state_path, self.state)
        code, output, error = self.invoke("--fp", "safari")
        self.assertEqual((code, output), (1, ""))
        self.assertIn("fingerprint overrides require REALITY", error)
