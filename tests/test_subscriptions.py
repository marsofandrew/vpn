from vpn_manager import files as atomic_files

"""Generated UUID/key fixtures and reserved addresses only; no live endpoints."""

import base64
import copy
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, unquote, urlencode, urlsplit

import vpn_subscriptions as subscriptions
import vpn_transports


def fixture_link(
    number=1,
    network="tcp",
    security="reality",
    host="gateway.example.com",
    label="",
    **changes,
):
    query = {
        "type": network,
        "security": security,
        "sni": "origin.example.com",
        "encryption": "none",
    }
    if security == "reality":
        query.update(
            pbk=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
            sid="ab12",
            fp="chrome",
            spx="/",
        )
        if network == "tcp":
            query["flow"] = "xtls-rprx-vision"
    if network == "xhttp":
        query.update(
            path="/vpn/%61?item=a+b&literal=%2B",
            host="cdn.example.com",
            mode="stream-one" if security == "reality" else "auto",
        )
    if security == "tls":
        query.update(alpn="h2,http/1.1", allowInsecure="0")
    query.update(changes)
    return (
        f"vless://{uuid.UUID(int=number)}@{host}:8443?"
        + urlencode(query, quote_via=quote)
        + ("#" + quote(label, safe="") if label else "")
    )


def decoded_links(text):
    return base64.b64decode(text, validate=True).decode("utf-8").split("\n")


class SubscriptionTests(unittest.TestCase):
    def test_add_stores_canonical_endpoint_without_touching_other_state(self):
        state = {
            "upstreams": {"server-route": {"unchanged": True}},
            "profiles": ["sentinel"],
        }
        original = copy.deepcopy(state)
        link = fixture_link(label="ignored incoming label")
        self.assertIsNone(subscriptions.add_endpoint(state, "gateway_1", "phone", link))
        self.assertEqual(
            state,
            {
                **original,
                "client_entries": {
                    "gateway_1": {
                        "client": "phone",
                        "endpoint": vpn_transports.parse_link(link),
                    },
                },
            },
        )
        endpoint = state["client_entries"]["gateway_1"]["endpoint"]
        self.assertTrue(endpoint["enabled"])
        self.assertEqual(endpoint["auth"]["id"], str(uuid.UUID(int=1)))

    def test_duplicates_across_clients_fail_without_mutation(self):
        state = {}
        subscriptions.add_endpoint(state, "Gateway", "phone", fixture_link())
        original = copy.deepcopy(state)
        for client in ("phone", "laptop"):
            with (
                self.subTest(client=client),
                self.assertRaisesRegex(ValueError, "already exists"),
            ):
                subscriptions.add_endpoint(state, "Gateway", client, fixture_link(2))
            self.assertEqual(state, original)
        subscriptions.add_endpoint(state, "gateway", "phone", fixture_link(2))
        self.assertEqual(list(state["client_entries"]), ["Gateway", "gateway"])

    def test_names_are_stable_ascii_and_never_sanitized(self):
        for name in (
            None,
            1,
            [],
            {},
            "",
            "two words",
            " entry",
            "entry ",
            "entry/name",
            "entry.name",
            "entry#label",
            "entry\n",
            "entrée",
            "東京",
        ):
            state = {}
            with self.subTest(name=name), self.assertRaises(ValueError):
                subscriptions.add_endpoint(state, name, "phone", fixture_link())
            self.assertEqual(state, {})
        for name in ("A", "gateway-1", "CDN_TLS", "0"):
            state = {}
            subscriptions.add_endpoint(state, name, "phone", fixture_link())
            self.assertEqual(list(state["client_entries"]), [name])
            self.assertEqual(
                unquote(
                    urlsplit(
                        decoded_links(subscriptions.subscription_text(state, "phone"))[
                            0
                        ]
                    ).fragment
                ),
                name,
            )

    def test_invalid_clients_and_states_are_rejected(self):
        for client in (None, 1, [], {}, "", " ", "phone\n", "phone\x00", "\ud800"):
            state = {}
            with self.subTest(client=client), self.assertRaises(ValueError):
                subscriptions.add_endpoint(state, "entry", client, fixture_link())
            self.assertEqual(state, {})
            with self.assertRaises(ValueError):
                subscriptions.subscription_text(state, client, [fixture_link()])
        for state in (
            None,
            [],
            "state",
            {"client_entries": None},
            {"client_entries": []},
        ):
            with self.subTest(state=state), self.assertRaises(ValueError):
                subscriptions.add_endpoint(state, "entry", "phone", fixture_link())
            with self.assertRaises(ValueError):
                subscriptions.remove_endpoint(state, "entry")
            with self.assertRaises(ValueError):
                subscriptions.subscription_text(state, "phone", [fixture_link()])

    def test_failed_parse_preserves_state_including_absent_mapping(self):
        valid = fixture_link()
        for link in (
            None,
            "",
            "https://example.com/subscription",
            valid + "&type=tcp",
            valid + "\n",
            valid.replace("security=reality", "security=none"),
        ):
            for state in ({}, {"client_entries": {}}):
                original = copy.deepcopy(state)
                with (
                    self.subTest(link=link, state=state),
                    self.assertRaises(ValueError),
                ):
                    subscriptions.add_endpoint(state, "entry", "phone", link)
                self.assertEqual(state, original)

    def test_remove_changes_only_requested_entry(self):
        state = {"unrelated": "preserved"}
        subscriptions.add_endpoint(state, "gateway", "phone", fixture_link())
        subscriptions.add_endpoint(
            state, "cdn", "phone", fixture_link(2, "xhttp", "tls")
        )
        retained = copy.deepcopy(state["client_entries"]["cdn"])
        self.assertIsNone(subscriptions.remove_endpoint(state, "gateway"))
        self.assertEqual(
            state, {"unrelated": "preserved", "client_entries": {"cdn": retained}}
        )
        original = copy.deepcopy(state)
        for name in ("gateway", "missing", "bad name", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                subscriptions.remove_endpoint(state, name)
            self.assertEqual(state, original)
        empty = {}
        with self.assertRaises(ValueError):
            subscriptions.remove_endpoint(empty, "missing")
        self.assertEqual(empty, {})

    def test_independent_gateway_direct_cdn_and_reality_entries_round_trip(self):
        state = {"upstreams": {"unrelated": "preserved"}}
        fixtures = {
            "gateway": fixture_link(1, host="gateway.example.com"),
            "direct": fixture_link(2, host="192.0.2.20"),
            "cdn-tls": fixture_link(3, "xhttp", "tls", host="cdn.example.com"),
            "xhttp-reality": fixture_link(4, "xhttp", "reality", host="[2001:db8::1]"),
        }
        for name, link in fixtures.items():
            subscriptions.add_endpoint(state, name, "phone", link)
        original = copy.deepcopy(state)
        encoded = subscriptions.subscription_text(state, "phone")
        urls = decoded_links(encoded)
        self.assertEqual(len(urls), 4)
        self.assertNotIn("\n", encoded)
        self.assertFalse(base64.b64decode(encoded).endswith(b"\n"))
        self.assertEqual(state, original)
        for name, url in zip(sorted(fixtures), urls):
            with self.subTest(name=name):
                endpoint = vpn_transports.parse_link(fixtures[name])
                self.assertEqual(url, vpn_transports.export_link(endpoint, name))
                self.assertEqual(vpn_transports.parse_link(url), endpoint)
                self.assertEqual(unquote(urlsplit(url).fragment), name)
        state["client_entries"]["gateway"]["endpoint"]["auth"]["id"] = str(
            uuid.UUID(int=99)
        )
        self.assertEqual(
            state["client_entries"]["direct"], original["client_entries"]["direct"]
        )
        self.assertEqual(
            state["client_entries"]["cdn-tls"], original["client_entries"]["cdn-tls"]
        )
        reversed_state = {
            "client_entries": dict(reversed(list(original["client_entries"].items())))
        }
        self.assertEqual(
            subscriptions.subscription_text(reversed_state, "phone"), encoded
        )

    def test_identical_links_under_distinct_names_remain_separate(self):
        state = {}
        for name in ("gateway", "direct"):
            subscriptions.add_endpoint(state, name, "phone", fixture_link())
        first, second = decoded_links(subscriptions.subscription_text(state, "phone"))
        self.assertNotEqual(first, second)
        self.assertEqual(
            vpn_transports.parse_link(first), vpn_transports.parse_link(second)
        )

    def test_only_enabled_matching_endpoints_are_exported(self):
        state = {}
        for name, client in (
            ("enabled", "phone"),
            ("disabled", "phone"),
            ("other", "laptop"),
        ):
            subscriptions.add_endpoint(state, name, client, fixture_link())
        state["client_entries"]["disabled"]["endpoint"]["enabled"] = False
        state["client_entries"]["other"]["endpoint"] = {"unrelated": "not inspected"}
        original = copy.deepcopy(state)
        urls = decoded_links(subscriptions.subscription_text(state, "phone"))
        self.assertEqual(
            urls,
            [
                vpn_transports.export_link(
                    state["client_entries"]["enabled"]["endpoint"], "enabled"
                )
            ],
        )
        self.assertEqual(state, original)
        state["client_entries"]["enabled"]["endpoint"]["enabled"] = False
        with self.assertRaisesRegex(ValueError, "at least one"):
            subscriptions.subscription_text(state, "phone")

    def test_missing_enabled_defaults_to_true_but_other_types_are_rejected(self):
        state = {}
        subscriptions.add_endpoint(state, "gateway", "phone", fixture_link())
        endpoint = state["client_entries"]["gateway"]["endpoint"]
        del endpoint["enabled"]
        self.assertEqual(
            len(decoded_links(subscriptions.subscription_text(state, "phone"))), 1
        )
        for value in (0, 1, "true", "false", None):
            endpoint["enabled"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                subscriptions.subscription_text(state, "phone")

    def test_invalid_entry_wrappers_and_endpoints_are_rejected(self):
        endpoint = vpn_transports.parse_link(fixture_link())
        for entry in (
            None,
            [],
            {},
            {"client": "phone"},
            {"endpoint": endpoint},
            {"client": "phone", "endpoint": endpoint, "enabled": True},
            {"client": None, "endpoint": endpoint},
            {"client": "phone", "endpoint": {}},
            {"client": "phone", "endpoint": None},
        ):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                subscriptions.subscription_text(
                    {"client_entries": {"entry": entry}}, "phone"
                )
        for name in (1, "invalid name", "ümlaut"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                subscriptions.subscription_text(
                    {
                        "client_entries": {
                            name: {"client": "phone", "endpoint": endpoint},
                        }
                    },
                    "phone",
                )

    def test_explicit_local_links_keep_order_labels_and_canonical_content(self):
        local = [
            fixture_link(8, "xhttp", "tls", label="Local + 東京 #1"),
            fixture_link(9, label="local-direct"),
        ]
        state = {}
        subscriptions.add_endpoint(state, "gateway", "phone", fixture_link())
        original_state, original_local = copy.deepcopy(state), list(local)
        urls = decoded_links(subscriptions.subscription_text(state, "phone", local))
        for provided, exported in zip(local, urls):
            self.assertEqual(
                vpn_transports.parse_link(provided), vpn_transports.parse_link(exported)
            )
            self.assertEqual(
                unquote(urlsplit(provided).fragment),
                unquote(urlsplit(exported).fragment),
            )
            self.assertEqual(
                exported,
                vpn_transports.export_link(
                    vpn_transports.parse_link(provided),
                    unquote(urlsplit(provided).fragment),
                ),
            )
        self.assertEqual(unquote(urlsplit(urls[-1]).fragment), "gateway")
        self.assertEqual(state, original_state)
        self.assertEqual(local, original_local)
        empty_state = {}
        self.assertEqual(
            len(
                decoded_links(
                    subscriptions.subscription_text(empty_state, "phone", local)
                )
            ),
            2,
        )
        self.assertEqual(empty_state, {})

    def test_empty_subscriptions_and_implicit_or_invalid_local_links_fail(self):
        for local in ((), []):
            with (
                self.subTest(local=local),
                self.assertRaisesRegex(ValueError, "at least one"),
            ):
                subscriptions.subscription_text({}, "phone", local)
        for local in (
            fixture_link(),
            None,
            {},
            {fixture_link()},
            iter([fixture_link()]),
            [None],
            ["https://example.com/subscription"],
            [fixture_link() + "\n"],
            [fixture_link(), fixture_link() + "&type=tcp"],
            [fixture_link(1, "xhttp", "tls", allowInsecure="1")],
        ):
            state = {}
            subscriptions.add_endpoint(state, "valid", "phone", fixture_link())
            original = copy.deepcopy(state)
            with self.subTest(local=local), self.assertRaises(ValueError):
                subscriptions.subscription_text(state, "phone", local)
            self.assertEqual(state, original)

    def test_errors_do_not_echo_supplied_credentials_or_names(self):
        link = fixture_link().replace(str(uuid.UUID(int=1)), "NEVER-ECHO")
        with self.assertRaises(ValueError) as raised:
            subscriptions.add_endpoint({}, "entry", "phone", link)
        self.assertNotIn("NEVER-ECHO", str(raised.exception))
        with self.assertRaises(ValueError) as raised:
            subscriptions.remove_endpoint({}, "NEVER-ECHO")
        self.assertNotIn("NEVER-ECHO", str(raised.exception))

    def test_no_runtime_import_or_third_party_dependency(self):
        root = Path(__file__).resolve().parents[1]
        code = """
import sys
sys.path.insert(0, sys.argv[1])
import vpn_subscriptions
state = {}
vpn_subscriptions.add_endpoint(state, 'fixture', 'phone', sys.argv[2])
assert vpn_subscriptions.subscription_text(state, 'phone')
assert 'vpnctl' not in sys.modules
assert 'qrcode' not in sys.modules
assert 'cryptography' not in sys.modules
"""
        subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", code, str(root), fixture_link()],
            check=True,
            capture_output=True,
            text=True,
        )


class PrivateWriteTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "subscription.txt"

    def test_private_utf8_output_replaces_existing_file_and_has_no_backups(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.path.write_text("old")
                    self.path.chmod(0o644)
                self.assertIsNone(subscriptions.private_write(self.path, "new\n東京\n"))
                self.assertEqual(self.path.read_bytes(), "new\n東京\n".encode())
                self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
                self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_same_directory_temp_is_private_and_fsynced_before_replace(self):
        events = []
        real_fsync, real_replace = os.fsync, os.replace

        def fsync(descriptor):
            mode = os.fstat(descriptor).st_mode
            events.append("directory-sync" if stat.S_ISDIR(mode) else "file-sync")
            if stat.S_ISREG(mode):
                self.assertEqual(stat.S_IMODE(mode), 0o600)
            real_fsync(descriptor)

        def replace(source, destination):
            self.assertEqual(Path(source).parent, self.path.parent)
            self.assertEqual(Path(destination), self.path)
            self.assertEqual(Path(source).read_text(), "replacement")
            self.assertEqual(stat.S_IMODE(Path(source).stat().st_mode), 0o600)
            self.assertEqual(events, ["file-sync"])
            events.append("replace")
            real_replace(source, destination)

        with (
            patch.object(atomic_files.os, "fsync", side_effect=fsync),
            patch.object(atomic_files.os, "replace", side_effect=replace),
        ):
            subscriptions.private_write(self.path, "replacement")
        self.assertEqual(events, ["file-sync", "replace", "directory-sync"])

    def test_failures_before_replace_preserve_old_content_and_cleanup(self):
        for operation in ("mkstemp", "fchmod", "fdopen", "fsync", "replace"):
            self.path.write_bytes(b"old artifact")
            self.path.chmod(0o600)
            owner = atomic_files.tempfile if operation == "mkstemp" else atomic_files.os
            with (
                self.subTest(operation=operation),
                patch.object(owner, operation, side_effect=OSError("injected failure")),
            ):
                with self.assertRaises(OSError):
                    subscriptions.private_write(self.path, "replacement")
            self.assertEqual(self.path.read_bytes(), b"old artifact")
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_partial_write_failure_preserves_old_artifact(self):
        self.path.write_bytes(b"old artifact")
        real_fdopen = os.fdopen

        class FailedWriter:
            def __init__(self, descriptor, mode):
                self.handle = real_fdopen(descriptor, mode)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.handle.close()

            def write(self, content):
                self.handle.write(content[:3])
                self.handle.flush()
                raise OSError("injected partial write")

        with patch.object(atomic_files.os, "fdopen", side_effect=FailedWriter):
            with self.assertRaises(OSError):
                subscriptions.private_write(self.path, "replacement")
        self.assertEqual(self.path.read_bytes(), b"old artifact")
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_failed_new_export_leaves_no_artifact(self):
        with patch.object(
            atomic_files.os, "replace", side_effect=OSError("injected failure")
        ):
            with self.assertRaises(OSError):
                subscriptions.private_write(self.path, "replacement")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_directory_sync_failure_is_reported_after_atomic_replacement(self):
        self.path.write_bytes(b"old artifact")
        real_fsync = os.fsync

        def fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("directory sync failed")
            real_fsync(descriptor)

        with patch.object(atomic_files.os, "fsync", side_effect=fsync):
            with self.assertRaisesRegex(OSError, "directory sync failed"):
                subscriptions.private_write(self.path, "replacement")
        self.assertEqual(self.path.read_text(), "replacement")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_existing_symlink_target_is_not_overwritten(self):
        target = self.root / "target.txt"
        target.write_text("leave intact")
        self.path.symlink_to(target)
        subscriptions.private_write(self.path, "replacement")
        self.assertFalse(self.path.is_symlink())
        self.assertEqual(target.read_text(), "leave intact")
        self.assertEqual(self.path.read_text(), "replacement")

    def test_invalid_content_leaves_existing_output_unchanged(self):
        self.path.write_bytes(b"old artifact")
        for content in (None, b"bytes", 1, "\ud800"):
            with (
                self.subTest(content=content),
                self.assertRaises((ValueError, UnicodeError)),
            ):
                subscriptions.private_write(self.path, content)
            self.assertEqual(self.path.read_bytes(), b"old artifact")
            self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_nested_output_and_empty_text_are_supported(self):
        path = self.root / "nested" / "exports" / "subscription.txt"
        subscriptions.private_write(str(path), "")
        self.assertEqual(path.read_bytes(), b"")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(list(path.parent.iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
