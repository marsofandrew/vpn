import copy
import math
import unittest
from unittest.mock import patch

import vpn_health
import vpn_transports
import vpnctl
from vpn_validation import validate_state_shape


class StateValidationTests(unittest.TestCase):
    def setUp(self):
        self.state = vpnctl.create_state(
            "vpn.example.com", "example.com:443", "example.com", 8443, ["phone"], None
        )
        self.endpoint = vpn_transports.parse_link(
            "vless://11111111-2222-3333-4444-555555555555@exit.example.com:443"
            "?security=tls&type=xhttp&sni=example.com&path=%2Fentry"
        )

    def populated_state(self):
        state = copy.deepcopy(self.state)
        state.update(
            accounting={
                "epoch": "runtime",
                "checkpoints": {"phone@example.com": {"uplink": 12, "downlink": 34}},
            },
            upstreams={"exit": copy.deepcopy(self.endpoint)},
            upstream_nodes={"exit": "remote"},
            health={
                "exit": vpn_health.record_probe(
                    {},
                    {"success": True, "latency_ms": 1.5, "body_bytes": 131072},
                    1000,
                    {"success_threshold": 1},
                )
            },
            health_settings={
                "exit": {
                    "download_url": "https://example.com/sample",
                    "egress_url": "https://example.com/ip",
                    "expected_exit_ips": ["203.0.113.10"],
                    "interval": 30,
                    "timeout": 15.5,
                    "fail_threshold": 3,
                    "success_threshold": 3,
                    "bytes_required": 131072,
                }
            },
            client_entries={
                "phone-exit": {
                    "client": "phone",
                    "endpoint": copy.deepcopy(self.endpoint),
                }
            },
            route_events=[
                {
                    "at": vpnctl.utc_now(),
                    "policy": "foreign",
                    "from": None,
                    "to": "exit",
                }
            ],
        )
        state["routing_policies"]["foreign"] = {
            "type": "priority",
            "upstreams": ["exit"],
            "current_upstream": None,
            "cooldown": 0.5,
        }
        return state

    def record_at(self, state, path):
        record = state
        for field in path:
            record = record[field]
        return record

    def assert_invalid(self, state, path):
        before = copy.deepcopy(state)
        with self.assertRaises(ValueError) as raised:
            validate_state_shape(state)
        self.assertTrue(
            str(raised.exception).startswith(path + " "), str(raised.exception)
        )
        self.assertEqual(state, before)
        return str(raised.exception)

    def test_created_and_populated_states_are_accepted_without_mutation(self):
        for state in (self.state, self.populated_state()):
            before = copy.deepcopy(state)
            with (
                patch.object(
                    vpnctl, "generate_reality_keys", side_effect=AssertionError
                ),
                patch.object(vpnctl.uuid, "uuid4", side_effect=AssertionError),
            ):
                self.assertIsNone(validate_state_shape(state))
            self.assertEqual(state, before)

    def test_minimal_backward_compatible_records_are_accepted(self):
        state = copy.deepcopy(self.state)
        for field in (
            "created_at",
            "updated_at",
            "usage_period",
            "fingerprint",
            "flow",
            "spider_x",
        ):
            state.pop(field)
        profile = state["profiles"][0]
        for field in (
            "name",
            "created_at",
            "updated_at",
            "outbound_mode",
            "route",
            "transport",
        ):
            profile.pop(field)
        client = profile["clients"][0]
        profile["clients"] = [
            {field: client[field] for field in ("name", "id", "email")}
        ]
        state.update(
            accounting={},
            health={"old": {}},
            health_settings={"old": {}},
            client_entries={},
            upstream_nodes={},
            route_events=[],
        )
        self.assertIsNone(validate_state_shape(state))
        profile.pop("clients")
        self.assertIsNone(validate_state_shape(state))

    def test_optional_accounting_partial_checkpoints_and_health_settings(self):
        state = self.populated_state()
        state["accounting"] = {"checkpoints": {"phone@example.com": {"uplink": 12}}}
        state["health_settings"] = {"exit": {"interval": 30, "success_threshold": 1}}
        state["health"] = {"exit": {"status": "healthy"}}
        self.assertIsNone(validate_state_shape(state))

    def test_imported_reality_xhttp_and_tls_states_are_accepted(self):
        for network, security in (
            ("tcp", "reality"),
            ("xhttp", "reality"),
            ("xhttp", "tls"),
        ):
            with self.subTest(network=network, security=security):
                state = copy.deepcopy(self.state)
                profile = state["profiles"][0]
                profile["transport"] = {"type": network, "settings": {}}
                if security == "tls":
                    profile["security"] = {
                        "type": "tls",
                        "settings": {
                            "server_name": "example.com",
                            "certificates": [
                                {"certificateFile": "/cert.pem", "keyFile": "/key.pem"}
                            ],
                        },
                    }
                imported = vpnctl.import_state_from_xray_config(
                    vpnctl.render_config(state), state["server_host"]
                )
                before = copy.deepcopy(imported)
                self.assertIsNone(validate_state_shape(imported))
                self.assertEqual(imported, before)
                if security == "tls":
                    self.assertIsNone(imported["profiles"][0]["keys"]["private_key"])

    def test_legacy_migrations_preserve_identity_usage_and_accounting(self):
        for version in (1, 2, 3):
            with self.subTest(version=version):
                state = self.populated_state()
                profile = state["profiles"][0]
                client = profile["clients"][0]
                client.update(
                    quota_bytes=1000, used_uplink_bytes=12, used_downlink_bytes=34
                )
                identity = copy.deepcopy(
                    (profile["keys"], profile["short_id"], profile["clients"])
                )
                state["version"] = version
                for field in ("node", "upstreams", "routing_policies"):
                    state.pop(field)
                state.pop("upstream_nodes")
                for field in ("route", "transport"):
                    profile.pop(field)
                if version == 1:
                    state.update(
                        {
                            field: profile[field]
                            for field in (
                                "keys",
                                "short_id",
                                "clients",
                                "port",
                                "reality_target",
                            )
                        }
                    )
                    state.pop("profiles")
                migrated = vpnctl.migrate_legacy_state(state)
                before = copy.deepcopy(migrated)
                self.assertIsNone(validate_state_shape(migrated))
                profile = migrated["profiles"][0]
                self.assertEqual(
                    (profile["keys"], profile["short_id"], profile["clients"]), identity
                )
                self.assertEqual(migrated, before)
                if version != 1:
                    self.assertEqual(
                        migrated["accounting"]["checkpoints"]["phone@example.com"],
                        {"uplink": 12, "downlink": 34},
                    )

    def test_unknown_metadata_is_preserved_at_every_record_level(self):
        state = self.populated_state()
        paths = [
            (),
            ("node",),
            ("profiles", 0),
            ("profiles", 0, "keys"),
            ("profiles", 0, "clients", 0),
            ("upstreams", "exit"),
            ("routing_policies", "foreign"),
            ("accounting",),
            ("accounting", "checkpoints", "phone@example.com"),
            ("health", "exit"),
            ("health_settings", "exit"),
            ("client_entries", "phone-exit"),
            ("route_events", 0),
        ]
        for path in paths:
            self.record_at(state, path)["future_metadata"] = {"nested": [None, True, 7]}
        before = copy.deepcopy(state)
        self.assertIsNone(validate_state_shape(state))
        self.assertEqual(state, before)

    def test_nonobject_roots_raise_value_error(self):
        for state in (None, [], "secret", 1, True):
            with self.subTest(kind=type(state).__name__):
                self.assert_invalid(state, "state")

    def test_required_fields_raise_value_error_when_missing(self):
        cases = [
            (
                (),
                (
                    "version",
                    "server_host",
                    "default_domain",
                    "node",
                    "upstreams",
                    "routing_policies",
                    "profiles",
                ),
                "state",
            ),
            (("node",), ("id", "role"), "state.node"),
            (
                ("profiles", 0),
                ("port", "reality_target", "short_id", "keys"),
                "state.profiles[0]",
            ),
            (
                ("profiles", 0, "keys"),
                ("private_key", "public_key"),
                "state.profiles[0].keys",
            ),
            (
                ("profiles", 0, "clients", 0),
                ("name", "id", "email"),
                "state.profiles[0].clients[0]",
            ),
            (
                ("upstreams", "exit"),
                ("protocol", "address", "port", "auth", "transport", "security"),
                "state.upstreams[0]",
            ),
            (("upstreams", "exit", "auth"), ("id",), "state.upstreams[0].auth"),
            (
                ("upstreams", "exit", "transport"),
                ("type",),
                "state.upstreams[0].transport",
            ),
            (
                ("upstreams", "exit", "security"),
                ("type", "settings"),
                "state.upstreams[0].security",
            ),
            (
                ("routing_policies", "foreign"),
                ("type", "upstreams"),
                "state.routing_policies[2]",
            ),
            (
                ("client_entries", "phone-exit"),
                ("client", "endpoint"),
                "state.client_entries[0]",
            ),
            (
                ("route_events", 0),
                ("at", "policy", "from", "to"),
                "state.route_events[0]",
            ),
        ]
        for record_path, fields, safe_path in cases:
            for field in fields:
                with self.subTest(record=record_path, field=field):
                    state = self.populated_state()
                    del self.record_at(state, record_path)[field]
                    self.assert_invalid(state, safe_path + "." + field)

    def test_containers_and_nested_records_reject_wrong_types(self):
        paths = [
            (("node",), "state.node"),
            (("upstreams",), "state.upstreams"),
            (("upstreams", "exit"), "state.upstreams[0]"),
            (("routing_policies",), "state.routing_policies"),
            (("routing_policies", "foreign"), "state.routing_policies[2]"),
            (("profiles",), "state.profiles"),
            (("profiles", 0), "state.profiles[0]"),
            (("profiles", 0, "keys"), "state.profiles[0].keys"),
            (("profiles", 0, "clients"), "state.profiles[0].clients"),
            (("profiles", 0, "clients", 0), "state.profiles[0].clients[0]"),
            (("accounting",), "state.accounting"),
            (("accounting", "checkpoints"), "state.accounting.checkpoints"),
            (
                ("accounting", "checkpoints", "phone@example.com"),
                "state.accounting.checkpoints[0]",
            ),
            (("health",), "state.health"),
            (("health", "exit"), "state.health[0]"),
            (("health_settings",), "state.health_settings"),
            (("health_settings", "exit"), "state.health_settings[0]"),
            (("upstream_nodes",), "state.upstream_nodes"),
            (("client_entries",), "state.client_entries"),
            (("client_entries", "phone-exit"), "state.client_entries[0]"),
            (("route_events",), "state.route_events"),
            (("route_events", 0), "state.route_events[0]"),
        ]
        for path, safe_path in paths:
            for value in (None, "secret", 3, True):
                with self.subTest(path=path, kind=type(value).__name__):
                    state = self.populated_state()
                    self.record_at(state, path[:-1])[path[-1]] = value
                    self.assert_invalid(state, safe_path)

    def test_known_string_and_boolean_fields_reject_incompatible_types(self):
        paths = [
            (("server_host",), "state.server_host"),
            (("default_domain",), "state.default_domain"),
            (("flow",), "state.flow"),
            (("node", "id"), "state.node.id"),
            (("node", "role"), "state.node.role"),
            (("node", "foreign_only"), "state.node.foreign_only"),
            (("profiles", 0, "name"), "state.profiles[0].name"),
            (("profiles", 0, "route"), "state.profiles[0].route"),
            (("profiles", 0, "outbound_mode"), "state.profiles[0].outbound_mode"),
            (("profiles", 0, "reality_target"), "state.profiles[0].reality_target"),
            (("profiles", 0, "short_id"), "state.profiles[0].short_id"),
            (
                ("profiles", 0, "keys", "private_key"),
                "state.profiles[0].keys.private_key",
            ),
            (
                ("profiles", 0, "keys", "public_key"),
                "state.profiles[0].keys.public_key",
            ),
            (
                ("profiles", 0, "clients", 0, "email"),
                "state.profiles[0].clients[0].email",
            ),
            (
                ("profiles", 0, "clients", 0, "enabled"),
                "state.profiles[0].clients[0].enabled",
            ),
            (
                ("profiles", 0, "clients", 0, "disabled_reason"),
                "state.profiles[0].clients[0].disabled_reason",
            ),
            (("accounting", "epoch"), "state.accounting.epoch"),
            (("health", "exit", "status"), "state.health[0].status"),
            (("health", "exit", "error"), "state.health[0].error"),
            (("health", "exit", "success"), "state.health[0].success"),
            (
                ("health_settings", "exit", "download_url"),
                "state.health_settings[0].download_url",
            ),
            (("upstream_nodes", "exit"), "state.upstream_nodes[0]"),
            (
                ("client_entries", "phone-exit", "client"),
                "state.client_entries[0].client",
            ),
            (("route_events", 0, "from"), "state.route_events[0].from"),
            (
                ("routing_policies", "foreign", "current_upstream"),
                "state.routing_policies[2].current_upstream",
            ),
        ]
        for path, safe_path in paths:
            for value in ([], {}, 1):
                with self.subTest(path=path, kind=type(value).__name__):
                    state = self.populated_state()
                    self.record_at(state, path[:-1])[path[-1]] = value
                    self.assert_invalid(state, safe_path)

    def test_byte_totals_quotas_and_counters_require_nonnegative_integers(self):
        cases = [
            (
                ("profiles", 0, "clients", 0),
                ("quota_bytes", "used_uplink_bytes", "used_downlink_bytes"),
                "state.profiles[0].clients[0]",
            ),
            (
                ("accounting", "checkpoints", "phone@example.com"),
                ("uplink", "downlink"),
                "state.accounting.checkpoints[0]",
            ),
            (
                ("health", "exit"),
                ("body_bytes", "consecutive_failures", "consecutive_successes"),
                "state.health[0]",
            ),
        ]
        for path, fields, safe_path in cases:
            for field in fields:
                for value in (-1, 1.5, "12", True, [], {}):
                    with self.subTest(
                        path=path, field=field, kind=type(value).__name__
                    ):
                        state = self.populated_state()
                        self.record_at(state, path)[field] = value
                        self.assert_invalid(state, safe_path + "." + field)
                state = self.populated_state()
                self.record_at(state, path)[field] = 0
                self.assertIsNone(validate_state_shape(state))

    def test_finite_nonnegative_metrics_timestamps_and_cooldowns(self):
        cases = [
            (
                ("health", "exit"),
                (
                    "latency_ms",
                    "download_time_ms",
                    "total_time_ms",
                    "throughput_bps",
                    "last_probe",
                    "next_probe_at",
                    "last_success",
                    "restored_at",
                ),
                "state.health[0]",
            ),
            (
                ("routing_policies", "foreign"),
                ("cooldown",),
                "state.routing_policies[2]",
            ),
        ]
        for path, fields, safe_path in cases:
            for field in fields:
                for value in (-1, True, "12", math.inf, -math.inf, math.nan, 10**1000):
                    with self.subTest(
                        path=path, field=field, kind=type(value).__name__
                    ):
                        state = self.populated_state()
                        self.record_at(state, path)[field] = value
                        with self.assertRaisesRegex(
                            ValueError,
                            safe_path.replace("[", r"\[").replace("]", r"\]")
                            + "."
                            + field,
                        ):
                            validate_state_shape(state)
        state = self.populated_state()
        state["health"]["exit"]["next_probe_at"] = None
        self.assert_invalid(state, "state.health[0].next_probe_at")

    def test_probe_settings_require_positive_numbers_and_integer_thresholds(self):
        for field in (
            "interval",
            "timeout",
            "fail_threshold",
            "success_threshold",
            "bytes_required",
        ):
            invalid = (None, 0, -1, True, "3", math.nan, math.inf)
            if field in ("fail_threshold", "success_threshold", "bytes_required"):
                invalid += (1.5,)
            for value in invalid:
                with self.subTest(field=field, kind=type(value).__name__):
                    state = self.populated_state()
                    state["health_settings"]["exit"][field] = value
                    with self.assertRaises(ValueError) as raised:
                        validate_state_shape(state)
                    self.assertIn(
                        "state.health_settings[0]." + field, str(raised.exception)
                    )

    def test_string_lists_reject_scalars_and_nonstring_members(self):
        for path, safe_path in [
            (
                ("routing_policies", "foreign", "upstreams"),
                "state.routing_policies[2].upstreams",
            ),
            (
                ("health_settings", "exit", "expected_exit_ips"),
                "state.health_settings[0].expected_exit_ips",
            ),
        ]:
            for value in (None, "exit", {}, [None], [[]], [1]):
                with self.subTest(path=path, kind=type(value).__name__):
                    state = self.populated_state()
                    self.record_at(state, path[:-1])[path[-1]] = value
                    with self.assertRaises(ValueError) as raised:
                        validate_state_shape(state)
                    self.assertTrue(str(raised.exception).startswith(safe_path))

    def test_nullable_fields_and_zero_unlimited_quotas(self):
        state = self.populated_state()
        state["usage_period"] = None
        state["profiles"][0]["clients"][0].update(quota_bytes=0, disabled_reason=None)
        for field in (
            "last_probe",
            "last_success",
            "restored_at",
            "latency_ms",
            "download_time_ms",
            "total_time_ms",
            "throughput_bps",
            "status_code",
            "egress_status_code",
            "error",
        ):
            state["health"]["exit"][field] = None
        self.assertIsNone(validate_state_shape(state))
        state["profiles"][0]["clients"][0]["quota_bytes"] = None
        self.assertIsNone(validate_state_shape(state))

    def test_nonstring_mapping_keys_raise_safe_value_errors(self):
        for field in (
            "upstreams",
            "routing_policies",
            "health",
            "health_settings",
            "upstream_nodes",
            "client_entries",
        ):
            state = self.populated_state()
            state[field] = {42: {}}
            self.assert_invalid(state, "state." + field + "[0].key")

    def test_errors_never_contain_mapping_keys_values_or_credentials(self):
        secret = "vless://private-credential@example.com?token=secret\nunsafe"
        for field in (
            "upstreams",
            "routing_policies",
            "health",
            "health_settings",
            "upstream_nodes",
            "client_entries",
        ):
            state = self.populated_state()
            state[field] = {secret: [secret]}
            message = self.assert_invalid(state, "state." + field + "[0]")
            self.assertNotIn(secret, message)
            self.assertNotIn("credential", message)
            self.assertNotIn("\n", message)
        state = self.populated_state()
        state["accounting"]["checkpoints"] = {secret: {"uplink": secret}}
        self.assertEqual(
            self.assert_invalid(state, "state.accounting.checkpoints[0].uplink"),
            "state.accounting.checkpoints[0].uplink must be an integer at least 0",
        )

    def test_transport_semantics_and_key_formats_are_left_to_existing_validators(self):
        state = self.populated_state()
        state["profiles"][0]["keys"] = {
            "private_key": "legacy-private",
            "public_key": "legacy-public",
        }
        state["profiles"][0]["clients"][0]["id"] = "legacy-client-id"
        state["upstreams"]["exit"]["security"]["settings"] = {
            "future_setting": "retained"
        }
        with (
            patch.object(
                vpn_transports, "validate_upstream", side_effect=AssertionError
            ),
            patch.object(vpn_transports, "render_stream", side_effect=AssertionError),
        ):
            self.assertIsNone(validate_state_shape(state))


if __name__ == "__main__":
    unittest.main()
