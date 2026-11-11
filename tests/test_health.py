import ssl
import time

"""Offline tests: real HTTP parsing, in-memory SOCKS peers, mocked TLS boundary."""

import copy
import json
import math
import socket
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

import vpn_health as health

_CREATE_DEFAULT_CONTEXT = ssl.create_default_context


class StateTests(unittest.TestCase):
    def test_initial_success_and_failure_are_unknown_until_threshold(self):
        for success, counter in [
            (True, "consecutive_successes"),
            (False, "consecutive_failures"),
        ]:
            with self.subTest(success=success):
                state = {}
                for n in range(1, 4):
                    state = health.record_probe(
                        state,
                        {"success": success, "exit_ip_verified": True},
                        n * 30,
                        {},
                    )
                    self.assertEqual(state[counter], n)
                    expected = (
                        "unknown" if n < 3 else ("healthy" if success else "unhealthy")
                    )
                    self.assertEqual(state["status"], expected)
                self.assertEqual(state["next_probe_at"], 120)
                self.assertEqual(state["last_success"], 90 if success else None)
                self.assertEqual(state["restored_at"], 90 if success else None)

    def test_hysteresis_and_recovery_timestamp(self):
        state = {}
        for now in [0, 30, 60]:
            state = health.record_probe(
                state, {"success": True, "exit_ip_verified": True}, now, {}
            )
        for now in [90, 120]:
            state = health.record_probe(state, {"success": False}, now, {})
            self.assertEqual(state["status"], "healthy")
            self.assertEqual(state["restored_at"], 60)
        state = health.record_probe(state, {"success": False}, 150, {})
        self.assertEqual(state["status"], "unhealthy")
        self.assertIsNone(state["restored_at"])
        self.assertEqual(state["last_success"], 60)
        for now in [180, 210]:
            state = health.record_probe(
                state, {"success": True, "exit_ip_verified": True}, now, {}
            )
            self.assertEqual(state["status"], "unhealthy")
        state = health.record_probe(
            state, {"success": True, "exit_ip_verified": True}, 240, {}
        )
        self.assertEqual(state["status"], "healthy")
        self.assertEqual(state["restored_at"], 240)
        state = health.record_probe(
            state, {"success": True, "exit_ip_verified": True}, 270, {}
        )
        self.assertEqual(state["restored_at"], 240)

    def test_opposite_result_resets_streaks(self):
        state = {}
        for now, success in enumerate([True, True, False, False, True, False, True]):
            state = health.record_probe(
                state, {"success": success, "exit_ip_verified": True}, now, {}
            )
            self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertEqual(state["consecutive_successes"], 1)

    def test_custom_config_and_measurements_without_mutation(self):
        previous = {"status": "unhealthy", "consecutive_failures": 4}
        result = {
            "success": True,
            "latency_ms": 12,
            "throughput_bps": 200000,
            "body_bytes": 131072,
            "download_time_ms": 500,
            "total_time_ms": 550,
            "status_code": 200,
            "egress_status_code": 200,
            "exit_ip_verified": True,
        }
        config = {
            "interval": 7,
            "fail_threshold": 1,
            "success_threshold": 1,
            "cooldown": 42,
        }
        before = copy.deepcopy((previous, result, config))
        state = health.record_probe(previous, result, 100, config)
        self.assertEqual(state["status"], "healthy")
        self.assertEqual(state["next_probe_at"], 107)
        self.assertEqual(state["restored_at"], 100)
        for key, value in result.items():
            self.assertEqual(state[key], value)
        self.assertEqual((previous, result, config), before)
        failed = health.record_probe(state, {"success": False}, 101, config)
        self.assertEqual(failed["status"], "unhealthy")
        self.assertEqual(failed["last_success"], 100)
        self.assertIsNone(failed["latency_ms"])

    def test_latest_result_is_recorded_even_before_advisory_due_time(self):
        state = health.record_probe(
            {}, {"success": True, "exit_ip_verified": True}, 10, {}
        )
        state = health.record_probe(state, {"success": False}, 11, {})
        self.assertEqual(state["last_probe"], 11)
        self.assertEqual(state["next_probe_at"], 41)
        self.assertEqual(state["consecutive_failures"], 1)

    def test_unverified_positive_cannot_become_healthy(self):
        for verification in (
            {},
            {"exit_ip_verified": False},
            {"exit_ip_verified": None},
            {"exit_ip_verified": 1},
            {"exit_ip_verified": "true"},
        ):
            with self.subTest(verification=verification):
                result = {"success": True, "error": "SECRET-CREDENTIAL", **verification}
                before = copy.deepcopy(result)
                state = health.record_probe({}, result, 10, {"success_threshold": 1})
                self.assertEqual(state["status"], "unknown")
                self.assertFalse(state["success"])
                self.assertFalse(state["exit_ip_verified"])
                self.assertEqual(state["error"], "exit_ip_unverified")
                self.assertEqual(state["consecutive_failures"], 1)
                self.assertEqual(state["consecutive_successes"], 0)
                self.assertIsNone(state["last_success"])
                self.assertIsNone(state["restored_at"])
                self.assertEqual(result, before)

    def test_unverified_positives_preserve_health_until_failure_threshold(self):
        for verification in ({}, {"exit_ip_verified": False}):
            with self.subTest(verification=verification):
                state = {}
                for now in (0, 30, 60):
                    state = health.record_probe(
                        state, {"success": True, "exit_ip_verified": True}, now, {}
                    )
                for now, failures in ((90, 1), (120, 2), (150, 3)):
                    previous = copy.deepcopy(state)
                    state = health.record_probe(
                        state, {"success": True, **verification}, now, {}
                    )
                    self.assertEqual(
                        state["status"], "healthy" if failures < 3 else "unhealthy"
                    )
                    self.assertEqual(state["restored_at"], 60 if failures < 3 else None)
                    self.assertEqual(state["consecutive_failures"], failures)
                    self.assertEqual(state["consecutive_successes"], 0)
                    self.assertEqual(state["last_success"], 60)
                    self.assertEqual(state["last_probe"], now)
                    self.assertEqual(state["next_probe_at"], now + 30)
                    self.assertEqual(state["error"], "exit_ip_unverified")
                    if failures < 3:
                        self.assertEqual(previous["restored_at"], state["restored_at"])
                state = health.record_probe(
                    state, {"success": True, **verification}, 180, {}
                )
                self.assertEqual(state["status"], "unhealthy")
                self.assertEqual(state["consecutive_successes"], 0)

    def test_runtime_version_failure_code_is_preserved(self):
        state = health.record_probe(
            {}, {"success": False, "error": "runtime_version_mismatch"}, 10, {}
        )
        self.assertEqual(state["error"], "runtime_version_mismatch")

    def test_invalid_config_and_out_of_order_observations(self):
        for config in [
            {"interval": -1},
            {"fail_threshold": 0},
            {"success_threshold": 1.5},
            {"success_threshold": True},
            {"cooldown": -1},
            {"interval": math.inf},
        ]:
            with self.subTest(config=config), self.assertRaises(ValueError):
                health.record_probe({}, {}, 10, config)
        for now in [math.nan, math.inf, True, "10", 10**1000]:
            with self.subTest(now=now), self.assertRaises(ValueError):
                health.record_probe({}, {}, now, {})
        with self.assertRaises(ValueError):
            health.record_probe({"last_probe": 11}, {}, 10, {})

    def test_only_boolean_success_counts_and_invalid_measurements_are_discarded(self):
        result = {
            "success": "yes",
            "exit_ip_verified": True,
            "latency_ms": math.nan,
            "throughput_bps": -1,
            "error": "secret URL and token",
            "body_bytes": True,
            "status_code": 999,
        }
        state = health.record_probe({}, result, 10, {})
        self.assertFalse(state["success"])
        self.assertEqual(state["error"], "probe_failed")
        self.assertIsNone(state["latency_ms"])
        self.assertIsNone(state["throughput_bps"])
        self.assertIsNone(state["status_code"])
        self.assertEqual(state["body_bytes"], 0)
        state = health.record_probe({}, {"error": {"secret": "value"}}, 10, {})
        self.assertEqual(state["error"], "probe_failed")


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.upstreams = {uid: {"enabled": True} for uid in ["a", "b", "c"]}
        self.health = {
            uid: {"status": "healthy", "latency_ms": latency, "restored_at": 50}
            for uid, latency in [("a", 20), ("b", 10), ("c", 30)]
        }

    def select(self, kind, **kwargs):
        return health.select_route(
            {"type": kind, "upstreams": ["a", "b", "c"], **kwargs},
            self.upstreams,
            self.health,
            100,
        )

    def test_upstream_uses_stable_key_not_embedded_protocol_identity(self):
        self.upstreams["a"]["id"] = "vless-user-uuid"
        policy = {"type": "upstream", "upstreams": ["a"]}
        self.assertEqual(
            health.select_route(policy, self.upstreams, self.health, 100), "a"
        )
        self.health["a"]["status"] = "unknown"
        self.assertIsNone(health.select_route(policy, self.upstreams, self.health, 100))

    def test_priority_order_and_immediate_failover(self):
        self.assertEqual(self.select("priority"), "a")
        self.health["a"]["status"] = "unhealthy"
        self.assertEqual(
            self.select("priority", current_upstream="a", cooldown=10000), "b"
        )
        self.upstreams["b"]["enabled"] = False
        self.assertEqual(self.select("priority"), "c")

    def test_priority_switchback_boundary_and_missing_restoration(self):
        self.assertEqual(self.select("priority", current_upstream="b"), "b")
        self.health["a"]["restored_at"] = 40
        self.assertEqual(self.select("priority", current_upstream="b"), "a")
        self.health["a"].pop("restored_at")
        self.assertEqual(self.select("priority", current_upstream="b"), "b")
        self.assertEqual(self.select("priority", current_upstream="b", cooldown=0), "a")
        self.health["a"]["restored_at"] = 101
        self.assertEqual(self.select("priority", current_upstream="b", cooldown=1), "b")

    def test_priority_uses_next_eligible_preferred_member(self):
        self.health["b"]["restored_at"] = 0
        self.assertEqual(self.select("priority", current_upstream="c"), "b")
        self.assertEqual(self.select("priority", current_upstream="a"), "a")
        self.assertEqual(self.select("priority", current_upstream="missing"), "a")

    def test_repeated_success_does_not_postpone_switchback(self):
        state = {}
        for now in [0, 30, 60, 90]:
            state = health.record_probe(
                state, {"success": True, "exit_ip_verified": True}, now, {}
            )
        self.health["a"] = state
        policy = {
            "type": "priority",
            "upstreams": ["a", "b"],
            "current_upstream": "b",
            "cooldown": 60,
        }
        self.assertEqual(
            health.select_route(policy, self.upstreams, self.health, 119), "b"
        )
        self.assertEqual(
            health.select_route(policy, self.upstreams, self.health, 120), "a"
        )

    def test_balanced_minimizes_latency_only_among_eligible_members(self):
        self.assertEqual(self.select("balanced"), "b")
        self.health["b"]["status"] = "unhealthy"
        self.assertEqual(self.select("balanced"), "a")
        self.upstreams["a"]["enabled"] = False
        self.assertEqual(self.select("balanced"), "c")

    def test_unverified_positives_preserve_switchback_cooldown_until_failure_threshold(
        self,
    ):
        state = {
            "status": "healthy",
            "restored_at": 60,
            "last_success": 60,
            "consecutive_successes": 3,
        }
        policy = {
            "type": "priority",
            "upstreams": ["a", "b"],
            "current_upstream": "b",
            "cooldown": 60,
        }
        for now, expected in ((119, "b"), (120, "a"), (121, "b")):
            state = health.record_probe(
                state, {"success": True, "exit_ip_verified": False}, now, {}
            )
            self.health["a"] = state
            self.assertEqual(
                health.select_route(policy, self.upstreams, self.health, now), expected
            )

    def test_balanced_ties_and_missing_or_invalid_latency_are_deterministic(self):
        for value in [None, math.nan, math.inf, -1, "fast", True]:
            with self.subTest(value=value):
                self.health["b"]["latency_ms"] = value
                self.assertEqual(self.select("balanced"), "a")
        self.health["b"]["latency_ms"] = 20
        self.assertEqual(self.select("balanced"), "a")
        for state in self.health.values():
            state.pop("latency_ms")
        self.assertEqual(self.select("balanced"), "a")

    def test_missing_unknown_disabled_and_empty_candidates_fail_closed(self):
        for kind in ["priority", "balanced"]:
            for state in self.health.values():
                state["status"] = "unknown"
            self.assertIsNone(self.select(kind))
            self.assertIsNone(
                health.select_route({"type": kind, "upstreams": ["missing"]}, {}, {}, 0)
            )
            self.assertIsNone(
                health.select_route({"type": kind, "upstreams": []}, {}, {}, 0)
            )

    def test_direct_and_block_are_deferred_to_orchestrator(self):
        for kind in ["direct", "block"]:
            self.assertIsNone(health.select_route({"type": kind}, {}, {}, 0))

    def test_invalid_policies_raise_and_inputs_are_not_mutated(self):
        for policy in [
            {"type": "unknown"},
            {"type": "upstream", "upstreams": []},
            {"type": "upstream", "upstreams": ["a", "b"]},
            {"type": "balanced", "upstreams": "a"},
            {"type": "priority", "upstreams": ["a", "a"]},
            {"type": "priority", "upstreams": ["a"], "cooldown": -1},
        ]:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                health.select_route(policy, self.upstreams, self.health, 100)
        before = copy.deepcopy((self.upstreams, self.health))
        self.select("balanced")
        self.select("priority", current_upstream="b")
        self.assertEqual((self.upstreams, self.health), before)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class MemorySocket:
    """A fragmented SOCKS server followed by an HTTPS response at a mocked TLS boundary."""

    def __init__(self, data, clock, fragment=4096, delay=0.001):
        self.data = bytearray(data)
        self.clock = clock
        self.fragment = fragment
        self.delay = delay
        self.sent = []
        self.timeouts = []
        self.closed = False
        self.connected = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.closed = True

    def connect(self, address):
        self.connected = address
        self.clock.now += 0.001

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.sent.append(data)
        self.clock.now += 0.001

    def recv(self, count):
        self.clock.now += self.delay
        count = min(count, self.fragment, len(self.data))
        data = bytes(self.data[:count])
        del self.data[:count]
        return data

    def do_handshake(self):
        self.clock.now += 0.001


def http_response(body, status=200, headers=None, chunked=False):
    headers = dict(headers or {})
    if chunked:
        headers.setdefault("Transfer-Encoding", "chunked")
        chunks = [body[n : n + 10000] for n in range(0, len(body), 10000)]
        body = (
            b"".join(
                (f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n") for chunk in chunks
            )
            + b"0\r\n\r\n"
        )
    elif "Content-Length" not in headers and "Transfer-Encoding" not in headers:
        headers["Content-Length"] = str(len(body))
    head = f"HTTP/1.1 {status} Test\r\n".encode()
    head += b"".join(f"{key}: {value}\r\n".encode() for key, value in headers.items())
    return head + b"\r\n" + body


SOCKS_OK = b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"
BODY = b"x" * 131072
EGRESS = b'{"ip":"203.0.113.10"}'


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.clock = Clock()
        self.stack.enter_context(patch.object(time, "monotonic", self.clock))
        self.sockets = []
        self.pending = []
        self.socket_factory = self.stack.enter_context(
            patch.object(socket, "socket", side_effect=self.socket)
        )
        self.stack.enter_context(
            patch.object(
                socket,
                "getaddrinfo",
                side_effect=AssertionError("DNS forbidden"),
            )
        )
        self.context = Mock()
        self.context.wrap_socket.side_effect = lambda sock, **kwargs: sock
        self.create_context = self.stack.enter_context(
            patch.object(ssl, "create_default_context", return_value=self.context)
        )

    def socket(self, family, kind):
        self.assertIn(family, (socket.AF_INET, socket.AF_INET6))
        self.assertEqual(kind, socket.SOCK_STREAM)
        if not self.pending:
            self.fail("unexpected connection (probe must never bypass SOCKS)")
        sock = self.pending.pop(0)
        self.sockets.append(sock)
        return sock

    def enqueue(self, response, prefix=SOCKS_OK, **kwargs):
        sock = MemorySocket(prefix + response, self.clock, **kwargs)
        self.pending.append(sock)
        return sock

    def defaults(self, **kwargs):
        options = {
            "socks_host": "127.0.0.1",
            "socks_port": 1080,
            "download_url": "https://download.invalid/sample?operator=secret",
            "egress_url": "https://egress.invalid/json",
            "expected_exit_ips": ["203.0.113.10"],
        }
        options.update(kwargs)
        return health.probe_path(**options)

    def success_responses(self, **kwargs):
        self.enqueue(http_response(BODY, **kwargs))
        self.enqueue(http_response(EGRESS, **kwargs))

    def assert_failed(self, result, error):
        self.assertFalse(result["success"], result)
        self.assertEqual(result["error"], error, result)
        encoded = json.dumps(result)
        for secret in ["operator", "secret", "invalid/", "password", "203.0.113.10"]:
            self.assertNotIn(secret, encoded)
        self.assertTrue(all(sock.closed for sock in self.sockets))

    def test_success_remote_dns_tls_status_measurements_and_resource_cleanup(self):
        self.success_responses()
        result = self.defaults()
        self.assertTrue(result["success"], result)
        self.assertIsNone(result["error"])
        self.assertTrue(result["exit_ip_verified"])
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["egress_status_code"], 200)
        self.assertEqual(result["body_bytes"], len(BODY))
        self.assertGreater(result["latency_ms"], 0)
        self.assertGreater(result["download_time_ms"], result["latency_ms"])
        self.assertGreater(result["total_time_ms"], result["download_time_ms"])
        self.assertAlmostEqual(
            result["throughput_bps"], len(BODY) * 8000 / result["download_time_ms"]
        )
        self.assertEqual(len(self.sockets), 2)
        for sock, hostname in zip(self.sockets, ["download.invalid", "egress.invalid"]):
            self.assertEqual(sock.connected, ("127.0.0.1", 1080))
            self.assertEqual(sock.sent[0], b"\x05\x01\x00")
            self.assertEqual(
                sock.sent[1],
                b"\x05\x01\x00\x03"
                + bytes([len(hostname)])
                + hostname.encode()
                + b"\x01\xbb",
            )
            self.assertIn(b"Host: " + hostname.encode() + b"\r\n", sock.sent[2])
            self.assertIn(b"Accept-Encoding: identity\r\n", sock.sent[2])
            self.assertTrue(sock.closed)
            self.assertTrue(all(t > 0 for t in sock.timeouts))
            self.assertEqual(sock.timeouts, sorted(sock.timeouts, reverse=True))
        self.create_context.assert_called_once_with()
        self.assertEqual(
            [
                call.kwargs["server_hostname"]
                for call in self.context.wrap_socket.call_args_list
            ],
            ["download.invalid", "egress.invalid"],
        )
        self.assertTrue(
            all(
                call.kwargs["do_handshake_on_connect"] is False
                for call in self.context.wrap_socket.call_args_list
            )
        )

    def test_chunked_download_and_egress(self):
        self.success_responses(chunked=True)
        self.assertTrue(self.defaults()["success"])

    def test_real_default_context_requires_certificate_and_hostname_verification(self):
        context = _CREATE_DEFAULT_CONTEXT()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        context.wrap_socket = Mock(side_effect=lambda sock, **kwargs: sock)
        self.create_context.return_value = context
        self.success_responses()
        self.assertTrue(self.defaults()["success"])
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_fragmented_handshakes_and_bounded_sample_of_larger_body(self):
        download = self.enqueue(http_response(BODY + BODY), fragment=7)
        self.enqueue(http_response(EGRESS), fragment=1)
        result = self.defaults(timeout=60)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["body_bytes"], len(BODY))
        self.assertGreater(len(download.data), 0)

    def test_ipv6_proxy_and_target_and_equivalent_expected_ip(self):
        self.enqueue(
            http_response(BODY), prefix=b"\x05\x00\x05\x00\x00\x04" + b"\0" * 18
        )
        self.enqueue(http_response(b'{"ip":"2001:db8::1"}'))
        result = self.defaults(
            socks_host="::1",
            download_url="https://[2001:db8::2]:8443/sample",
            expected_exit_ips=["2001:0db8:0:0:0:0:0:1"],
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(self.sockets[0].connected, ("::1", 1080))
        self.assertEqual(self.sockets[0].sent[1][3], 4)
        self.assertIn(b"Host: [2001:db8::2]:8443\r\n", self.sockets[0].sent[2])

    def test_ipv4_target_and_domain_socks_reply(self):
        self.enqueue(
            http_response(BODY), prefix=b"\x05\x00\x05\x00\x00\x03\x03abc\x00\x00"
        )
        self.enqueue(http_response(EGRESS))
        self.assertTrue(
            self.defaults(socks_host="localhost", download_url="https://192.0.2.1/")[
                "success"
            ]
        )
        self.assertEqual(self.sockets[0].sent[1][3], 1)

    def test_missing_verification_configuration_fails_before_connect(self):
        for kwargs, error in [
            ({"expected_exit_ips": []}, "expected_exit_ips_required"),
            ({"expected_exit_ips": None}, "expected_exit_ips_required"),
            ({"egress_url": None}, "egress_url_required"),
        ]:
            with self.subTest(kwargs=kwargs):
                self.assert_failed(self.defaults(**kwargs), error)
        self.socket_factory.assert_not_called()

    def test_configuration_validation_has_no_network_or_sensitive_errors(self):
        invalid = [
            {"download_url": None},
            {"download_url": "http://download.invalid/"},
            {"download_url": "https://user:password@download.invalid/"},
            {"download_url": "https://download.invalid/#secret"},
            {"download_url": "https://download.invalid/\r\nsecret"},
            {"download_url": "https://download.invalid:0/"},
            {"download_url": "https://download.invalid:65536/"},
            {"download_url": "https://bad_host.invalid/"},
            {"download_url": "https://[fe80::1%en0]/"},
            {"egress_url": "http://egress.invalid/"},
            {"socks_host": "remote.invalid"},
            {"socks_host": "192.0.2.1"},
            {"socks_port": 0},
            {"socks_port": 65536},
            {"socks_port": True},
            {"bytes_required": 131071},
            {"bytes_required": 17 * 1024 * 1024},
            {"bytes_required": True},
            {"timeout": 0},
            {"timeout": -1},
            {"timeout": math.nan},
            {"timeout": math.inf},
            {"timeout": 10**1000},
            {"expected_exit_ips": "203.0.113.10"},
            {"expected_exit_ips": [123]},
            {"expected_exit_ips": ["not an IP"]},
            {"expected_exit_ips": ["fe80::1%en0"]},
        ]
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs):
                self.assert_failed(self.defaults(**kwargs), "invalid_configuration")
        self.socket_factory.assert_not_called()

    def test_socks_protocol_errors_and_unsupported_authentication(self):
        cases = [
            (b"", "socks_protocol"),
            (b"\x04\x00", "socks_protocol"),
            (b"\x05\xff", "socks_authentication"),
            (b"\x05\x02", "socks_authentication"),
            (b"\x05\x00\x05\x05\x00\x01", "socks_connect_failed"),
            (b"\x05\x00\x04\x00\x00\x01", "socks_protocol"),
            (b"\x05\x00\x05\x00\x01\x01", "socks_protocol"),
            (b"\x05\x00\x05\x00\x00\x05", "socks_protocol"),
            (b"\x05\x00\x05\x00\x00\x03\x00", "socks_protocol"),
            (SOCKS_OK[:-1], "socks_protocol"),
        ]
        for prefix, error in cases:
            with self.subTest(prefix=prefix):
                self.enqueue(b"", prefix=prefix, fragment=1)
                self.assert_failed(self.defaults(), error)

    def test_tls_and_socket_errors_are_sanitized(self):
        for exception, code in [
            (ssl.SSLCertVerificationError("secret"), "tls_verification_failed"),
            (ssl.SSLError("secret"), "tls_failed"),
            (TimeoutError("secret"), "timeout"),
            (OverflowError("secret"), "invalid_configuration"),
            (OSError("secret"), "connection_failed"),
        ]:
            with self.subTest(code=code):
                self.enqueue(http_response(BODY))
                self.context.wrap_socket.side_effect = exception
                self.assert_failed(self.defaults(), code)

    def test_non_2xx_responses_and_redirects_are_not_followed(self):
        for status in [301, 401, 404, 500]:
            with self.subTest(status=status):
                self.enqueue(
                    http_response(
                        b"",
                        status=status,
                        headers={"Location": "https://secret.invalid/"},
                    )
                )
                result = self.defaults()
                self.assert_failed(result, "http_status")
                self.assertEqual(result["status_code"], status)
        self.assertEqual(len(self.sockets), 4)

    def test_short_body_and_truncated_content_length(self):
        for response in [
            http_response(b"x" * 131071),
            http_response(b"x" * 100, headers={"Content-Length": "131072"}),
        ]:
            with self.subTest(length=len(response)):
                self.enqueue(response)
                self.assert_failed(self.defaults(), "body_too_short")

    def test_invalid_http_ambiguous_framing_and_compression(self):
        cases = [
            (b"garbage\r\n\r\n", "invalid_http"),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
                "invalid_http",
            ),
            (http_response(BODY, headers={"Content-Length": "-1"}), "invalid_http"),
            (
                http_response(BODY, headers={"Transfer-Encoding": "gzip"}),
                "invalid_http",
            ),
            (
                http_response(
                    BODY,
                    headers={
                        "Transfer-Encoding": "chunked",
                        "Content-Length": "131072",
                    },
                ),
                "invalid_http",
            ),
            (
                http_response(BODY, headers={"Content-Encoding": "gzip"}),
                "unsupported_encoding",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
                "invalid_http",
            ),
        ]
        for response, code in cases:
            with self.subTest(code=code):
                self.enqueue(response)
                self.assert_failed(self.defaults(), code)

    def test_oversized_headers_and_interim_responses_are_bounded(self):
        for response in [
            b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 70000 + b"\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\n" * 3000,
        ]:
            with self.subTest(length=len(response)):
                sock = self.enqueue(response)
                self.assert_failed(self.defaults(), "response_too_large")
                self.assertLess(len(response) - len(sock.data), 65536 + 8192)

    def test_egress_mismatch_invalid_json_schema_and_address(self):
        cases = [
            (b'{"ip":"192.0.2.99"}', "exit_ip_mismatch"),
            (b"not JSON", "invalid_egress_response"),
            (b"[]", "invalid_egress_response"),
            (b"null", "invalid_egress_response"),
            (b"{}", "invalid_egress_response"),
            (b'{"ip":123}', "invalid_egress_response"),
            (b'{"ip":"not an IP"}', "invalid_egress_response"),
            (b'{"ip":"fe80::1%en0"}', "invalid_egress_response"),
            (b"\xff", "invalid_egress_response"),
        ]
        for body, error in cases:
            with self.subTest(body=body):
                self.enqueue(http_response(BODY))
                self.enqueue(http_response(body))
                result = self.defaults()
                self.assert_failed(result, error)
                self.assertFalse(result["exit_ip_verified"])
                self.assertEqual(result["body_bytes"], len(BODY))

    def test_egress_status_and_body_limits(self):
        for response, code in [
            (http_response(EGRESS, status=503), "egress_http_status"),
            (http_response(EGRESS, headers={"Content-Length": "100"}), "invalid_http"),
            (http_response(b"x" * 16385), "response_too_large"),
            (http_response(b"x" * 16385, chunked=True), "response_too_large"),
        ]:
            with self.subTest(code=code):
                self.enqueue(http_response(BODY))
                self.enqueue(response)
                self.assert_failed(self.defaults(), code)

    def test_close_delimited_responses_and_custom_sample_size(self):
        self.enqueue(b"HTTP/1.1 200 OK\r\n\r\n" + BODY + BODY)
        self.enqueue(b"HTTP/1.1 200 OK\r\n\r\n" + EGRESS)
        result = self.defaults(bytes_required=262144)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["body_bytes"], 262144)

    def test_multiple_expected_addresses_accepts_any_exact_match(self):
        self.success_responses()
        result = self.defaults(expected_exit_ips=["192.0.2.1", "203.0.113.10"])
        self.assertTrue(result["success"], result)

    def test_egress_chunk_framing_overhead_is_bounded(self):
        self.enqueue(http_response(BODY))
        response = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + b"1;"
            + b"x" * 65000
            + b"\r\nx\r\n"
            + b"1;"
            + b"x" * 65000
            + b"\r\nx\r\n0\r\n\r\n"
        )
        self.enqueue(response)
        self.assert_failed(self.defaults(), "response_too_large")

    def test_absolute_deadline_catches_slow_socks_headers_and_body(self):
        for fragment, timeout in [(1, 0.005), (1, 0.04), (128, 0.08)]:
            with self.subTest(fragment=fragment, timeout=timeout):
                self.enqueue(http_response(BODY), fragment=fragment, delay=0.001)
                self.assert_failed(self.defaults(timeout=timeout), "timeout")

    def test_absolute_deadline_is_shared_by_both_requests(self):
        self.enqueue(http_response(BODY))
        self.enqueue(http_response(EGRESS), delay=0.01)
        result = self.defaults(timeout=0.065)
        self.assert_failed(result, "timeout")
        self.assertEqual(result["body_bytes"], len(BODY))
        self.assertEqual(len(self.sockets), 2)
        self.assertGreater(result["total_time_ms"], result["download_time_ms"])

    def test_chunk_extensions_and_trailers_are_also_deadline_bounded(self):
        self.enqueue(http_response(BODY))
        response = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{len(EGRESS):x};extension=yes\r\n".encode()
            + EGRESS
            + b"\r\n0\r\n"
            + b"Trailer: trickle\r\n" * 1000
            + b"\r\n"
        )
        self.enqueue(response, fragment=1)
        self.assert_failed(self.defaults(timeout=0.3), "timeout")


if __name__ == "__main__":
    unittest.main()
