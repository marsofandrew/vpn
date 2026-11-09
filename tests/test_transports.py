"""Stdlib transport regression tests.

Optional pinned native validation:
  XRAY_BINARY=/path/to/xray python3 -m unittest discover -s tests -p test_transports.py
or XRAY_TRANSPORT_INTEGRATION=1 (Docker, XRAY_TEST_IMAGE defaults to
 teddysun/xray:25.3.6). Native checks assert the version before testing configs.
"""

import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import vpn_transports as transports


CLIENT_ID = "11111111-2222-3333-4444-555555555555"
PUBLIC_KEY = "pOCSkrZRwni5dyxWn1-puxPZBrRqtoyd-dwrRAn4ogk"
PRIVATE_KEY = "AAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAUE"


def link(network="tcp", security="reality", **changes):
    params = {"encryption": "none", "type": network, "security": security,
              "sni": "example.com"}
    if security == "reality":
        params.update(pbk=PUBLIC_KEY, sid="ab12", fp="chrome", spx="/")
    if network == "xhttp":
        params.update(path="/vpn/", host="cdn.example.com", mode="stream-one" if security == "reality" else "auto")
    params.update(changes)
    params = {k: v for k, v in params.items() if v is not None}
    return "vless://" + CLIENT_ID + "@proxy.example.com:8443?" + urlencode(params, quote_via=quote)


def upstream(network="tcp", security="reality", **changes):
    return transports.parse_link(link(network, security, **changes))


def server_security(security="reality"):
    if security == "reality":
        settings = {"server_name": "example.com", "target": "example.com:443",
                    "private_key": PRIVATE_KEY, "short_ids": ["", "ab12"]}
    else:
        settings = {"certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]}
    return {"type": security, "settings": settings}


def changed(original, path, value):
    result = copy.deepcopy(original)
    node = result
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return result


class ParseTests(unittest.TestCase):
    def test_canonical_tcp_reality_shape_and_rendering(self):
        u = upstream(flow="xtls-rprx-vision")
        self.assertEqual(u, {
            "protocol": "vless", "auth": {"id": CLIENT_ID, "encryption": "none", "flow": "xtls-rprx-vision"},
            "address": "proxy.example.com", "port": 8443,
            "transport": {"type": "tcp", "settings": {}},
            "security": {"type": "reality", "settings": {"server_name": "example.com", "public_key": PUBLIC_KEY,
                         "short_id": "ab12", "fingerprint": "chrome", "spider_x": "/"}}, "enabled": True})
        self.assertEqual(transports.render_outbound(u, "exit"), {
            "tag": "exit", "protocol": "vless", "settings": {"vnext": [{"address": "proxy.example.com", "port": 8443,
                "users": [{"id": CLIENT_ID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": "example.com", "publicKey": PUBLIC_KEY, "shortId": "ab12", "fingerprint": "chrome", "spiderX": "/"}}})

    def test_xhttp_reality_shape_and_stream(self):
        u = upstream("xhttp", "reality", path="/entry?token=a+b&n=1", host="cdn.example.com:443")
        self.assertEqual(u["auth"]["flow"], "")
        stream = transports.render_outbound(u, "exit")["streamSettings"]
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["xhttpSettings"], {"path": "/entry?token=a+b&n=1", "host": "cdn.example.com:443", "mode": "stream-one"})
        self.assertNotIn("flow", transports.render_outbound(u, "exit")["settings"]["vnext"][0]["users"][0])

    def test_tls_all_modes_and_secure_defaults(self):
        for mode in ("auto", "packet-up", "stream-up", "stream-one"):
            with self.subTest(mode=mode):
                u = upstream("xhttp", "tls", mode=mode)
                self.assertEqual(u["security"]["settings"], {"server_name": "example.com", "alpn": ["h2", "http/1.1"], "allow_insecure": False})
                stream = transports.render_stream(u["transport"], u["security"])
                self.assertEqual(stream["tlsSettings"], {"serverName": "example.com", "alpn": ["h2", "http/1.1"], "allowInsecure": False})
                self.assertEqual(stream["xhttpSettings"]["mode"], mode)

    def test_minimal_inputs_and_defaults(self):
        u = transports.parse_link("vless://" + CLIENT_ID + "@example.com?type=xhttp&security=tls")
        self.assertEqual(u["port"], 443)
        self.assertEqual(u["transport"]["settings"], {"path": "/", "host": "", "mode": "auto"})
        self.assertEqual(u["security"]["settings"]["server_name"], "example.com")
        minimal_tls = {"type": "tls", "settings": {"server_name": "example.com"}}
        self.assertFalse(transports.render_stream({"type": "xhttp"}, minimal_tls)["tlsSettings"]["allowInsecure"])
        u = upstream("xhttp", mode=None, host=None, path=None, fp=None, spx=None, flow=None, encryption=None)
        self.assertEqual(u["transport"]["settings"], {"path": "/", "host": "", "mode": "stream-one"})
        self.assertEqual(u["security"]["settings"]["fingerprint"], "chrome")

    def test_empty_short_id_and_alias_are_preserved(self):
        for param in ("sid", "shortid"):
            with self.subTest(param=param):
                params = {"sid": None}
                params[param] = ""
                u = transports.parse_link(link(**params))
                self.assertEqual(u["security"]["settings"]["short_id"], "")
                self.assertIn("sid=", transports.export_link(u))
                self.assertEqual(transports.parse_link(transports.export_link(u)), u)

    def test_normalizes_uuid_dns_ip_and_fingerprint(self):
        u = transports.parse_link(link(sid="ABCD", fp="Chrome").replace("proxy.example.com", "PROXY.example.com").replace(CLIENT_ID, CLIENT_ID.replace("-", "")))
        self.assertEqual(u["auth"]["id"], CLIENT_ID)
        self.assertEqual(u["address"], "proxy.example.com")
        self.assertEqual(u["security"]["settings"]["short_id"], "abcd")
        for address in ("192.0.2.1", "[2001:db8::1]"):
            with self.subTest(address=address):
                u = transports.parse_link(link().replace("proxy.example.com", address))
                self.assertEqual(transports.parse_link(transports.export_link(u)), u)

    def test_roundtrips_ipv6_queries_percent_plus_and_unicode_label(self):
        for network, security in (("tcp", "reality"), ("xhttp", "reality"), ("xhttp", "tls")):
            with self.subTest(network=network, security=security):
                u = upstream(network, security)
                u["address"] = "2001:db8::1"
                if network == "xhttp":
                    u["transport"]["settings"].update(path="/vpn/%61?token=a+b&literal=%2B", host="[2001:db8::2]:8443")
                exported = transports.export_link(u, "Lisboa + 東京 #1")
                self.assertIn("@[2001:db8::1]:8443?", exported)
                self.assertTrue(exported.endswith("#Lisboa%20%2B%20%E6%9D%B1%E4%BA%AC%20%231"))
                self.assertEqual(transports.parse_link(exported), u)
                self.assertEqual(transports.export_link(transports.parse_link(exported), "Lisboa + 東京 #1"), exported)
                if network == "xhttp":
                    self.assertEqual(parse_qs(urlsplit(exported).query)["path"], [u["transport"]["settings"]["path"]])

    def test_tls_explicit_alpn_and_verification_false(self):
        for alpn in ("h2", "http/1.1", "h3", "h2,http/1.1"):
            for insecure in ("0", "false"):
                with self.subTest(alpn=alpn, insecure=insecure):
                    u = upstream("xhttp", "tls", alpn=alpn, allowInsecure=insecure)
                    self.assertEqual(u["security"]["settings"]["alpn"], alpn.split(","))
                    self.assertEqual(transports.parse_link(transports.export_link(u)), u)

    def test_rejects_malformed_and_ambiguous_links(self):
        valid = link()
        invalid = [None, {}, b"vless://", "", " " + valid, valid + "\n", valid.replace("vless://", "vmess://"),
                   valid.replace(CLIENT_ID, "secret-invalid-id"), valid.replace(CLIENT_ID + "@", ""),
                   valid.replace(CLIENT_ID + "@", CLIENT_ID + ":password@"), valid.replace("@proxy", "@@proxy"),
                   valid.replace(":8443", ":0"), valid.replace(":8443", ":65536"), valid.replace(":8443", ":abc"),
                   valid.replace(":8443", ":"), valid.replace("proxy.example.com", "[::1]junk"),
                   valid.replace("proxy.example.com", "[v1.example]"), valid.replace("proxy.example.com", "2001:db8::1"),
                   valid.replace("proxy.example.com", "example.com\\evil"), valid.replace("proxy.example.com", "bad%20host"),
                   valid.replace(":8443?", ":8443/evil?"), valid + "&unknown=secret", valid + "&type=tcp", valid + "&%74ype=tcp",
                   valid + "&shortid=ab12", valid + "&sid=", valid + "&broken", valid + "&fp=%ZZ", valid + "&fp=%FF",
                   valid + "#%FF", valid + "&security=tls", valid + "&extra=%7B%7D"]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    transports.parse_link(value)

    def test_rejects_unsupported_or_cross_security_parameters(self):
        cases = [link(security="none"), link(security="tls"), link(network="ws"), link(encryption="aes-128-gcm"),
                 link(headerType="http"), link(path="/"), link(host="example.com"), link(mode="stream-one"),
                 link("xhttp", headerType="none"), link(alpn="h2"), link(allowInsecure="0"), link(sid=None),
                 link(pbk=None), link(sni=None), link(fp="unsafe"), link(fp="hellogolang"), link(fp="unknown"),
                 link("xhttp", flow="xtls-rprx-vision"), link("xhttp", "tls", flow="xtls-rprx-vision-udp443"),
                 link("xhttp", "tls", pbk=PUBLIC_KEY), link("xhttp", "tls", sid="ab"),
                 link("xhttp", "tls", fp="chrome"), link("xhttp", "tls", spx="/")]
        cases += [link("xhttp", "reality", mode=m) for m in ("auto", "packet-up", "stream-up", "", "invalid")]
        cases += [link("xhttp", "tls", mode=m) for m in ("", "invalid", "STREAM-ONE")]
        cases += [link("xhttp", "tls", allowInsecure=v) for v in ("1", "true", "False", "", "yes")]
        cases += [link("xhttp", "tls", alpn=v) for v in ("", "h2,h2", "h2,", "h2,h3", "foo", "h2, http/1.1")]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    transports.parse_link(value)


class ValidationTests(unittest.TestCase):
    def test_all_apis_are_pure_and_results_are_independent(self):
        u = upstream("xhttp", "tls")
        original = copy.deepcopy(u)
        self.assertIsNone(transports.validate_upstream(u))
        outbound = transports.render_outbound(u, "exit")
        transports.export_link(u)
        stream = transports.render_stream(u["transport"], u["security"])
        outbound["streamSettings"]["tlsSettings"]["alpn"].clear()
        stream["tlsSettings"]["alpn"].append("invalid")
        self.assertEqual(u, original)
        security = server_security("tls")
        before = copy.deepcopy(security)
        stream = transports.render_stream({"type": "xhttp"}, security, server=True)
        stream["tlsSettings"]["certificates"][0]["keyFile"] = "changed"
        self.assertEqual(security, before)

    def test_validate_and_render_reject_bad_shapes_and_types(self):
        u = upstream()
        mutations = [(("protocol",), v) for v in (None, [], "vmess")]
        mutations += [(("port",), v) for v in (True, False, 0, 65536, -1, "443", 443.0, None)]
        mutations += [(("enabled",), v) for v in (0, 1, "true", None)]
        mutations += [(("auth",), v) for v in (None, [], {}, {"id": CLIENT_ID, "password": "secret"})]
        mutations += [(("auth", "id"), v) for v in (None, [], 10, "", "invalid")]
        mutations += [(("auth", "flow"), v) for v in (None, [], "vision", "xtls-rprx-direct")]
        mutations += [(("auth", "encryption"), "aes")]
        mutations += [(("transport",), v) for v in (None, [], {}, {"type": "ws"}, {"type": "tcp", "settings": {"host": "example.com"}})]
        mutations += [(("transport", "type"), v) for v in (None, [], {}, "grpc")]
        mutations += [(("security",), v) for v in (None, [], {}, {"type": "tls", "settings": {"server_name": "example.com"}})]
        mutations += [(("security", "type"), v) for v in (None, [], {}, "none")]
        mutations += [(("security", "settings"), v) for v in (None, [], {}, {"server_name": "example.com", "private_key": PRIVATE_KEY})]
        for path, value in mutations:
            bad = changed(u, path, value)
            for api in (transports.validate_upstream, lambda x: transports.render_outbound(x, "exit"), transports.export_link):
                with self.subTest(path=path, value=value, api=api):
                    with self.assertRaises(ValueError):
                        api(bad)
        for value in (None, [], {}, "link", False):
            with self.subTest(top=value):
                with self.assertRaises(ValueError):
                    transports.validate_upstream(value)
        for field in u:
            bad = copy.deepcopy(u)
            del bad[field]
            if field == "enabled":
                transports.validate_upstream(bad)
            else:
                with self.assertRaises(ValueError):
                    transports.validate_upstream(bad)

    def test_strict_host_and_path_validation_on_both_entry_points(self):
        bad_hosts = ["https://example.com", "foo/bar", "foo?bar", "foo#bar", "user@host", "bad host", "example.com\r\nX:a",
                     "a..b", "-host", "host-", "host_foo", "999.0.0.1", "[::1]junk", "[v1.foo]", "host:", "host:0", "host:65536", "::1", "host:abc"]
        bad_paths = ["", "relative", "https://example.com/x", "//host/path", "/x#fragment", "/a\\b", "/white space", "/\n", "/%0d%0a",
                     "/bad%", "/bad%GG", "/%FF", "/a/../b", "/%2e%2e/b", "/a/./b", "/%5c", "/%23fragment", "/%2fhost"]
        for field, values in (("host", bad_hosts), ("path", bad_paths)):
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        upstream("xhttp", "tls", **{field: value})
                    bad = upstream("xhttp", "tls")
                    bad["transport"]["settings"][field] = value
                    with self.assertRaises(ValueError):
                        transports.render_stream(bad["transport"], bad["security"])
        for value in bad_paths:
            with self.subTest(spider_x=value):
                with self.assertRaises(ValueError):
                    upstream(spx=value)
        for field in ("address", "server_name"):
            for value in ("", "host:443", "[::1]", "foo/bar", "bad host", None, "a" * 64 + ".com"):
                with self.subTest(field=field, value=value):
                    bad = upstream()
                    if field == "address":
                        bad[field] = value
                    else:
                        bad["security"]["settings"][field] = value
                    with self.assertRaises(ValueError):
                        transports.validate_upstream(bad)

    def test_reality_keys_and_short_ids(self):
        for value in ("bad-key", PUBLIC_KEY + "=", PUBLIC_KEY[:-1], "!" * 43, base64.urlsafe_b64encode(b"short").decode(), None, [], 123):
            with self.subTest(key=value):
                bad = changed(upstream(), ("security", "settings", "public_key"), value)
                with self.assertRaises(ValueError):
                    transports.validate_upstream(bad)
        for value in ("a", "abc", "x1", "ab" * 9, None, [], 10):
            with self.subTest(sid=value):
                bad = changed(upstream(), ("security", "settings", "short_id"), value)
                with self.assertRaises(ValueError):
                    transports.validate_upstream(bad)
        for value in ("", "00", "0123456789abcdef"):
            self.assertEqual(upstream(sid=value)["security"]["settings"]["short_id"], value)

    def test_tls_settings_require_actual_false_and_valid_alpn(self):
        u = upstream("xhttp", "tls")
        for value in (True, 0, 1, None, "false", []):
            with self.subTest(allow_insecure=value):
                bad = changed(u, ("security", "settings", "allow_insecure"), value)
                with self.assertRaises(ValueError):
                    transports.validate_upstream(bad)
        for value in ([], "h2", ["h2", "h2"], ["h3", "h2"], [None], [[]]):
            with self.subTest(alpn=value):
                bad = changed(u, ("security", "settings", "alpn"), value)
                with self.assertRaises(ValueError):
                    transports.validate_upstream(bad)

    def test_disabled_flag_and_optional_defaults(self):
        u = upstream()
        u["enabled"] = False
        self.assertIsNone(transports.validate_upstream(u))
        with self.assertRaisesRegex(ValueError, "disabled"):
            transports.render_outbound(u, "exit")
        with self.assertRaisesRegex(ValueError, "disabled"):
            transports.export_link(u)
        u = upstream("xhttp", "tls")
        del u["auth"]["flow"]
        del u["auth"]["encryption"]
        del u["security"]["settings"]["alpn"]
        del u["security"]["settings"]["allow_insecure"]
        self.assertIsNone(transports.validate_upstream(u))
        self.assertFalse(transports.render_outbound(u, "exit")["streamSettings"]["tlsSettings"]["allowInsecure"])

    def test_safe_errors_contain_no_input_secrets(self):
        secret = "SECRET-uuid-key-link-label"
        bad_inputs = [lambda: transports.parse_link("vless://" + secret + ":password@example.com?security=tls"),
                      lambda: transports.parse_link(link(pbk=secret)),
                      lambda: transports.validate_upstream(changed(upstream(), ("auth", "id"), secret)),
                      lambda: transports.validate_upstream(changed(upstream(), ("security", "settings", "public_key"), secret)),
                      lambda: transports.validate_upstream(dict(upstream(), **{secret: secret})),
                      lambda: transports.render_stream({"type": "xhttp", "settings": {secret: secret}}, server_security(), True)]
        for call in bad_inputs:
            with self.subTest(call=call):
                with self.assertRaises(ValueError) as caught:
                    call()
                self.assertNotIn(secret, str(caught.exception))
                self.assertNotIn("vless://", str(caught.exception))


class ServerTests(unittest.TestCase):
    def test_reality_inbound_native_shape(self):
        for network in ("tcp", "xhttp"):
            with self.subTest(network=network):
                result = transports.render_stream({"type": network}, server_security(), server=True)
                self.assertEqual(result["realitySettings"], {"target": "example.com:443", "serverNames": ["example.com"],
                                 "privateKey": PRIVATE_KEY, "shortIds": ["", "ab12"]})
                if network == "xhttp":
                    self.assertEqual(result["xhttpSettings"], {"path": "/", "host": "", "mode": "stream-one"})
                self.assertNotIn("publicKey", result["realitySettings"])

    def test_tls_inbound_native_certificates(self):
        result = transports.render_stream({"type": "xhttp"}, server_security("tls"), server=True)
        self.assertEqual(result, {"network": "xhttp", "security": "tls", "xhttpSettings": {"path": "/", "host": "", "mode": "auto"},
            "tlsSettings": {"alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]}})
        security = server_security("tls")
        security["settings"].update(server_name="example.com", alpn=["h3"])
        result = transports.render_stream({"type": "xhttp"}, security, True)
        self.assertEqual(result["tlsSettings"]["serverName"], "example.com")
        self.assertEqual(result["tlsSettings"]["alpn"], ["h3"])

    def test_reality_server_validation_and_no_client_field_leaks(self):
        cases = [(("target",), v) for v in (None, "example.com", "https://example.com:443", "example.com:0", "/unix.sock", "[::1]junk:443")]
        cases += [(("private_key",), v) for v in ("", "secret-key", None)]
        cases += [(("short_ids",), v) for v in ([], "ab", ["a"], [None], ["ab", "AB"], ["ab" * 9])]
        cases += [(("server_name",), v) for v in ("", "example.com:443", "bad host")]
        for path, value in cases:
            security = copy.deepcopy(server_security())
            security["settings"][path[0]] = value
            with self.subTest(path=path, value=value):
                with self.assertRaises(ValueError):
                    transports.render_stream({"type": "xhttp"}, security, server=True)
        for field in ("public_key", "short_id", "fingerprint", "spider_x", "unknown"):
            security = server_security()
            security["settings"][field] = "secret"
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    transports.render_stream({"type": "tcp"}, security, True)
        for mode in ("auto", "packet-up", "stream-up", "bad"):
            with self.assertRaises(ValueError):
                transports.render_stream({"type": "xhttp", "settings": {"mode": mode}}, server_security(), True)
        security = server_security()
        security["settings"]["target"] = "[2001:db8::1]:443"
        self.assertEqual(transports.render_stream({"type": "tcp"}, security, True)["realitySettings"]["target"], "[2001:db8::1]:443")

    def test_tls_server_rejects_invalid_certificates_and_client_fields(self):
        for certs in (None, [], {}, [None], [{}], [{"certificateFile": "cert"}], [{"certificateFile": "cert", "keyFile": ""}],
                      [{"certificateFile": "cert\nsecret", "keyFile": "key"}], [{"certificateFile": "cert", "keyFile": "key", "usage": "verify"}]):
            with self.subTest(certs=certs):
                with self.assertRaises(ValueError):
                    transports.render_stream({"type": "xhttp"}, {"type": "tls", "settings": {"certificates": certs}}, True)
        for field in ("allow_insecure", "private_key", "public_key"):
            security = server_security("tls")
            security["settings"][field] = False
            with self.assertRaises(ValueError):
                transports.render_stream({"type": "xhttp"}, security, True)
        for security in (server_security(), server_security("tls")):
            with self.assertRaises(ValueError):
                transports.render_stream({"type": "xhttp"}, security)  # server fields cannot enter client configs
        with self.assertRaises(ValueError):
            transports.render_stream({"type": "tcp"}, server_security("tls"), True)
        with self.assertRaises(ValueError):
            transports.render_stream({"type": "tcp"}, server_security(), server="yes")


@unittest.skipUnless(os.environ.get("XRAY_BINARY") or os.environ.get("XRAY_TRANSPORT_INTEGRATION") == "1",
                     "set XRAY_BINARY or XRAY_TRANSPORT_INTEGRATION=1 for pinned native validation")
class NativeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vpn-transports-native-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        binary = os.environ.get("XRAY_BINARY")
        self.runtime_root = str(self.root) if binary else "/work"
        self.command = [binary] if binary else ["docker", "run", "--rm", "-i", "--network", "none", "--entrypoint", "xray",
            "-v", str(self.root) + ":/work:ro", os.environ.get("XRAY_TEST_IMAGE", "teddysun/xray:25.3.6")]
        version = self.native("version")
        self.assertRegex(version, r"\AXray 25\.3\.6 \(")

    def native(self, *args, config=None):
        result = subprocess.run(self.command + list(args), input=json.dumps(config) if config is not None else None,
                                text=True, capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def validate(self, config):
        self.assertIn("Configuration OK.", self.native("run", "-test", "-config", "stdin:", config=config))

    def test_native_all_supported_outbound_combinations(self):
        outbounds = [transports.render_outbound(upstream(flow="xtls-rprx-vision"), "tcp-reality"),
                     transports.render_outbound(upstream("xhttp", "reality"), "xhttp-reality")]
        outbounds += [transports.render_outbound(upstream("xhttp", "tls", mode=mode), "tls-" + mode)
                      for mode in ("auto", "packet-up", "stream-up", "stream-one")]
        self.validate({"outbounds": outbounds})

    def test_native_all_supported_inbound_combinations(self):
        certificate = json.loads(self.native("tls", "cert", "-domain", "example.com"))
        for field, name in (("certificate", "cert.pem"), ("key", "key.pem")):
            (self.root / name).write_text("\n".join(certificate[field]) + "\n")
        security = server_security("tls")
        security["settings"]["certificates"] = [{"certificateFile": self.runtime_root + "/cert.pem", "keyFile": self.runtime_root + "/key.pem"}]
        streams = [transports.render_stream({"type": network}, server_security(), True) for network in ("tcp", "xhttp")]
        streams += [transports.render_stream({"type": "xhttp", "settings": {"mode": mode}}, security, True)
                    for mode in ("auto", "packet-up", "stream-up", "stream-one")]
        self.validate({"inbounds": [{"listen": "127.0.0.1", "port": 20000 + index, "protocol": "vless",
            "settings": {"clients": [{"id": CLIENT_ID}], "decryption": "none"}, "streamSettings": stream}
            for index, stream in enumerate(streams)], "outbounds": [{"protocol": "freedom"}]})

    def test_native_reality_mode_parser_is_broader_than_pr2_policy(self):
        outbound = transports.render_outbound(upstream("xhttp", "reality"), "exit")
        for mode in ("auto", "packet-up", "stream-up", "stream-one"):
            with self.subTest(mode=mode):
                outbound["streamSettings"]["xhttpSettings"]["mode"] = mode
                self.validate({"outbounds": [outbound]})


if __name__ == "__main__":
    unittest.main()
