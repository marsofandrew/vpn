"""Opt-in pinned Xray syntax checks; these do not start a live server.

Run with XRAY_INTEGRATION=1 python3 -m unittest discover -s tests \
    -p test_native_transports.py -v
Set XRAY_TEST_IMAGE to use an alternate image.
"""

import base64
import copy
import datetime
import importlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(
    os.environ.get("XRAY_INTEGRATION") == "1",
    "set XRAY_INTEGRATION=1 for native Docker validation",
)
class NativeTransportTests(unittest.TestCase):
    XHTTP_MODES = ("auto", "packet-up", "stream-up", "stream-one")

    @classmethod
    def setUpClass(cls):
        cls.transports = importlib.import_module("vpn_transports")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, x25519
        from cryptography.x509.oid import NameOID

        cls.image = os.environ.get("XRAY_TEST_IMAGE", "ghcr.io/xtls/xray-core:26.10.31")
        temporary = tempfile.TemporaryDirectory(prefix="vpn-native-transports-")
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name).resolve()

        reality_key = x25519.X25519PrivateKey.generate()
        cls.private_key = (
            base64.urlsafe_b64encode(
                reality_key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            )
            .decode("ascii")
            .rstrip("=")
        )
        cls.public_key = (
            base64.urlsafe_b64encode(
                reality_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            )
            .decode("ascii")
            .rstrip("=")
        )

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vpn.example.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("vpn.example.test"),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        (cls.root / "certificate.pem").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )
        (cls.root / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    def endpoint(self, transport, security, mode="auto", address="vpn.example.test"):
        transport_settings = {}
        if transport == "xhttp":
            transport_settings = {
                "path": "/native/encoded%2Fsegment?token=a%26b",
                "host": "front.example.test",
                "mode": mode,
            }
        security_settings = {"server_name": "vpn.example.test"}
        if security == "reality":
            security_settings.update(
                {"public_key": self.public_key, "short_id": "a1b2c3d4"}
            )
        return {
            "protocol": "vless",
            "address": address,
            "port": 8443,
            "auth": {
                "id": "982a30f4-c7d1-4b63-9962-50a2ec93b8d1",
                "encryption": "none",
                "flow": "xtls-rprx-vision" if transport == "tcp" else "",
            },
            "transport": {"type": transport, "settings": transport_settings},
            "security": {"type": security, "settings": security_settings},
            "enabled": True,
        }

    def validate_native(self, config, label):
        path = self.root / f"{label}.json"
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "xray",
                "-v",
                f"{self.root}:/work:ro",
                self.image,
                "run",
                "-test",
                "-config",
                f"/work/{path.name}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"{label} rejected by {self.image}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn(
            "Xray " + self.transports.PINNED_XRAY_VERSION,
            result.stdout + result.stderr,
            "XRAY_TEST_IMAGE must provide the requested Xray version",
        )
        self.assertIn("Configuration OK", result.stdout + result.stderr)

    def assert_roundtrip(self, endpoint):
        self.transports.validate_upstream(endpoint)
        label = "native transport: spaces / unicode \u2603"
        link = self.transports.export_link(copy.deepcopy(endpoint), label)
        parsed = self.transports.parse_link(link)
        for field in ("protocol", "address", "port", "enabled"):
            self.assertEqual(parsed[field], endpoint[field], field)
        for section in ("auth", "transport", "security"):
            self.assertEqual(parsed[section].get("type"), endpoint[section].get("type"))
            expected = endpoint[section].get("settings", endpoint[section])
            actual = parsed[section].get("settings", parsed[section])
            for key, value in expected.items():
                self.assertEqual(actual[key], value, f"{section}.{key}")
        reparsed = self.transports.parse_link(
            self.transports.export_link(parsed, label)
        )
        self.assertEqual(reparsed, parsed)
        return parsed

    def check_outbound(self, transport, security):
        modes = self.modes(transport, security)
        for mode in modes:
            for address in ("vpn.example.test", "2001:db8::1"):
                with self.subTest(
                    transport=transport, security=security, mode=mode, address=address
                ):
                    endpoint = self.assert_roundtrip(
                        self.endpoint(transport, security, mode, address)
                    )
                    outbound = self.transports.render_outbound(endpoint, "upstream")
                    self.assertEqual(outbound["streamSettings"]["network"], transport)
                    self.assertEqual(outbound["streamSettings"]["security"], security)
                    if transport == "xhttp":
                        self.assertEqual(
                            outbound["streamSettings"]["xhttpSettings"],
                            endpoint["transport"]["settings"],
                        )
                    self.assertEqual(
                        outbound["settings"]["vnext"][0]["users"][0].get("flow", ""),
                        endpoint["auth"]["flow"],
                    )
                    config = {
                        "inbounds": [
                            {
                                "tag": "local",
                                "listen": "127.0.0.1",
                                "port": 1080,
                                "protocol": "socks",
                                "settings": {"auth": "noauth"},
                            }
                        ],
                        "outbounds": [outbound],
                    }
                    family = "ipv6" if ":" in address else "dns"
                    self.validate_native(
                        config, f"outbound-{transport}-{security}-{mode}-{family}"
                    )

    def modes(self, transport, security):
        if transport == "tcp":
            return ("auto",)
        return ("stream-one",) if security == "reality" else self.XHTTP_MODES

    def check_inbound(self, transport, security):
        modes = self.modes(transport, security)
        for mode in modes:
            with self.subTest(transport=transport, security=security, mode=mode):
                endpoint = self.endpoint(transport, security, mode)
                settings = endpoint["security"]["settings"]
                settings.pop("public_key", None)
                settings.pop("short_id", None)
                if security == "reality":
                    settings.update(
                        {
                            "private_key": self.private_key,
                            "short_ids": ["a1b2c3d4"],
                            "target": "www.example.com:443",
                        }
                    )
                else:
                    settings["certificates"] = [
                        {
                            "certificateFile": "/work/certificate.pem",
                            "keyFile": "/work/key.pem",
                        }
                    ]
                stream = self.transports.render_stream(
                    endpoint["transport"],
                    endpoint["security"],
                    server=True,
                )
                self.assertEqual(stream["network"], transport)
                self.assertEqual(stream["security"], security)
                if transport == "xhttp":
                    self.assertEqual(
                        stream["xhttpSettings"], endpoint["transport"]["settings"]
                    )
                config = {
                    "inbounds": [
                        {
                            "tag": "native",
                            "listen": "127.0.0.1",
                            "port": endpoint["port"],
                            "protocol": "vless",
                            "settings": {
                                "decryption": "none",
                                "clients": [
                                    {
                                        "id": endpoint["auth"]["id"],
                                        "flow": endpoint["auth"]["flow"],
                                    }
                                ],
                            },
                            "streamSettings": stream,
                        }
                    ],
                    "outbounds": [
                        {"tag": "direct", "protocol": "freedom", "settings": {}}
                    ],
                }
                self.validate_native(config, f"inbound-{transport}-{security}-{mode}")

    def test_tcp_reality_inbound(self):
        self.check_inbound("tcp", "reality")

    def test_tcp_reality_outbound_and_link_roundtrip(self):
        self.check_outbound("tcp", "reality")

    def test_xhttp_reality_inbound(self):
        self.check_inbound("xhttp", "reality")

    def test_xhttp_reality_outbound_and_link_roundtrip(self):
        self.check_outbound("xhttp", "reality")

    def test_xhttp_tls_inbound(self):
        self.check_inbound("xhttp", "tls")

    def test_xhttp_tls_outbound_and_link_roundtrip(self):
        self.check_outbound("xhttp", "tls")


if __name__ == "__main__":
    unittest.main()
