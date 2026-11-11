"""Synthetic VLESS builders and mutation data for transport tests."""

import base64
import copy
from urllib.parse import quote, urlencode

import vpn_transports as transports

CLIENT_ID = "11111111-2222-3333-4444-555555555555"

PUBLIC_KEY = "pOCSkrZRwni5dyxWn1-puxPZBrRqtoyd-dwrRAn4ogk"

PRIVATE_KEY = "AAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAUE"

ECH_CONFIG = base64.b64encode(b"\xfb\xff").decode("ascii")


def link(network="tcp", security="reality", **changes):
    params = {
        "encryption": "none",
        "type": network,
        "security": security,
        "sni": "example.com",
    }
    if security == "reality":
        params.update(pbk=PUBLIC_KEY, sid="ab12", fp="chrome", spx="/")
    if network == "xhttp":
        params.update(
            path="/vpn/",
            host="cdn.example.com",
            mode="stream-one" if security == "reality" else "auto",
        )
    params.update(changes)
    params = {k: v for k, v in params.items() if v is not None}
    return (
        "vless://"
        + CLIENT_ID
        + "@proxy.example.com:8443?"
        + urlencode(params, quote_via=quote)
    )


def upstream(network="tcp", security="reality", **changes):
    return transports.parse_link(link(network, security, **changes))


def server_security(security="reality"):
    if security == "reality":
        settings = {
            "server_name": "example.com",
            "target": "example.com:443",
            "private_key": PRIVATE_KEY,
            "short_ids": ["", "ab12"],
        }
    else:
        settings = {
            "certificates": [
                {
                    "certificateFile": "/etc/xray/cert.pem",
                    "keyFile": "/etc/xray/key.pem",
                }
            ]
        }
    return {"type": security, "settings": settings}


def changed(original, path, value):
    result = copy.deepcopy(original)
    node = result
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return result


BAD_UPSTREAM_MUTATIONS = [(("protocol",), v) for v in (None, [], "vmess")]
BAD_UPSTREAM_MUTATIONS += [
    (("port",), v) for v in (True, False, 0, 65536, -1, "443", 443.0, None)
]
BAD_UPSTREAM_MUTATIONS += [(("enabled",), v) for v in (0, 1, "true", None)]
BAD_UPSTREAM_MUTATIONS += [
    (("auth",), v) for v in (None, [], {}, {"id": CLIENT_ID, "password": "secret"})
]
BAD_UPSTREAM_MUTATIONS += [(("auth", "id"), v) for v in (None, [], 10, "", "invalid")]
BAD_UPSTREAM_MUTATIONS += [
    (("auth", "flow"), v) for v in (None, [], "vision", "xtls-rprx-direct")
]
BAD_UPSTREAM_MUTATIONS += [(("auth", "encryption"), "aes")]
BAD_UPSTREAM_MUTATIONS += [
    (("transport",), v)
    for v in (
        None,
        [],
        {},
        {"type": "ws"},
        {"type": "tcp", "settings": {"host": "example.com"}},
    )
]
BAD_UPSTREAM_MUTATIONS += [(("transport", "type"), v) for v in (None, [], {}, "grpc")]
BAD_UPSTREAM_MUTATIONS += [
    (("security",), v)
    for v in (
        None,
        [],
        {},
        {"type": "tls", "settings": {"server_name": "example.com"}},
    )
]
BAD_UPSTREAM_MUTATIONS += [(("security", "type"), v) for v in (None, [], {}, "none")]
BAD_UPSTREAM_MUTATIONS += [
    (("security", "settings"), v)
    for v in (
        None,
        [],
        {},
        {"server_name": "example.com", "private_key": PRIVATE_KEY},
    )
]
