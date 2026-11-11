from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from vpn_manager.transports.fields import _BAD_PERCENT, _authority, _text
from vpn_manager.transports.validation import _upstream


def parse_link(link: str) -> dict:
    """Parse a VLESS URI into the canonical upstream shape, with explicit defaults.

    Only supported parameters are accepted; duplicates (including sid/shortid)
    are errors. A missing port defaults to 443, type to tcp, encryption to none,
    and flow to ''. Security must be explicit. The optional label is discarded.
    TLS ech maps to ech_config_list and enforces full; empty ech is omitted.
    """
    parsed, client_id, address, port, pairs = _link_syntax(link)
    query = _link_query(pairs)
    network, sec = _link_transport(query)
    settings = _link_security(query, sec, address)
    return _link_data(client_id, address, port, query, network, sec, settings)


def _link_data(client_id, address, port, query, network, sec, settings):
    return _upstream(
        {
            "protocol": "vless",
            "auth": {
                "id": client_id,
                "encryption": query.get("encryption", "none"),
                "flow": query.get("flow", ""),
            },
            "address": address,
            "port": 443 if port is None else port,
            "transport": {
                "type": network,
                "settings": {
                    k: query[k] for k in ("path", "host", "mode") if k in query
                },
            },
            "security": {"type": sec, "settings": settings},
            "enabled": True,
        }
    )


def _link_syntax(link):
    link = _text(link, "link")
    if len(link) > 16384 or any(c.isspace() for c in link) or _BAD_PERCENT.search(link):
        raise ValueError("link has invalid characters or encoding")
    try:
        parsed = urlsplit(link)
        if (
            parsed.scheme != "vless"
            or not parsed.netloc
            or parsed.password is not None
            or parsed.netloc.count("@") != 1
            or parsed.path not in {"", "/"}
        ):
            raise ValueError
        client_id = unquote(parsed.username or "", errors="strict")
        address = parsed.hostname
        port = parsed.port
        if not address or parsed.netloc.endswith(":"):
            raise ValueError
        _authority(parsed.netloc.rsplit("@", 1)[1], "address")
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=32,
        )
        _text(unquote(parsed.fragment, errors="strict"), "label", empty=True)
    except (ValueError, UnicodeError):
        raise ValueError("invalid VLESS link syntax") from None
    return parsed, client_id, address, port, pairs


def _link_query(pairs):
    query = {}
    for key, value in pairs:
        if key not in _QUERY_PARAMETERS:
            raise ValueError("link contains an unsupported parameter")
        key = "sid" if key == "shortid" else key
        if key in query:
            raise ValueError("link contains duplicate parameters")
        query[key] = value
    return query


def _link_transport(query):
    network, sec = query.get("type", "tcp"), query.get("security")
    if query.get("headerType", "none") != "none":
        raise ValueError("only headerType none is supported")
    if network != "tcp" and "headerType" in query:
        raise ValueError("headerType is only supported for tcp")
    if network == "tcp" and any(k in query for k in ("path", "host", "mode")):
        raise ValueError("tcp does not support xhttp parameters")
    return network, sec


def _link_security(query, sec, address):
    settings: dict[str, Any]
    if sec == "reality":
        if any(k in query for k in ("alpn", "allowInsecure", "ech")):
            raise ValueError("reality does not support tls parameters")
        if not {"sni", "pbk", "sid"} <= query.keys():
            raise ValueError("reality link requires sni, pbk and sid")
        settings = {
            "server_name": query["sni"],
            "public_key": query["pbk"],
            "short_id": query["sid"],
            "fingerprint": query.get("fp", "chrome"),
            "spider_x": query.get("spx", "/"),
        }
    elif sec == "tls":
        if any(k in query for k in ("pbk", "sid", "fp", "spx")):
            raise ValueError("tls does not support reality parameters")
        if query.get("allowInsecure", "false") not in {"false", "0"}:
            raise ValueError("allowInsecure must be false")
        settings = {"server_name": query.get("sni", address)}
        if "alpn" in query:
            settings["alpn"] = query["alpn"].split(",")
        if "ech" in query:
            settings["ech_config_list"] = query["ech"]
    else:
        raise ValueError("link security must be reality or tls")
    return settings


_QUERY_PARAMETERS = {
    "type",
    "security",
    "encryption",
    "flow",
    "sni",
    "pbk",
    "sid",
    "shortid",
    "fp",
    "spx",
    "path",
    "host",
    "mode",
    "alpn",
    "allowInsecure",
    "headerType",
    "ech",
}


def export_link(upstream: dict, label: str = "") -> str:
    """Export a deterministic, percent-encoded VLESS client URI."""
    u = _upstream(upstream)
    label = _text(label, "label", empty=True)
    if not u["enabled"]:
        raise ValueError("upstream is disabled")
    t, s = u["transport"], u["security"]
    ss = s["settings"]
    params = {
        "encryption": "none",
        "type": t["type"],
        "security": s["type"],
        "sni": ss["server_name"],
    }
    if u["auth"]["flow"]:
        params["flow"] = u["auth"]["flow"]
    if t["type"] == "xhttp":
        params.update(t["settings"])
    if s["type"] == "reality":
        params.update(
            {
                "pbk": ss["public_key"],
                "sid": ss["short_id"],
                "fp": ss["fingerprint"],
                "spx": ss["spider_x"],
            }
        )
    else:
        params["alpn"] = ",".join(ss["alpn"])
        params["allowInsecure"] = "0"
        if "ech_config_list" in ss:
            params["ech"] = ss["ech_config_list"]
    address = "[" + u["address"] + "]" if ":" in u["address"] else u["address"]
    return (
        "vless://"
        + u["auth"]["id"]
        + "@"
        + address
        + ":"
        + str(u["port"])
        + "?"
        + urlencode(params, quote_via=quote, safe="")
        + ("#" + quote(label, safe="") if label else "")
    )
