"""Strict, stdlib-only VLESS transports pinned to Xray 26.3.27.

Public API: parse_link, validate_upstream, render_outbound, export_link,
render_stream. Validation raises ValueError without including input values.
Validation/rendering never mutate inputs; validate_upstream returns None.

TCP settings are {}; XHTTP defaults to path='/', host='', and mode='auto'
(TLS) or 'stream-one' (REALITY). Missing auth flow defaults to ''. Client TLS
requires only server_name; alpn defaults to ['h2', 'http/1.1'] and
allow_insecure to False. Parsed links include all these defaults and enabled=True.
An explicit disabled upstream validates, but cannot be rendered or exported.

Server REALITY settings: target (host:port), server_name, private_key, short_ids.
Server TLS settings: certificates, a native list of {certificateFile, keyFile};
optional server_name and alpn. Certificate files are validated structurally,
not opened locally: their paths refer to the Xray runtime filesystem.

Optional TLS client ech_config_list accepts standard Base64 or HTTPS DNS
discovery, optionally lookupdomain+https://resolver/dns-query. Configured ECH
always uses ech_force_query='full'; other values are rejected. An empty client
ech_config_list or URI ech= is treated as omitted. ech_force_query without a
nonempty config is rejected. URI ech is percent-encoded ech_config_list; the
full policy is implied and has no separate URI parameter. Optional server
ech_server_keys accepts nonempty standard Base64. echSockopt is unsupported.
Existing non-ECH variants remain compatible with 25.3.6; ECH requires the
26.3.27 capability pin and cannot be rendered for REALITY.

Pinned validation sources (tag v26.3.27, commit d2758a0):
https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go
https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/tls/ech.go
https://github.com/XTLS/Xray-core/blob/v26.3.27/main/commands/all/tls/ech.go
https://github.com/XTLS/Xray-core/discussions/716

PR2 deliberately restricts XHTTP+REALITY to explicit stream-one, even though
native config parsing accepts other modes and native auto selects stream-one.
Paths/hosts and the supported field set are stricter than native config parsing.
"""

import base64
import binascii
import ipaddress
import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

PINNED_XRAY_VERSION = "26.3.27"

__all__ = [
    "PINNED_XRAY_VERSION",
    "parse_link",
    "validate_upstream",
    "render_outbound",
    "export_link",
    "render_stream",
]

_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
_FLOWS = {"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}
_FINGERPRINTS = set(
    """
chrome firefox safari ios android edge 360 qq random randomized randomizednoalpn
hellofirefox_99 hellofirefox_102 hellofirefox_105 hellofirefox_120
hellochrome_83 hellochrome_87 hellochrome_96 hellochrome_100 hellochrome_102
hellochrome_106_shuffle hellochrome_120 helloios_13 helloios_14 helloedge_85
helloedge_106 hellosafari_16_0 hello360_11_0 helloqq_11_1 hellorandomized
hellorandomizedalpn hellorandomizednoalpn hellofirefox_auto hellofirefox_55
hellofirefox_56 hellofirefox_63 hellofirefox_65 hellochrome_auto hellochrome_58
hellochrome_62 hellochrome_70 hellochrome_72 helloios_auto helloios_11_1
helloios_12_1 helloandroid_11_okhttp helloedge_auto hellosafari_auto
hello360_auto hello360_7_5 helloqq_auto
""".split()
)
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def _object(value, allowed, required, field):
    if not isinstance(value, dict):
        raise ValueError(field + " must be an object")
    if set(value) - set(allowed):
        raise ValueError(field + " contains unsupported fields")
    if set(required) - set(value):
        raise ValueError(field + " is missing required fields")
    return value


def _text(value, field, empty=False):
    if not isinstance(value, str) or (not value and not empty):
        raise ValueError(
            field + " must be a string" + ("" if empty else " and nonempty")
        )
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError(field + " contains invalid characters")
    return value


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return value


def _host(value, field="address", empty=False):
    value = _text(value, field, empty)
    if not value and empty:
        return value
    if any(c.isspace() for c in value) or any(c in value for c in "@/\\?#%[]"):
        raise ValueError(field + " must be a hostname or IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    name = value[:-1] if value.endswith(".") else value
    if (
        len(name) > 253
        or not name
        or all(c in "0123456789." for c in name)
        or any(not _DNS_LABEL.fullmatch(part) for part in name.split("."))
    ):
        raise ValueError(field + " must be a hostname or IP address")
    return value.lower()


def _authority(value, field, require_port=False):
    value = _text(value, field)
    if any(c.isspace() for c in value) or any(c in value for c in "@/\\?#%"):
        raise ValueError(field + " must be a host with an optional port")
    if value.startswith("["):
        if not re.fullmatch(r"\[[0-9a-fA-F:.]+\](?::[0-9]+)?", value):
            raise ValueError(field + " has an invalid host or port")
    elif not re.fullmatch(r"[^:\[\]]+(?::[0-9]+)?", value):
        raise ValueError(field + " has an invalid host or port")
    try:
        parsed = urlsplit("//" + value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError(field + " has an invalid host or port") from None
    if not host or parsed.path or parsed.query or parsed.fragment:
        raise ValueError(field + " has an invalid host or port")
    host = _host(host, field)
    bracketed = ":" in host
    if value.startswith("[") and not bracketed:
        raise ValueError(field + " requires an IPv6 address inside brackets")
    if bracketed and not value.startswith("["):
        raise ValueError(field + " requires brackets around IPv6")
    if value.endswith(":") or (require_port and port is None):
        raise ValueError(field + " requires a valid port")
    if port is not None:
        _port(port)
    return ("[" + host + "]" if bracketed else host) + (
        ":" + str(port) if port is not None else ""
    )


def _path(value, field):
    value = _text(value, field)
    if _BAD_PERCENT.search(value):
        raise ValueError(field + " has invalid percent encoding")
    try:
        decoded = unquote(value, errors="strict")
    except UnicodeError:
        raise ValueError(field + " has invalid percent encoding") from None
    _text(decoded, field)
    if (
        not decoded.startswith("/")
        or decoded.startswith("//")
        or any(c.isspace() for c in decoded)
        or "\\" in decoded
        or "#" in decoded
        or any(p in {".", ".."} for p in decoded.split("?", 1)[0].split("/"))
    ):
        raise ValueError(
            field + " must be an absolute path without traversal or fragments"
        )
    return value


def _key(value, field):
    value = _text(value, field)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValueError(field + " must be a 32-byte unpadded base64url key")
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ValueError(field + " must be a 32-byte unpadded base64url key") from None
    if (
        len(decoded) != 32
        or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value
    ):
        raise ValueError(field + " must be a 32-byte unpadded base64url key")
    return value


def _short_id(value):
    value = _text(value, "short_id", empty=True)
    if len(value) > 16 or len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", value):
        raise ValueError(
            "short_id must contain an even number of hex digits, at most 16"
        )
    return value.lower()


def _standard_base64(value, field):
    value = _text(value, field)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError(
            field + " must be standard Base64 with required padding"
        ) from None
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(field + " must be standard Base64 with required padding")
    return value


def _ech_config(value):
    value = _text(value, "ech_config_list", empty=True)
    if not value:
        return value
    if "://" not in value:
        return _standard_base64(value, "ech_config_list")
    discovery = value
    if "+https://" in value:
        lookup, _, resolver = value.partition("+https://")
        lookup = _host(lookup, "ECH lookup domain")
        try:
            ipaddress.ip_address(lookup)
        except ValueError:
            pass
        else:
            raise ValueError("ECH lookup domain must be a DNS name")
        discovery = "https://" + resolver
    if (
        not discovery.startswith("https://")
        or "+" in discovery
        or "\\" in discovery
        or "#" in discovery
        or any(c.isspace() for c in discovery)
        or _BAD_PERCENT.search(discovery)
    ):
        raise ValueError("ECH discovery requires a valid HTTPS URL")
    try:
        parsed = urlsplit(discovery)
        _authority(parsed.netloc, "ECH resolver")
        _path(parsed.path or "/", "ECH discovery path")
        _text(unquote(parsed.query, errors="strict"), "ECH discovery query", empty=True)
    except (ValueError, UnicodeError):
        raise ValueError("ECH discovery requires a valid HTTPS URL") from None
    return value


def _alpn(value):
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(p, str) or p not in {"h2", "http/1.1", "h3"} for p in value
        )
        or len(set(value)) != len(value)
    ):
        raise ValueError("alpn must be a nonempty list of distinct HTTP protocols")
    if "h3" in value and len(value) != 1:
        raise ValueError("h3 must be the sole alpn protocol")
    return list(value)


def _stream(transport, security, server=False):
    if type(server) is not bool:
        raise ValueError("server must be a boolean")
    t = _object(transport, {"type", "settings"}, {"type"}, "transport")
    s = _object(security, {"type", "settings"}, {"type", "settings"}, "security")
    network, sec = t["type"], s["type"]
    if not isinstance(network, str) or network not in {"tcp", "xhttp"}:
        raise ValueError("transport type must be tcp or xhttp")
    if not isinstance(sec, str) or sec not in {"reality", "tls"}:
        raise ValueError("security type must be reality or tls")
    if network == "tcp" and sec != "reality":
        raise ValueError("tcp requires reality security")
    settings = _object(
        t.get("settings", {}),
        {"path", "host", "mode"} if network == "xhttp" else set(),
        set(),
        "transport settings",
    )
    ts = {}
    if network == "xhttp":
        mode = settings.get("mode", "stream-one" if sec == "reality" else "auto")
        if not isinstance(mode, str) or mode not in _MODES:
            raise ValueError(
                "xhttp mode must be auto, packet-up, stream-up or stream-one"
            )
        if sec == "reality" and mode != "stream-one":
            raise ValueError("xhttp reality requires mode stream-one")
        host = _text(settings.get("host", ""), "xhttp host", empty=True)
        ts = {
            "path": _path(settings.get("path", "/"), "xhttp path"),
            "host": _authority(host, "xhttp host") if host else "",
            "mode": mode,
        }
    if sec == "reality":
        fields = (
            {"target", "server_name", "private_key", "short_ids"}
            if server
            else {"server_name", "public_key", "short_id", "fingerprint", "spider_x"}
        )
        required = fields if server else {"server_name", "public_key", "short_id"}
        ss = _object(s["settings"], fields, required, "reality settings")
        name = _host(ss["server_name"], "server_name")
        if server:
            ids = ss["short_ids"]
            if not isinstance(ids, list) or not ids:
                raise ValueError("short_ids must be a nonempty list")
            ids = [_short_id(i) for i in ids]
            if len(set(ids)) != len(ids):
                raise ValueError("short_ids must be distinct")
            result = {
                "server_name": name,
                "target": _authority(ss["target"], "target", True),
                "private_key": _key(ss["private_key"], "private_key"),
                "short_ids": ids,
            }
        else:
            fp = _text(ss.get("fingerprint", "chrome"), "fingerprint").lower()
            if fp not in _FINGERPRINTS:
                raise ValueError(
                    "fingerprint is unsupported by the pinned Xray capability set"
                )
            result = {
                "server_name": name,
                "public_key": _key(ss["public_key"], "public_key"),
                "short_id": _short_id(ss["short_id"]),
                "fingerprint": fp,
                "spider_x": _path(ss.get("spider_x", "/"), "spider_x"),
            }
    else:
        fields = (
            {"server_name", "alpn", "certificates", "ech_server_keys"}
            if server
            else {
                "server_name",
                "alpn",
                "allow_insecure",
                "ech_config_list",
                "ech_force_query",
            }
        )
        ss = _object(
            s["settings"],
            fields,
            {"certificates"} if server else {"server_name"},
            "tls settings",
        )
        result = {"alpn": _alpn(ss.get("alpn", ["h2", "http/1.1"]))}
        if "server_name" in ss or not server:
            result["server_name"] = _host(ss["server_name"], "server_name")
        if server:
            certs = ss["certificates"]
            if not isinstance(certs, list) or not certs:
                raise ValueError("certificates must be a nonempty list")
            result["certificates"] = []
            for cert in certs:
                cert = _object(
                    cert,
                    {"certificateFile", "keyFile"},
                    {"certificateFile", "keyFile"},
                    "certificate",
                )
                result["certificates"].append(
                    {
                        k: _text(cert[k], "certificate file path")
                        for k in ("certificateFile", "keyFile")
                    }
                )
            if "ech_server_keys" in ss:
                result["ech_server_keys"] = _standard_base64(
                    ss["ech_server_keys"], "ech_server_keys"
                )
        else:
            if ss.get("allow_insecure", False) is not False:
                raise ValueError("allow_insecure must be false")
            result["allow_insecure"] = False
            ech = _ech_config(ss.get("ech_config_list", ""))
            if ech:
                if ss.get("ech_force_query", "full") != "full":
                    raise ValueError(
                        "ech_force_query must be full when ECH is configured"
                    )
                result.update(ech_config_list=ech, ech_force_query="full")
            elif "ech_force_query" in ss:
                raise ValueError("ech_force_query requires a nonempty ech_config_list")
    return {"type": network, "settings": ts}, {"type": sec, "settings": result}


def _upstream(upstream):
    u = _object(
        upstream,
        {"protocol", "auth", "address", "port", "transport", "security", "enabled"},
        {"protocol", "auth", "address", "port", "transport", "security"},
        "upstream",
    )
    if u["protocol"] != "vless":
        raise ValueError("protocol must be vless")
    a = _object(u["auth"], {"id", "encryption", "flow"}, {"id"}, "auth")
    client_id = _text(a["id"], "client UUID")
    try:
        client_id = str(uuid.UUID(client_id))
    except ValueError:
        raise ValueError("invalid client UUID") from None
    if a.get("encryption", "none") != "none":
        raise ValueError("encryption must be none")
    flow = a.get("flow", "")
    if not isinstance(flow, str) or flow not in _FLOWS:
        raise ValueError("unsupported VLESS flow")
    transport, security = _stream(u["transport"], u["security"])
    if transport["type"] == "xhttp" and flow:
        raise ValueError("xhttp requires an empty VLESS flow")
    enabled = u.get("enabled", True)
    if type(enabled) is not bool:
        raise ValueError("enabled must be a boolean")
    return {
        "protocol": "vless",
        "auth": {"id": client_id, "encryption": "none", "flow": flow},
        "address": _host(u["address"]),
        "port": _port(u["port"]),
        "transport": transport,
        "security": security,
        "enabled": enabled,
    }


def validate_upstream(upstream: dict) -> None:
    """Validate an upstream (including disabled ones), returning None; no mutation."""
    _upstream(upstream)


def parse_link(link: str) -> dict:
    """Parse a VLESS URI into the canonical upstream shape, with explicit defaults.

    Only supported parameters are accepted; duplicates (including sid/shortid)
    are errors. A missing port defaults to 443, type to tcp, encryption to none,
    and flow to ''. Security must be explicit. The optional label is discarded.
    TLS ech maps to ech_config_list and enforces full; empty ech is omitted.
    """
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
    query = {}
    allowed = {
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
    for key, value in pairs:
        if key not in allowed:
            raise ValueError("link contains an unsupported parameter")
        key = "sid" if key == "shortid" else key
        if key in query:
            raise ValueError("link contains duplicate parameters")
        query[key] = value
    network, sec = query.get("type", "tcp"), query.get("security")
    if query.get("headerType", "none") != "none":
        raise ValueError("only headerType none is supported")
    if network != "tcp" and "headerType" in query:
        raise ValueError("headerType is only supported for tcp")
    if network == "tcp" and any(k in query for k in ("path", "host", "mode")):
        raise ValueError("tcp does not support xhttp parameters")
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


def render_stream(transport: dict, security: dict, server: bool = False) -> dict:
    """Render native streamSettings, validating the client or server variant."""
    t, s = _stream(transport, security, server)
    ss = s["settings"]
    result = {"network": t["type"], "security": s["type"]}
    if t["type"] == "xhttp":
        result["xhttpSettings"] = dict(t["settings"])
    if s["type"] == "reality":
        if server:
            native = {
                "target": ss["target"],
                "serverNames": [ss["server_name"]],
                "privateKey": ss["private_key"],
                "shortIds": list(ss["short_ids"]),
            }
        else:
            native = {
                "serverName": ss["server_name"],
                "publicKey": ss["public_key"],
                "shortId": ss["short_id"],
                "fingerprint": ss["fingerprint"],
                "spiderX": ss["spider_x"],
            }
        result["realitySettings"] = native
    else:
        native = {"alpn": list(ss["alpn"])}
        if "server_name" in ss:
            native["serverName"] = ss["server_name"]
        if server:
            native["certificates"] = [dict(cert) for cert in ss["certificates"]]
            if "ech_server_keys" in ss:
                native["echServerKeys"] = ss["ech_server_keys"]
        else:
            native["allowInsecure"] = False
            if "ech_config_list" in ss:
                native.update(echConfigList=ss["ech_config_list"], echForceQuery="full")
        result["tlsSettings"] = native
    return result


def render_outbound(upstream: dict, tag: str) -> dict:
    """Render one native VLESS outbound. Disabled upstreams cannot be rendered."""
    u = _upstream(upstream)
    tag = _text(tag, "tag")
    if not u["enabled"]:
        raise ValueError("upstream is disabled")
    user = dict(u["auth"])
    if not user["flow"]:
        del user["flow"]
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": u["address"], "port": u["port"], "users": [user]}]
        },
        "streamSettings": render_stream(u["transport"], u["security"]),
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
