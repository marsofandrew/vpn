import uuid

from vpn_manager.transports.fields import (
    _FLOWS,
    _MODES,
    _alpn,
    _authority,
    _ech_config,
    _fingerprint,
    _host,
    _key,
    _object,
    _path,
    _port,
    _short_id,
    _standard_base64,
    _text,
)


def _stream(transport, security, server=False):
    if type(server) is not bool:
        raise ValueError("server must be a boolean")
    t = _object(transport, {"type", "settings"}, {"type"}, "transport")
    s = _object(security, {"type", "settings"}, {"type", "settings"}, "security")
    network, sec = t["type"], s["type"]
    if not isinstance(network, str) or network not in _TRANSPORT_VALIDATORS:
        raise ValueError("transport type must be tcp or xhttp")
    if not isinstance(sec, str) or sec not in _SECURITY_VALIDATORS:
        raise ValueError("security type must be reality or tls")
    if network == "tcp" and sec != "reality":
        raise ValueError("tcp requires reality security")
    ts = _TRANSPORT_VALIDATORS[network](t.get("settings", {}), sec)
    ss = _SECURITY_VALIDATORS[sec](s, server)
    return {"type": network, "settings": ts}, {"type": sec, "settings": ss}


def _tcp(settings, security):
    _object(settings, set(), set(), "transport settings")
    return {}


def _xhttp(settings, security):
    settings = _object(settings, {"path", "host", "mode"}, set(), "transport settings")
    mode = settings.get("mode", "stream-one" if security == "reality" else "auto")
    if not isinstance(mode, str) or mode not in _MODES:
        raise ValueError("xhttp mode must be auto, packet-up, stream-up or stream-one")
    if security == "reality" and mode != "stream-one":
        raise ValueError("xhttp reality requires mode stream-one")
    host = _text(settings.get("host", ""), "xhttp host", empty=True)
    return {
        "path": _path(settings.get("path", "/"), "xhttp path"),
        "host": _authority(host, "xhttp host") if host else "",
        "mode": mode,
    }


def _reality(s, server):
    fields = (
        {"target", "server_name", "private_key", "short_ids"}
        if server
        else {"server_name", "public_key", "short_id", "fingerprint", "spider_x"}
    )
    required = fields if server else {"server_name", "public_key", "short_id"}
    ss = _object(s["settings"], fields, required, "reality settings")
    name = _host(ss["server_name"], "server_name")
    return _reality_server(ss, name) if server else _reality_client(ss, name)


def _reality_server(ss, name):
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
    return result


def _reality_client(ss, name):
    fp = _fingerprint(ss.get("fingerprint", "chrome"))
    result = {
        "server_name": name,
        "public_key": _key(ss["public_key"], "public_key"),
        "short_id": _short_id(ss["short_id"]),
        "fingerprint": fp,
        "spider_x": _path(ss.get("spider_x", "/"), "spider_x"),
    }

    return result


def _tls(s, server):
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
    _tls_server(ss, result) if server else _tls_client(ss, result)
    return result


def _tls_server(ss, result):
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


def _tls_client(ss, result):
    if ss.get("allow_insecure", False) is not False:
        raise ValueError("allow_insecure must be false")
    result["allow_insecure"] = False
    ech = _ech_config(ss.get("ech_config_list", ""))
    if ech:
        if ss.get("ech_force_query", "full") != "full":
            raise ValueError("ech_force_query must be full when ECH is configured")
        result.update(ech_config_list=ech, ech_force_query="full")
    elif "ech_force_query" in ss:
        raise ValueError("ech_force_query requires a nonempty ech_config_list")


_TRANSPORT_VALIDATORS = {"tcp": _tcp, "xhttp": _xhttp}
_SECURITY_VALIDATORS = {"reality": _reality, "tls": _tls}


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
