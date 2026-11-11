from vpn_manager.transports.fields import _text
from vpn_manager.transports.validation import _stream, _upstream


def render_stream(transport: dict, security: dict, server: bool = False) -> dict:
    """Render native streamSettings, validating the client or server variant."""
    t, s = _stream(transport, security, server)
    ss = s["settings"]
    result = {"network": t["type"], "security": s["type"]}
    if t["type"] == "xhttp":
        result["xhttpSettings"] = dict(t["settings"])
    key, renderer = _SECURITY_RENDERERS[s["type"]]
    result[key] = renderer(ss, server)
    return result


def _render_reality(ss, server):
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
    return native


def _render_tls(ss, server):
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
            native["echConfigList"] = ss["ech_config_list"]
    return native


_SECURITY_RENDERERS = {
    "reality": ("realitySettings", _render_reality),
    "tls": ("tlsSettings", _render_tls),
}


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
