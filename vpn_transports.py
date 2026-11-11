"""Strict, stdlib-only VLESS transports pinned to Xray 26.10.31.

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
retains the full ECH query policy; weaker values are rejected. An empty client
ech_config_list or URI ech= is treated as omitted. ech_force_query without a
nonempty config is rejected. URI ech is percent-encoded ech_config_list; the
full policy is implied and has no separate URI parameter. Optional server
ech_server_keys accepts nonempty standard Base64. echSockopt is unsupported.
The native pin applies ECH failure behavior directly; the legacy echForceQuery
JSON field is not emitted.
Existing non-ECH variants remain compatible with 25.3.6; ECH requires the
26.10.31 capability pin and cannot be rendered for REALITY.

Pinned validation sources (tag v26.10.31, commit a4a3dff):
https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/transport_security.go
https://github.com/XTLS/Xray-core/blob/v26.10.31/transport/internet/tls/ech.go
https://github.com/XTLS/Xray-core/blob/v26.10.31/main/commands/all/tls/ech.go
https://github.com/XTLS/Xray-core/discussions/716

PR2 deliberately restricts XHTTP+REALITY to explicit stream-one, even though
native config parsing accepts other modes and native auto selects stream-one.
Paths/hosts and the supported field set are stricter than native config parsing."""

from vpn_manager.transports.fields import PINNED_XRAY_VERSION as PINNED_XRAY_VERSION
from vpn_manager.transports.links import export_link as export_link
from vpn_manager.transports.links import parse_link as parse_link
from vpn_manager.transports.rendering import render_outbound as render_outbound
from vpn_manager.transports.rendering import render_stream as render_stream
from vpn_manager.transports.validation import validate_upstream as validate_upstream

__all__ = [
    "PINNED_XRAY_VERSION",
    "parse_link",
    "validate_upstream",
    "render_outbound",
    "export_link",
    "render_stream",
]
