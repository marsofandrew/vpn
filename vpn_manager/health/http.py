import http.client
import ipaddress
from urllib.parse import urlsplit

from vpn_manager.health.fields import _WIRE_OVERHEAD, _ProbeError
from vpn_manager.health.wire import (
    _remaining,
    _send,
    _WireReader,
    connect_socks,
)


def _url(value):
    if (
        not isinstance(value, str)
        or len(value) > 8192
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("invalid URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "#" in value
    ):
        raise ValueError("invalid URL")
    host = parsed.hostname.encode("idna").decode("ascii")
    if "%" in host:
        raise ValueError("invalid host")
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    destination, authority = _destination(host)
    if port != 443:
        authority += ":" + str(port)
    target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    request = (
        "GET "
        + target
        + " HTTP/1.1\r\nHost: "
        + authority
        + "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    return host, destination + port.to_bytes(2, "big"), request


def _destination(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (c.isalnum() or c == "-") for c in label)
            for label in labels
        ):
            raise ValueError("invalid host")
        encoded = host.encode("ascii")
        destination = b"\x03" + bytes([len(encoded)]) + encoded
        authority = host
    else:
        destination = (b"\x01" if address.version == 4 else b"\x04") + address.packed
        authority = "[" + host + "]" if address.version == 6 else host
    return destination, authority


def _response(stack, proxy, destination, context, deadline, max_body):
    host, address, request = destination
    raw = connect_socks(stack, proxy, address, deadline)
    raw.settimeout(_remaining(deadline))
    tls = stack.enter_context(
        context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
    )
    tls.settimeout(_remaining(deadline))
    tls.do_handshake()
    _send(tls, request, deadline)
    wire = _WireReader(tls, deadline)
    response = stack.enter_context(http.client.HTTPResponse(wire))
    response.begin()
    wire.limit = max_body + _WIRE_OVERHEAD
    lengths = response.headers.get_all("Content-Length", [])
    transfer = response.headers.get_all("Transfer-Encoding", [])
    if (
        len(lengths) > 1
        or (lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()))
        or (
            transfer
            and (len(transfer) != 1 or transfer[0].lower() != "chunked" or lengths)
        )
    ):
        raise _ProbeError("invalid_http")
    if response.getheader("Content-Encoding", "identity").lower() != "identity":
        raise _ProbeError("unsupported_encoding")
    return response, wire
