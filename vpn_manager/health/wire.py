import io
import socket
import time

from vpn_manager.health.fields import _WIRE_OVERHEAD, _ProbeError


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _ProbeError("timeout")
    return remaining


def _recv_exact(sock, count, deadline):
    data = bytearray()
    while len(data) < count:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(count - len(data))
        _remaining(deadline)
        if not chunk:
            raise _ProbeError("socks_protocol")
        data.extend(chunk)
    return bytes(data)


def _send(sock, data, deadline):
    sock.settimeout(_remaining(deadline))
    sock.sendall(data)
    _remaining(deadline)


class _WireReader(io.RawIOBase):
    """Recheck a single deadline on *every* recv, including buffered HTTP reads."""

    def __init__(self, sock, deadline):
        super().__init__()
        self.sock = sock
        self.deadline = deadline
        self.limit = _WIRE_OVERHEAD
        self.received = 0
        self.first_byte_at = None

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(_remaining(self.deadline))
        data = self.sock.recv(min(len(buffer), self.limit - self.received + 1))
        _remaining(self.deadline)
        if data and self.first_byte_at is None:
            self.first_byte_at = time.monotonic()
        self.received += len(data)
        if self.received > self.limit:
            raise _ProbeError("response_too_large")
        buffer[: len(data)] = data
        return len(data)

    def makefile(self, mode):
        return io.BufferedReader(self, buffer_size=8192)


def connect_socks(stack, proxy, address, deadline):
    family, proxy_address = proxy
    raw = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
    raw.settimeout(_remaining(deadline))
    raw.connect(proxy_address)
    _send(raw, b"\x05\x01\x00", deadline)
    greeting = _recv_exact(raw, 2, deadline)
    if greeting[0] != 5:
        raise _ProbeError("socks_protocol")
    if greeting[1] != 0:
        raise _ProbeError("socks_authentication")
    _send(raw, b"\x05\x01\x00" + address, deadline)
    reply = _recv_exact(raw, 4, deadline)
    if reply[0] != 5 or reply[2] != 0:
        raise _ProbeError("socks_protocol")
    if reply[1] != 0:
        raise _ProbeError("socks_connect_failed")
    if reply[3] == 1:
        length = 4
    elif reply[3] == 4:
        length = 16
    elif reply[3] == 3:
        length = _recv_exact(raw, 1, deadline)[0]
        if not length:
            raise _ProbeError("socks_protocol")
    else:
        raise _ProbeError("socks_protocol")
    _recv_exact(raw, length + 2, deadline)
    return raw
