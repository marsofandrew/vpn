import base64
import binascii
import ipaddress
import re
from urllib.parse import unquote, urlsplit

PINNED_XRAY_VERSION = "26.10.31"


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


def _fingerprint(value):
    fingerprint = _text(value, "fingerprint").lower()
    if fingerprint not in _FINGERPRINTS:
        raise ValueError("fingerprint is unsupported by the pinned Xray capability set")
    return fingerprint


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
