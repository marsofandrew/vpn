import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from vpn_manager import errors as app_errors


def encode_x25519_key(key_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode("ascii")


def decode_x25519_key(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        key_bytes = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as error:
        raise app_errors.VpnctlError("invalid X25519 key encoding") from error
    if len(key_bytes) != 32:
        raise app_errors.VpnctlError("X25519 keys must decode to 32 bytes")
    return key_bytes


def public_key_from_private(private_key: str) -> str:
    key = x25519.X25519PrivateKey.from_private_bytes(decode_x25519_key(private_key))
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return encode_x25519_key(public_bytes)


def generate_reality_keys() -> dict[str, str]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "private_key": encode_x25519_key(private_bytes),
        "public_key": encode_x25519_key(public_bytes),
    }
