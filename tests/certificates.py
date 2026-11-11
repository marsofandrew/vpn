"""Ephemeral trusted certificate material for isolated local fixtures."""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def write_certificate(
    root, hostname, sans, *, ca=False, minutes=5, certificate="cert.pem"
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _certificate(key, hostname, sans, ca, minutes)
    _private_write(root / certificate, cert.public_bytes(serialization.Encoding.PEM))
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _private_write(root / "key.pem", key_pem)
    return key_pem


def _certificate(key, hostname, sans, ca, minutes):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=minutes))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in sans]),
            critical=False,
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
    return builder.sign(key, hashes.SHA256())


def _private_write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
