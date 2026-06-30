"""
TLS helper module for ML-KEM Braid Chat.

Provides self-signed certificate generation, certificate pinning (libsignal-
style trust model: trust exactly ONE self-signed server cert, not the system
CA store), SSL context builders for both server and client sides, and a
convenience function that generates a full dev/testnet cert tree.

Why self-signed + pinning (vs. a public CA)?
Peer-to-peer and private-server deployments frequently cannot obtain a public
CA cert.  Signal/libsignal solves this by distributing the server's DER cert
out-of-band and having every client verify the pinned fingerprint on connect —
completely bypassing CA trust hierarchies.  We mirror that model here.

Private key files are always written mode 0o600.  Private key material is never
logged.

Requires only the standard library ``ssl`` module and the ``cryptography``
package, which is already a project dependency.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    generate_private_key,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------


def generate_self_signed_cert(
    common_name: str,
    *,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    days_valid: int = 365,
    is_ca: bool = False,
) -> tuple[bytes, bytes]:
    """Generate a self-signed certificate with an EC P-256 key.

    The certificate includes:
    - SubjectAltName (DNS names + IP addresses)
    - BasicConstraints (CA or end-entity)
    - KeyUsage (digitalSignature + keyAgreement; plus keyCertSign/cRLSign for CA)
    - ExtendedKeyUsage (serverAuth + clientAuth)
    - A cryptographically random serial number

    Args:
        common_name:   CN field of the Subject/Issuer distinguished name.
        dns_names:     DNS SANs.  Defaults to ``["localhost"]``.
        ip_addresses:  IP address SANs.  Defaults to ``["127.0.0.1"]``.
        days_valid:    Certificate lifetime in days (default 365).
        is_ca:         If True, set BasicConstraints CA:TRUE and add keyCertSign.

    Returns:
        ``(cert_pem, key_pem)`` as bytes — both PEM-encoded.

    Note:
        Private key material is kept in memory only; it is never logged.
    """
    if dns_names is None:
        dns_names = ["localhost"]
    if ip_addresses is None:
        ip_addresses = ["127.0.0.1"]

    key = generate_private_key(SECP256R1())

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )

    now = datetime.now(UTC)
    san_entries: list[x509.GeneralName] = [
        x509.DNSName(name) for name in dns_names
    ] + [
        x509.IPAddress(ipaddress.ip_address(addr)) for addr in ip_addresses
    ]

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
    )

    # Key usage — add keyCertSign/cRLSign only for CA certs.
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=is_ca,
            crl_sign=is_ca,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Extended key usage — suitable for both TLS server and client auth.
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
        ),
        critical=False,
    )

    cert = builder.sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def write_cert_pair(
    cert_pem: bytes,
    key_pem: bytes,
    cert_path: str | Path,
    key_path: str | Path,
) -> None:
    """Write a certificate and private key to disk.

    The key file is created with mode 0o600 (owner read/write only).
    The cert file is created with default permissions (0o644).

    Args:
        cert_pem:  PEM-encoded certificate bytes.
        key_pem:   PEM-encoded private key bytes.  Never logged.
        cert_path: Destination path for the certificate.
        key_path:  Destination path for the private key.
    """
    cert_path = Path(cert_path)
    key_path = Path(key_path)

    cert_path.write_bytes(cert_pem)
    # Write key securely: create with restrictive permissions.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(key_path, flags, 0o600)
    try:
        os.write(fd, key_pem)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


def cert_fingerprint(cert_pem: bytes | str) -> str:
    """Return the SHA-256 fingerprint of a PEM certificate as a hex string.

    The fingerprint is computed over the DER (binary) encoding of the
    certificate — the same format used by ``openssl x509 -fingerprint``.

    Args:
        cert_pem: PEM-encoded certificate (bytes or str).

    Returns:
        Lower-case hex string of the SHA-256 hash, e.g.
        ``"a1b2c3..."``.  No colons.
    """
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode()
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


# ---------------------------------------------------------------------------
# SSL context builders
# ---------------------------------------------------------------------------


def make_server_ssl_context(
    cert_path: str | Path,
    key_path: str | Path,
    *,
    require_client_cert: bool = False,
    client_ca_path: str | Path | None = None,
) -> ssl.SSLContext:
    """Build a server-side ``ssl.SSLContext`` for uvicorn.

    Args:
        cert_path:           Path to the server's PEM certificate.
        key_path:            Path to the server's PEM private key.
        require_client_cert: If True, demand a valid client certificate
                             (mTLS).  Must be paired with ``client_ca_path``.
        client_ca_path:      Path to a PEM file that is trusted as the CA
                             (or the pinned cert directly) for verifying
                             client certificates.  Required when
                             ``require_client_cert`` is True.

    Returns:
        A configured ``ssl.SSLContext`` ready to pass to
        ``uvicorn.run(..., ssl_context=ctx)``.
    """
    if require_client_cert and client_ca_path is None:
        # Without a trust anchor, CERT_REQUIRED would have an empty store and
        # could admit unintended clients — fail loudly instead.
        raise ValueError("client_ca_path is required when require_client_cert=True")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(client_ca_path))

    return ctx


def make_client_ssl_context(
    *,
    pinned_server_cert: bytes | str | None = None,
    client_cert_path: str | Path | None = None,
    client_key_path: str | Path | None = None,
) -> ssl.SSLContext:
    """Build a client-side ``ssl.SSLContext`` with optional cert pinning and mTLS.

    Libsignal-style trust model: when ``pinned_server_cert`` is supplied the
    context trusts ONLY that one certificate.  The system CA store is NOT
    consulted.  This is suitable for connecting to a server that uses a
    self-signed certificate distributed out-of-band.

    ``check_hostname`` is disabled when a pinned cert is provided because
    self-signed certs are typically issued for ``127.0.0.1`` / ``localhost``
    and the hostname match is already covered by the Subject / SAN in the
    pinned cert; the pin itself provides the required authenticity guarantee.

    Args:
        pinned_server_cert:  PEM bytes (or str) of the server certificate to
                             pin.  When supplied, only this cert is trusted.
        client_cert_path:    Path to the client's PEM certificate (mTLS).
        client_key_path:     Path to the client's PEM private key (mTLS).

    Returns:
        A configured ``ssl.SSLContext``.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if pinned_server_cert is not None:
        # Replace the default CA store with only the pinned certificate.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Write the pinned cert to a temp location that load_verify_locations can read.
        # Using a bytes buffer avoids touching the filesystem for in-memory certs.
        if isinstance(pinned_server_cert, str):
            pinned_server_cert = pinned_server_cert.encode()
        # SSLContext.load_verify_locations accepts cadata (PEM string) directly.
        ctx.load_verify_locations(cadata=pinned_server_cert.decode())
    # else: default behaviour — verify against the system CA store.

    if client_cert_path is not None and client_key_path is not None:
        ctx.load_cert_chain(
            certfile=str(client_cert_path), keyfile=str(client_key_path)
        )

    return ctx


# ---------------------------------------------------------------------------
# Dev cert tree
# ---------------------------------------------------------------------------


def generate_dev_certs(directory: Path) -> dict:
    """Generate a server + client self-signed cert pair in *directory*.

    Creates four files:
        - ``server.crt`` / ``server.key`` — server certificate and private key
        - ``client.crt`` / ``client.key`` — client certificate and private key

    Designed for the testnet / local development environment.  Both certs are
    self-signed end-entity certs (not CA certs).  The server cert carries
    ``localhost`` / ``127.0.0.1`` SANs.

    Args:
        directory: Directory in which to write the generated files.
                   Created if it does not exist.

    Returns:
        Dict with keys:
            ``server_cert``, ``server_key``, ``client_cert``, ``client_key``
            (all ``Path`` objects) and ``server_fingerprint`` (hex str).
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    server_cert_pem, server_key_pem = generate_self_signed_cert(
        "braid-server",
        dns_names=["localhost"],
        ip_addresses=["127.0.0.1"],
    )
    client_cert_pem, client_key_pem = generate_self_signed_cert(
        "braid-client",
        dns_names=["localhost"],
        ip_addresses=["127.0.0.1"],
    )

    server_cert_path = directory / "server.crt"
    server_key_path = directory / "server.key"
    client_cert_path = directory / "client.crt"
    client_key_path = directory / "client.key"

    write_cert_pair(server_cert_pem, server_key_pem, server_cert_path, server_key_path)
    write_cert_pair(client_cert_pem, client_key_pem, client_cert_path, client_key_path)

    return {
        "server_cert": server_cert_path,
        "server_key": server_key_path,
        "client_cert": client_cert_path,
        "client_key": client_key_path,
        "server_fingerprint": cert_fingerprint(server_cert_pem),
    }
