"""
Tests for ml_kem_braid.tls and the TLS enforcement middleware.

Coverage:
  - generate_self_signed_cert: parseable x509, correct CN/SANs, self-signed,
    validity window, key PEM loads.
  - cert_fingerprint: stable, changes when cert changes.
  - Pin rejection: a client ssl.SSLContext pinned to cert A rejects cert B.
  - make_server_ssl_context / make_client_ssl_context: build without error for
    plain-TLS and mTLS configurations.
  - generate_dev_certs: creates all four files, returns correct paths and fp.
  - write_cert_pair: key file has mode 0o600.
  - Enforcement middleware (via TestClient):
      - enforce_tls=False → no 426 (existing tests unaffected).
      - enforce_tls=True, plain request → 426.
      - enforce_tls=True, X-Forwarded-Proto: https → 200 + HSTS header.
      - enforce_tls=True, /health without header → 200 (exempt path).
  - Live TLS round-trip (best-effort):
      Generate dev certs, spin up a real uvicorn TLS server on an ephemeral
      port, assert a pinned httpx client can reach /health (200) AND that a
      client pinned to a DIFFERENT cert raises an SSLError.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from fastapi.testclient import TestClient

from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore
from ml_kem_braid.tls import (
    cert_fingerprint,
    generate_dev_certs,
    generate_self_signed_cert,
    make_client_ssl_context,
    make_server_ssl_context,
    write_cert_pair,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def _load_key(pem: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


# ---------------------------------------------------------------------------
# generate_self_signed_cert
# ---------------------------------------------------------------------------


def test_cert_is_parseable_x509():
    cert_pem, _ = generate_self_signed_cert("test-cn")
    cert = _load_cert(cert_pem)
    assert cert is not None


def test_cert_has_correct_cn():
    cert_pem, _ = generate_self_signed_cert("my-server")
    cert = _load_cert(cert_pem)
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "my-server"


def test_cert_is_self_signed():
    """Issuer DN must equal Subject DN (self-signed)."""
    cert_pem, _ = generate_self_signed_cert("self-signed-test")
    cert = _load_cert(cert_pem)
    assert cert.subject == cert.issuer


def test_cert_has_dns_san():
    cert_pem, _ = generate_self_signed_cert("san-test", dns_names=["example.local", "alt.local"])
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_values = san.value.get_values_for_type(x509.DNSName)
    assert "example.local" in dns_values
    assert "alt.local" in dns_values


def test_cert_has_ip_san():
    cert_pem, _ = generate_self_signed_cert("ip-san-test", ip_addresses=["192.168.1.1", "127.0.0.1"])
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    ip_values = san.value.get_values_for_type(x509.IPAddress)
    assert ipaddress.ip_address("192.168.1.1") in ip_values
    assert ipaddress.ip_address("127.0.0.1") in ip_values


def test_cert_validity_window():
    cert_pem, _ = generate_self_signed_cert("validity-test", days_valid=90)
    cert = _load_cert(cert_pem)
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    delta = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert timedelta(days=89) < delta <= timedelta(days=91)
    assert cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def test_key_pem_loads():
    _, key_pem = generate_self_signed_cert("key-test")
    key = _load_key(key_pem)
    assert isinstance(key, EllipticCurvePrivateKey)


def test_ca_cert_basic_constraints():
    cert_pem, _ = generate_self_signed_cert("ca-test", is_ca=True)
    cert = _load_cert(cert_pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True


def test_end_entity_cert_basic_constraints():
    cert_pem, _ = generate_self_signed_cert("ee-test", is_ca=False)
    cert = _load_cert(cert_pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is False


def test_serial_numbers_are_unique():
    cert_a, _ = generate_self_signed_cert("serial-test")
    cert_b, _ = generate_self_signed_cert("serial-test")
    assert _load_cert(cert_a).serial_number != _load_cert(cert_b).serial_number


# ---------------------------------------------------------------------------
# cert_fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_is_64_hex_chars():
    cert_pem, _ = generate_self_signed_cert("fp-test")
    fp = cert_fingerprint(cert_pem)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_is_stable():
    cert_pem, _ = generate_self_signed_cert("fp-stable")
    assert cert_fingerprint(cert_pem) == cert_fingerprint(cert_pem)


def test_fingerprint_accepts_str():
    cert_pem, _ = generate_self_signed_cert("fp-str")
    assert cert_fingerprint(cert_pem.decode()) == cert_fingerprint(cert_pem)


def test_fingerprint_changes_for_different_cert():
    cert_a, _ = generate_self_signed_cert("fp-a")
    cert_b, _ = generate_self_signed_cert("fp-b")
    assert cert_fingerprint(cert_a) != cert_fingerprint(cert_b)


# ---------------------------------------------------------------------------
# Pin enforcement: a context pinned to cert A rejects cert B
# ---------------------------------------------------------------------------


def test_pinned_context_rejects_wrong_cert():
    """Core pin guarantee: trusting cert A must not verify cert B.

    We build a client SSLContext pinned to cert A, then try to verify cert B
    using that context's CA store.  The verification must fail — proving the
    pin actually rejects a mismatched certificate.

    Limitation: this tests the ssl layer directly (load_verify_locations +
    SSLContext.wrap_socket in server mode) rather than a live TCP handshake,
    because spinning up a real TLS server per test is fragile and slow.  The
    live round-trip test below covers the real handshake path.
    """
    import socket

    cert_a_pem, key_a_pem = generate_self_signed_cert("pin-a", dns_names=["localhost"], ip_addresses=["127.0.0.1"])
    cert_b_pem, key_b_pem = generate_self_signed_cert("pin-b", dns_names=["localhost"], ip_addresses=["127.0.0.1"])

    with tempfile.TemporaryDirectory() as tmp:
        cert_a_path = Path(tmp) / "a.crt"
        key_a_path = Path(tmp) / "a.key"
        cert_b_path = Path(tmp) / "b.crt"
        key_b_path = Path(tmp) / "b.key"
        write_cert_pair(cert_a_pem, key_a_pem, cert_a_path, key_a_path)
        write_cert_pair(cert_b_pem, key_b_pem, cert_b_path, key_b_path)

        # Server context for cert B.
        server_ctx = make_server_ssl_context(cert_b_path, key_b_path)

        # Client context pinned ONLY to cert A — must not trust cert B.
        client_ctx = make_client_ssl_context(pinned_server_cert=cert_a_pem)

        # Create a loopback socket pair and attempt a TLS handshake.
        # The server presents cert B; the client trusts only cert A → must fail.
        server_sock, client_sock = socket.socketpair()
        try:
            ssl_server = server_ctx.wrap_socket(server_sock, server_side=True, do_handshake_on_connect=False)
            ssl_client = client_ctx.wrap_socket(client_sock, server_side=False, server_hostname="localhost", do_handshake_on_connect=False)

            def _server_shake():
                try:
                    ssl_server.do_handshake()
                except Exception:
                    pass

            t = threading.Thread(target=_server_shake, daemon=True)
            t.start()
            with pytest.raises(ssl.SSLError):
                ssl_client.do_handshake()
            t.join(timeout=2)
        finally:
            try:
                server_sock.close()
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass


def test_pinned_context_accepts_matching_cert():
    """A context pinned to cert A must accept cert A."""
    import socket

    cert_pem, key_pem = generate_self_signed_cert("pin-match", dns_names=["localhost"], ip_addresses=["127.0.0.1"])

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp) / "match.crt"
        key_path = Path(tmp) / "match.key"
        write_cert_pair(cert_pem, key_pem, cert_path, key_path)

        server_ctx = make_server_ssl_context(cert_path, key_path)
        client_ctx = make_client_ssl_context(pinned_server_cert=cert_pem)

        server_sock, client_sock = socket.socketpair()
        error: list[Exception] = []

        def _server_shake():
            try:
                ssl_server = server_ctx.wrap_socket(server_sock, server_side=True, do_handshake_on_connect=False)
                ssl_server.do_handshake()
            except Exception as exc:
                error.append(exc)

        t = threading.Thread(target=_server_shake, daemon=True)
        t.start()
        ssl_client = client_ctx.wrap_socket(client_sock, server_side=False, server_hostname="localhost", do_handshake_on_connect=False)
        ssl_client.do_handshake()  # must NOT raise
        t.join(timeout=2)
        assert not error, f"Server handshake error: {error[0]}"
        ssl_client.close()


# ---------------------------------------------------------------------------
# make_server_ssl_context / make_client_ssl_context
# ---------------------------------------------------------------------------


def test_make_server_ssl_context_plain():
    with tempfile.TemporaryDirectory() as tmp:
        cert_pem, key_pem = generate_self_signed_cert("srv-plain")
        cert_path = Path(tmp) / "srv.crt"
        key_path = Path(tmp) / "srv.key"
        write_cert_pair(cert_pem, key_pem, cert_path, key_path)
        ctx = make_server_ssl_context(cert_path, key_path)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_NONE


def test_make_server_ssl_context_mtls():
    with tempfile.TemporaryDirectory() as tmp:
        srv_pem, srv_key = generate_self_signed_cert("srv-mtls")
        cli_pem, cli_key = generate_self_signed_cert("cli-mtls")
        srv_cert_path = Path(tmp) / "srv.crt"
        srv_key_path = Path(tmp) / "srv.key"
        cli_ca_path = Path(tmp) / "cli-ca.crt"
        write_cert_pair(srv_pem, srv_key, srv_cert_path, srv_key_path)
        cli_ca_path.write_bytes(cli_pem)
        ctx = make_server_ssl_context(
            srv_cert_path, srv_key_path,
            require_client_cert=True, client_ca_path=cli_ca_path,
        )
        assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_make_client_ssl_context_no_pin():
    ctx = make_client_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)


def test_make_client_ssl_context_with_pin():
    cert_pem, _ = generate_self_signed_cert("cli-pin")
    ctx = make_client_ssl_context(pinned_server_cert=cert_pem)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_make_client_ssl_context_mtls():
    with tempfile.TemporaryDirectory() as tmp:
        cert_pem, key_pem = generate_self_signed_cert("cli-mtls")
        cert_path = Path(tmp) / "cli.crt"
        key_path = Path(tmp) / "cli.key"
        write_cert_pair(cert_pem, key_pem, cert_path, key_path)
        ctx = make_client_ssl_context(
            pinned_server_cert=cert_pem,
            client_cert_path=str(cert_path),
            client_key_path=str(key_path),
        )
        assert isinstance(ctx, ssl.SSLContext)


# ---------------------------------------------------------------------------
# write_cert_pair — key file permissions
# ---------------------------------------------------------------------------


def test_key_file_mode_0o600():
    with tempfile.TemporaryDirectory() as tmp:
        cert_pem, key_pem = generate_self_signed_cert("perm-test")
        cert_path = Path(tmp) / "test.crt"
        key_path = Path(tmp) / "test.key"
        write_cert_pair(cert_pem, key_pem, cert_path, key_path)
        mode = oct(os.stat(key_path).st_mode & 0o777)
        assert mode == oct(0o600), f"Expected 0o600, got {mode}"


# ---------------------------------------------------------------------------
# generate_dev_certs
# ---------------------------------------------------------------------------


def test_generate_dev_certs_creates_files():
    with tempfile.TemporaryDirectory() as tmp:
        result = generate_dev_certs(Path(tmp))
        assert result["server_cert"].exists()
        assert result["server_key"].exists()
        assert result["client_cert"].exists()
        assert result["client_key"].exists()


def test_generate_dev_certs_fingerprint():
    with tempfile.TemporaryDirectory() as tmp:
        result = generate_dev_certs(Path(tmp))
        # Fingerprint in result matches the actual written cert.
        actual_fp = cert_fingerprint(result["server_cert"].read_bytes())
        assert result["server_fingerprint"] == actual_fp
        assert len(result["server_fingerprint"]) == 64


# ---------------------------------------------------------------------------
# TLS enforcement middleware (TestClient — no real TLS handshake needed)
# ---------------------------------------------------------------------------


@pytest.fixture()
def enforced_app():
    return create_app(SesameStore(), enforce_tls=True)


@pytest.fixture()
def plain_app():
    return create_app(SesameStore(), enforce_tls=False)


def test_enforcement_off_does_not_block_plain(plain_app):
    """Default enforce_tls=False: plain requests pass through normally."""
    with TestClient(plain_app) as c:
        r = c.get("/health")
    assert r.status_code == 200


def test_enforcement_blocks_plaintext(enforced_app):
    """enforce_tls=True without X-Forwarded-Proto → 426."""
    with TestClient(enforced_app, raise_server_exceptions=False) as c:
        r = c.get("/health?_force_plain=1", headers={})
        # /health is exempt; test a protected endpoint instead.
        r2 = c.get("/keys/nobody")
    assert r2.status_code == 426


def test_enforcement_426_on_register(enforced_app):
    """POST /register over plain HTTP returns 426."""
    with TestClient(enforced_app, raise_server_exceptions=False) as c:
        r = c.post("/register", json={})
    assert r.status_code == 426


def test_enforcement_passes_with_forwarded_proto(enforced_app):
    """X-Forwarded-Proto: https is treated as secure → request goes through."""
    with TestClient(enforced_app, raise_server_exceptions=False) as c:
        r = c.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert r.status_code == 200


def test_enforcement_hsts_header_present(enforced_app):
    """Responses carry Strict-Transport-Security when enforce_tls=True."""
    with TestClient(enforced_app, raise_server_exceptions=False) as c:
        r = c.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert "strict-transport-security" in r.headers
    assert "max-age=63072000" in r.headers["strict-transport-security"]


def test_health_exempt_from_enforcement(enforced_app):
    """/health is reachable over plain HTTP even when enforce_tls=True."""
    with TestClient(enforced_app, raise_server_exceptions=False) as c:
        r = c.get("/health")
    assert r.status_code == 200


def test_enforcement_off_no_hsts(plain_app):
    """With enforce_tls=False, HSTS header is NOT injected."""
    with TestClient(plain_app) as c:
        r = c.get("/health")
    assert "strict-transport-security" not in r.headers


# ---------------------------------------------------------------------------
# Live TLS round-trip
# ---------------------------------------------------------------------------


class _UvicornThread(threading.Thread):
    """Run a uvicorn server in a background thread for in-process TLS tests."""

    def __init__(self, app, host: str, port: int, ssl_certfile: str, ssl_keyfile: str):
        super().__init__(daemon=True)
        config = uvicorn.Config(
            app,
            host=host,
            port=port,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            log_level="warning",
        )
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        self.server.run()

    def stop(self) -> None:
        self.server.should_exit = True


def _wait_ready(host: str, port: int, timeout: float = 5.0) -> bool:
    """Poll until the server is accepting connections or *timeout* elapses."""
    import socket as _socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with _socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _free_port() -> int:
    import socket as _socket

    with _socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_live_tls_pinned_client_succeeds_wrong_pin_fails():
    """Real uvicorn TLS server: pinned client succeeds; wrong-pin client fails.

    A uvicorn instance is started with the server certificate.  Two httpx
    clients are created:
    - *good_client*: pinned to the actual server cert → GET /health returns 200.
    - *bad_client*: pinned to a completely different self-signed cert → the TLS
      handshake must raise ssl.SSLCertVerificationError (or SSLError).

    The server is stopped after the test via server.should_exit.
    """
    with tempfile.TemporaryDirectory() as tmp:
        certs = generate_dev_certs(Path(tmp))
        # Generate a second cert that we will (wrongly) pin the bad client to.
        other_cert_pem, _ = generate_self_signed_cert(
            "other", dns_names=["localhost"], ip_addresses=["127.0.0.1"]
        )

        port = _free_port()
        app = create_app(SesameStore())
        srv = _UvicornThread(
            app,
            host="127.0.0.1",
            port=port,
            ssl_certfile=str(certs["server_cert"]),
            ssl_keyfile=str(certs["server_key"]),
        )
        srv.start()

        if not _wait_ready("127.0.0.1", port, timeout=8.0):
            srv.stop()
            pytest.skip("TLS server did not start in time — skipping live TLS test")

        url = f"https://127.0.0.1:{port}"
        try:
            # Good client: pinned to the real server cert.
            good_ctx = make_client_ssl_context(
                pinned_server_cert=certs["server_cert"].read_bytes()
            )
            with httpx.Client(verify=good_ctx, base_url=url) as good_client:
                resp = good_client.get("/health")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

            # Bad client: pinned to a different cert — handshake must fail.
            bad_ctx = make_client_ssl_context(pinned_server_cert=other_cert_pem)
            with httpx.Client(verify=bad_ctx, base_url=url) as bad_client:
                with pytest.raises((ssl.SSLError, httpx.ConnectError)):
                    bad_client.get("/health")
        finally:
            srv.stop()
            srv.join(timeout=3)


def test_mtls_requires_client_ca():
    """require_client_cert=True without a client CA must fail loudly, not create
    a CERT_REQUIRED context with an empty (admit-anything) trust store."""
    import pytest

    from ml_kem_braid.tls import generate_self_signed_cert, make_server_ssl_context

    cert_pem, key_pem = generate_self_signed_cert("server")
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        with open(cp, "wb") as f:
            f.write(cert_pem)
        with open(kp, "wb") as f:
            f.write(key_pem)
        with pytest.raises(ValueError):
            make_server_ssl_context(cp, kp, require_client_cert=True)
