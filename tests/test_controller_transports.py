"""Qualify controller transport loading without contacting a managed host."""

from __future__ import annotations

import socket
import ssl
import sys
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address

import pytest


def test_locked_controller_can_prepare_verified_https_ntlm_without_network(monkeypatch):
    import requests
    from requests_ntlm import HttpNtlmAuth
    from winrm.protocol import Protocol

    def network_forbidden(*args, **kwargs):
        raise AssertionError("Offline controller qualification attempted a network request")

    monkeypatch.setattr(socket.socket, "connect", network_forbidden)
    monkeypatch.setattr(requests.sessions.Session, "send", network_forbidden)
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    protocol = Protocol(
        endpoint="https://winrm-fixture.example.invalid:5986/wsman",
        transport="ntlm",
        username="synthetic-fixture-user",
        password="synthetic-fixture-value",
        server_cert_validation="validate",
        ca_trust_path=None,
        proxy=None,
    )
    session = protocol.transport.build_session()
    try:
        assert isinstance(session.auth, HttpNtlmAuth)
        assert session.verify is True
        assert protocol.transport.server_cert_validation == "validate"
        assert protocol.transport.send_cbt is True
    finally:
        session.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Ansible controllers are qualified on Linux")
def test_locked_linux_ansible_controller_can_load_winrm_connection():
    from ansible.plugins.connection import winrm

    assert winrm.HAS_WINRM, "The locked development/controller profile must provide pywinrm"


@pytest.mark.parametrize("trust_ca,correct_hostname", [(True, True), (False, True), (True, False)])
def test_winrm_https_validates_trust_and_hostname_before_sending_requests(
    tmp_path, monkeypatch, trust_ca, correct_hostname
):
    """Use a synthetic local HTTPS receiver; no Windows authentication or commands."""
    import requests
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from winrm.exceptions import WinRMTransportError
    from winrm.protocol import Protocol

    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic controller test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic HTTPS receiver")])
        )
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ip_address("127.0.0.1" if correct_hostname else "127.0.0.2"))]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_file, cert_file, key_file = (
        tmp_path / name for name in ["ca.pem", "server.pem", "server.key"]
    )
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_file.chmod(0o600)
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            body = b"synthetic-https-response"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    protocol = Protocol(
        endpoint=f"https://127.0.0.1:{server.server_port}/wsman",
        transport="ntlm",
        username="synthetic-fixture-user",
        password="synthetic-fixture-value",
        server_cert_validation="validate",
        ca_trust_path=str(ca_file) if trust_ca else None,
        proxy=None,
        operation_timeout_sec=1,
        read_timeout_sec=5,
    )
    try:
        if trust_ca and correct_hostname:
            assert (
                protocol.transport.send_message("synthetic-request") == b"synthetic-https-response"
            )
            assert received == [b"synthetic-request"]
        else:
            with pytest.raises((requests.exceptions.SSLError, WinRMTransportError)) as error:
                protocol.transport.send_message("synthetic-request")
            reason = str(error.value).lower().replace("_", " ")
            assert "certificate verify failed" in reason
            if trust_ca:
                assert "ip address mismatch" in reason or "hostname mismatch" in reason
            assert received == []
    finally:
        if protocol.transport.session:
            protocol.transport.session.close()
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
        assert not worker.is_alive()
