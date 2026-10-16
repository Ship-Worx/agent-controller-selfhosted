"""Offline TLS configuration checks: no socket, DNS, certificate or key creation."""
import ssl
from urllib.request import HTTPSHandler, ProxyHandler

import pytest

from integration.client import ControllerClient, controller_tls_context


@pytest.fixture
def public_ca():
    certificates = ssl.create_default_context().get_ca_certs(binary_form=True)
    assert certificates, "Installed public CA bundle is required for this offline fixture"
    return ssl.DER_cert_to_PEM_cert(certificates[0])


def test_supplied_public_ca_retains_hostname_and_chain_verification(monkeypatch, public_ca):
    monkeypatch.setenv("CONTROLLER_CA_PEM", public_ca)
    context = controller_tls_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert len(context.get_ca_certs()) == 1


@pytest.mark.parametrize("value", [
    "", "https://untrusted.example/ca.pem", "private-marker",
    "-----BEGIN PRIVATE KEY-----\nprivate-marker\n-----END PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----",
    "x" * 16385,
])
def test_invalid_ca_fails_closed_without_echoing_input(monkeypatch, value):
    monkeypatch.setenv("CONTROLLER_CA_PEM", value)
    with pytest.raises(ValueError, match="^invalid_controller_ca$"):
        ControllerClient("https://controller.example.invalid:8443", "synthetic-token")


def test_private_key_appended_to_public_ca_is_rejected(monkeypatch, public_ca):
    monkeypatch.setenv("CONTROLLER_CA_PEM", public_ca + "\n-----BEGIN PRIVATE KEY-----\nsecret\n")
    with pytest.raises(ValueError, match="^invalid_controller_ca$"):
        controller_tls_context()


def test_default_trust_is_verified_when_no_private_ca_configured(monkeypatch):
    monkeypatch.delenv("CONTROLLER_CA_PEM", raising=False)
    context = controller_tls_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("endpoint", ["https://controller.example.invalid:8443", "http://127.0.0.1:8787"])
def test_controller_bypasses_ambient_proxy_configuration(monkeypatch, endpoint):
    monkeypatch.delenv("CONTROLLER_CA_PEM", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted-proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted-proxy.invalid:3128")
    client = ControllerClient(endpoint, "synthetic-token")
    assert not any(isinstance(handler, ProxyHandler) for handler in client._opener.handlers)
    if endpoint.startswith("https"):
        handler = next(h for h in client._opener.handlers if isinstance(h, HTTPSHandler))
        assert handler._context.check_hostname is True
        assert handler._context.verify_mode == ssl.CERT_REQUIRED
