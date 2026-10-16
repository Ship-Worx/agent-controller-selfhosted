"""Controller-only HTTP client; deployment supplies an authenticated HTTPS endpoint."""
from __future__ import annotations

import json
import os
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


class ControllerUnavailable(RuntimeError):
    pass


class ActionDenied(RuntimeError):
    """A safe controller reason code, never an HTTP body or credential."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Bearer credentials must never follow server-controlled destinations.
        return None


def controller_tls_context():
    """Trust only deployment-supplied public CA certificates when configured.

    This setting comes from trusted runtime configuration, never invocation data.
    It adds no file lookup, credential, download, or TLS verification bypass.
    """
    pem = os.environ.get("CONTROLLER_CA_PEM")
    if pem is None:
        return ssl.create_default_context()
    if (len(pem.encode("utf-8")) > 16384
            or re.fullmatch(r"(?:-----BEGIN CERTIFICATE-----\r?\n"
                            r"[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*){1,4}",
                            pem.strip()) is None):
        raise ValueError("invalid_controller_ca")
    try:
        return ssl.create_default_context(cadata=pem)
    except (ssl.SSLError, ValueError):
        raise ValueError("invalid_controller_ca") from None


class ControllerClient:
    def __init__(self, url: str, token: str, *, timeout: float = 10):
        parsed = urlsplit(url)
        if (not (parsed.scheme == "https" and parsed.hostname
                     or parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"})
                or parsed.username or parsed.password or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment):
            raise ValueError("controller_requires_https_or_loopback_http")
        if not token or any(c in token for c in "\r\n"):
            raise ValueError("worker_identity_required")
        self.url, self._token, self.timeout = url.rstrip("/"), token, timeout
        # The controller is a direct private destination. Ambient provider/build
        # proxies must never receive its bearer token. HTTPS always verifies the
        # hostname and configured public CA chain; redirects remain disabled.
        self._opener = (build_opener(ProxyHandler({}), _NoRedirect()) if parsed.scheme == "http"
                        else build_opener(ProxyHandler({}), _NoRedirect(),
                                          HTTPSHandler(context=controller_tls_context())))

    def request(self, path: str, data: dict | None = None) -> dict:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("invalid_controller_path")
        request = Request(
            self.url + path,
            data=None if data is None else json.dumps(data, allow_nan=False).encode(),
            headers={"Authorization": "Bearer " + self._token,
                     "Content-Type": "application/json"},
            method="GET" if data is None else "POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                result = json.loads(response.read(1_048_576))
        except HTTPError as exc:
            try:
                # A server error can follow dispatch or settlement. Its body
                # cannot establish that the protected request had no effect.
                if exc.code >= 500:
                    raise ControllerUnavailable("controller_unavailable") from None
                try:
                    result = json.loads(exc.read(65_536))
                except (ValueError, OSError):
                    raise ControllerUnavailable("invalid_controller_response") from None
            finally:
                exc.close()
        except (URLError, TimeoutError, OSError, ValueError):
            raise ControllerUnavailable("controller_unavailable") from None
        if not isinstance(result, dict):
            raise ControllerUnavailable("invalid_controller_response")
        return result

    def act(self, attempt: dict) -> dict:
        result = self.request("/act", {"attempt": attempt})
        if result.get("status") != "allowed":
            reason = result.get("reason", "authorization_denied")
            if not isinstance(reason, str) or not reason.replace("_", "").isalnum():
                reason = "authorization_denied"
            raise ActionDenied(reason[:128])
        return result
