"""Use the actual SDK loop with an in-memory controller, never a provider call."""
import asyncio
from io import BytesIO
import json
from urllib.error import HTTPError

import pytest

from integration.client import ControllerClient, ControllerUnavailable
from integration.live_worker import run_live


@pytest.fixture(autouse=True)
def no_worker_credentials(monkeypatch):
    for name in ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY", "OPENAI_CUSTOM_HEADERS",
                 "OPENAI_AGENTS_TRACING_API_KEY", "BRAINTRUST_API_KEY",
                 "CONTROLLER_OPENAI_API_KEY", "CONTROLLER_ADMIN_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    # These requests are in-memory fixtures, not I/O. Run them inline so this
    # status/accounting regression needs neither socket wakeups nor threads.
    # Real threaded transport remains covered by the separate HTTP suite.
    async def inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline)


SNAPSHOT = {"live_model": True, "purpose": "synthetic uncertainty check",
            "context": {}, "capabilities": []}


def test_worker_refuses_braintrust_credential_before_any_controller_request(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "synthetic-braintrust-credential")

    def forbidden(*args, **kwargs):
        pytest.fail("a credential-bearing worker must stop before transport")

    monkeypatch.setattr(ControllerClient, "request", forbidden)
    result = asyncio.run(run_live("https://controller.example.invalid:8443", "synthetic-run-token"))
    assert result == {"status": "blocked", "reason": "worker_privileged_credential_present",
                      "usage": None}
    assert "synthetic-braintrust-credential" not in json.dumps(result)


@pytest.mark.parametrize("outcome", [
    ControllerUnavailable("controller_unavailable"),
    {"status": "held", "reason": "model_outcome_unknown"},
    {"status": "held", "reason": "operation_unknown"},
    {"status": "held", "reason": "already_claimed"},
    {"status": "held", "reason": "result_unsettled"},
    {"status": "held", "reason": {"untrusted": "do-not-echo"}},
])
def test_model_uncertainty_is_held_without_retry_or_completion(monkeypatch, outcome):
    calls = []

    def request(self, path, data=None):
        calls.append(path)
        if path == "/snapshot":
            return SNAPSHOT
        assert path == "/model"
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(ControllerClient, "request", request)
    result = asyncio.run(run_live("https://controller.example.invalid:8443", "synthetic-worker-token"))
    assert result["status"] == "held"
    assert result["unknown_model_outcome"] is True
    assert result["usage"] is None
    assert calls == ["/snapshot", "/model"]
    assert "do-not-echo" not in json.dumps(result)


@pytest.mark.parametrize("response", [
    {"status": "denied", "reason": "root_stopped"},
    {"status": "held", "reason": "project_budget_denied"},
    {"status": "held", "reason": "project_budget_unavailable"},
])
def test_explicit_pre_dispatch_denial_does_not_invent_unknown_usage(monkeypatch, response):
    calls = []

    def request(self, path, data=None):
        calls.append(path)
        return SNAPSHOT if path == "/snapshot" else response

    monkeypatch.setattr(ControllerClient, "request", request)
    result = asyncio.run(run_live("https://controller.example.invalid:8443", "synthetic-worker-token"))
    assert result["status"] == "denied"
    assert result["reason"] == response["reason"]
    assert result["unknown_model_outcome"] is False
    assert result["usage"] is None
    assert calls == ["/snapshot", "/model"]


@pytest.mark.parametrize("code", [500, 502, 503, 504])
def test_server_errors_cannot_masquerade_as_known_denial(code):
    client = ControllerClient("http://127.0.0.1:1", "synthetic-worker-token")
    body = BytesIO(b'{"status":"denied","reason":"do-not-echo-server-body"}')
    error = HTTPError(client.url + "/model", code, "synthetic", {}, body)
    calls = []

    def fail(request, timeout):
        calls.append(request)
        raise error

    client._opener.open = fail
    with pytest.raises(ControllerUnavailable, match="^controller_unavailable$"):
        client.request("/model", {"prompt": "synthetic"})
    assert len(calls) == 1
    assert body.closed


def test_structured_403_denial_is_preserved_and_body_closed():
    client = ControllerClient("http://127.0.0.1:1", "synthetic-worker-token")
    body = BytesIO(b'{"status":"denied","reason":"unauthorized"}')

    def deny(request, timeout):
        raise HTTPError(request.full_url, 403, "synthetic", {}, body)

    client._opener.open = deny
    assert client.request("/snapshot") == {"status": "denied", "reason": "unauthorized"}
    assert body.closed
