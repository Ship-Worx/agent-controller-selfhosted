"""Correlate observations without changing authority, transport or uncertainty."""
import asyncio
import hashlib
import json

import pytest

from controller.service import Broker
from integration.client import ControllerClient, ControllerUnavailable
from integration.live_worker import run_live
from integration.worker import run_plan


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self, _limit):
        return json.dumps(self.value).encode()


def test_optional_transport_context_is_allowlisted_without_extra_requests():
    client = ControllerClient("http://127.0.0.1:1", "synthetic-worker-token")
    context = {"run_id_hash": "a" * 64, "config_pin": "b" * 64,
               "policy_pin": "c" * 64, "controller_instance_id": "d" * 32,
               "authority_epoch": 7, "token": "must-not-enter-trace"}
    calls = []

    def request(request, timeout):
        calls.append((request.full_url, timeout))
        return Response({"status": "denied", "reason": "outside_scope", "trace_context": context})

    client._opener.open = request
    result = client.request("/act", {"attempt": {}})
    assert result["status"] == "denied"
    assert len(calls) == 1 and calls[0][0].endswith("/act")
    assert client.trace_context == {key: value for key, value in context.items() if key != "token"}
    assert "must-not-enter-trace" not in json.dumps(client.trace_context)


@pytest.mark.parametrize("metadata", [None, [], "private-value", {
    "run_id_hash": "private-value", "config_pin": "https://private.invalid",
    "policy_pin": {}, "controller_instance_id": "x" * 1000, "authority_epoch": True,
}])
def test_invalid_optional_metadata_cannot_change_response_or_supply_binding(metadata):
    client = ControllerClient("http://127.0.0.1:1", "synthetic-worker-token")
    value = {"status": "allowed", "trace_context": metadata}
    client._opener.open = lambda *_args, **_kwargs: Response(value)
    assert client.request("/snapshot") == value
    assert client.trace_context == {}


def test_controller_trace_keeps_original_epoch_and_pin_after_restart(tmp_path):
    with Broker(tmp_path / "state", "synthetic-admin-" + "x" * 32) as broker:
        job = broker.create({"workflow": "recruiting"})
        original = broker.snapshot(broker.job(job["job_id"]), job["token"])
        created_event = broker.trace(broker.job(job["job_id"]))["events"][0]
        assert created_event["config_pin"] == original["config_pin"]
        assert created_event["policy_pin"] == original["policy_pin"]
        assert created_event["run_id_hash"] == hashlib.sha256(job["run_id"].encode()).hexdigest()
        assert created_event["source"] == "controller"
    with Broker(tmp_path / "state", "synthetic-admin-" + "x" * 32) as broker:
        current = broker.snapshot(broker.job(job["job_id"]), job["token"])
        events = broker.trace(broker.job(job["job_id"]))["events"]
        assert events[0] == created_event
        restarted = next(event for event in events if event["event"] == "service_restarted")
        assert current["authority_epoch"] > original["authority_epoch"]
        assert current["controller_instance_id"] != original["controller_instance_id"]
        assert restarted["authority_epoch"] == current["authority_epoch"]
        assert restarted["controller_instance_id"] == current["controller_instance_id"]
        assert restarted["config_pin"] == original["config_pin"] == current["config_pin"]


@pytest.mark.parametrize("controller_status,observed_status", [("held", "held"), (None, "unknown")])
def test_scripted_agent_trace_preserves_a_controller_hold_without_retry(monkeypatch, controller_status, observed_status):
    calls = []

    async def inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    def request(self, path, body=None):
        calls.append(path)
        assert path == "/act"
        return {"status": controller_status, "reason": "action_outcome_unknown"}

    monkeypatch.setattr(asyncio, "to_thread", inline)
    monkeypatch.setattr(ControllerClient, "request", request)
    result = asyncio.run(run_plan("https://controller.example.invalid:8443", "synthetic-token", [{
        "operation_id": "held-action", "step": "read", "action": "record.read",
        "resource": "candidate-a", "recipient": "worker", "payload": {},
    }]))
    # The existing scripted wrapper terminates on non-allowed responses. The
    # transport observation must still retain the controller's exact hold.
    assert result["status"] == "denied"
    assert calls == ["/act"] and result["results"] == []
    observed = next(event for event in result["agent_trace"]["events"]
                    if event["event"] == "action_result")
    assert observed["status"] == observed_status and observed["reason"] == "action_outcome_unknown"


@pytest.mark.parametrize("failure", ["unavailable", "unknown", "invalid_receipt"])
def test_sdk_model_trace_preserves_unknown_outcomes_and_no_retry(monkeypatch, failure):
    for name in ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY", "OPENAI_CUSTOM_HEADERS",
                 "OPENAI_AGENTS_TRACING_API_KEY", "CONTROLLER_OPENAI_API_KEY", "CONTROLLER_ADMIN_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    calls = []
    secret = "private-prompt-fixture-must-not-enter-telemetry"

    async def inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    def request(self, path, body=None):
        calls.append((path, body))
        if path == "/snapshot":
            return {"live_model": True, "purpose": secret, "context": {"private": secret},
                    "capabilities": [], "config_pin": "a" * 64, "policy_pin": "b" * 64,
                    "run_id": "fixture-run", "authority_epoch": 1}
        assert path == "/model"
        if failure == "unavailable":
            raise ControllerUnavailable("controller_unavailable")
        if failure == "unknown":
            return {"status": "held", "reason": "model_outcome_unknown"}
        return {"status": "allowed", "reason": "result_released", "receipt": {"private": secret}}

    monkeypatch.setattr(asyncio, "to_thread", inline)
    monkeypatch.setattr(ControllerClient, "request", request)
    result = asyncio.run(run_live("https://controller.example.invalid:8443", "synthetic-worker-token"))
    assert result["status"] == "held" and result["unknown_model_outcome"] is True
    assert result["usage"] is None
    assert [path for path, _body in calls] == ["/snapshot", "/model"]
    trace = result["agent_trace"]
    assert secret not in json.dumps(trace)
    assert trace["model_mode"] == "controller_broker"
    operation_hash = hashlib.sha256(calls[1][1]["operation_id"].encode()).hexdigest()
    model = [event for event in trace["events"] if event.get("operation_id_hash") == operation_hash]
    assert [event["event"] for event in model] == ["model_request", "model_result"]
    assert model[-1]["status"] == "held"
    assert trace["events"][-1]["event"] == "run_finished"
    assert trace["events"][-1]["status"] == "held"
    # SDK model callbacks occur even though remote tracing remains disabled.
    assert any(event["event"] == "model_started" for event in trace["events"])
