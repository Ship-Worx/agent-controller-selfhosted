"""Local SDK observations disclose no contents and never grant authority."""
import asyncio
import hashlib
import json
import re

import pytest

from integration.telemetry import AgentTrace, MAX_EVENTS, MAX_REPORT_BYTES


def serialized(result):
    return json.dumps(result["agent_trace"], separators=(",", ":"), allow_nan=False)


def test_hooks_ignore_sensitive_sdk_arguments_and_export_nothing(monkeypatch):
    # Inputs have dangerous conversion methods: hooks must not inspect contents.
    class Sensitive:
        def __str__(self):
            raise AssertionError("hook attempted content conversion")

        def __repr__(self):
            raise AssertionError("hook attempted content conversion")

    secret = "secret_fixture_must_never_be_a_reason_or_identifier"
    monkeypatch.setenv("OPENAI_AGENTS_TRACING_API_KEY", secret)
    trace = AgentTrace()
    sensitive = Sensitive()

    async def hooks():
        await trace.on_agent_start(sensitive, sensitive)
        await trace.on_llm_start(sensitive, sensitive, secret, [sensitive])
        await trace.on_llm_end(sensitive, sensitive, sensitive)
        await trace.on_tool_start(sensitive, sensitive, sensitive)
        await trace.on_tool_end(sensitive, sensitive, sensitive, secret)
        await trace.on_agent_end(sensitive, sensitive, secret)

    asyncio.run(hooks())
    trace.emit("action_proposed", operation_id=secret, status=secret, reason=secret)
    trace.emit(secret, operation_id=secret)
    report = trace.finish({"status": "denied", "reason": secret})["agent_trace"]
    encoded = json.dumps(report)
    assert secret not in encoded
    assert [e["event"] for e in report["events"]] == [
        "agent_started", "model_started", "model_finished", "tool_started",
        "tool_finished", "agent_finished", "action_proposed", "run_finished"]
    proposal = report["events"][-2]
    assert proposal["operation_id_hash"] == hashlib.sha256(secret.encode()).hexdigest()
    assert proposal["status"] == "unknown"
    assert proposal["reason"] == "unrecognized_reason"
    assert report["events"][-1]["reason"] == "unrecognized_reason"
    assert report["source"] == "agent_sdk"
    assert report["trust"] == "agent_reported_diagnostic"
    assert report["model_mode"] == "scripted"
    assert re.fullmatch("[0-9a-f]{32}", report["invocation_id"])
    assert AgentTrace().invocation_id != report["invocation_id"]


def test_bind_selects_correlation_metadata_only():
    trace = AgentTrace(model_mode="controller_broker")
    secret = "do-not-copy-context-or-token"
    snapshot = {"run_id": secret, "token": secret, "context": {"secret": secret},
                "config_pin": "a" * 64, "policy_pin": "b" * 64,
                "authority_epoch": 7, "purpose": secret}
    trace.bind(snapshot)
    report = trace.finish({"status": "completed"})["agent_trace"]
    assert secret not in json.dumps(report)
    assert report["run_id_hash"] == hashlib.sha256(secret.encode()).hexdigest()
    assert report["config_pin"] == "a" * 64
    assert report["policy_pin"] == "b" * 64
    assert report["authority_epoch"] == 7
    assert report["model_mode"] == "controller_broker"


def test_bind_accepts_validated_transport_context_without_raw_identifiers():
    trace = AgentTrace()
    context = {"run_id_hash": "c" * 64, "config_pin": "a" * 64,
               "policy_pin": "b" * 64, "controller_instance_id": "d" * 32,
               "authority_epoch": 3, "token": "private-token"}
    trace.bind(context)
    report = trace.finish({"status": "completed"})["agent_trace"]
    for field in ("run_id_hash", "config_pin", "policy_pin", "controller_instance_id", "authority_epoch"):
        assert report[field] == context[field]
    assert "private-token" not in json.dumps(report)


@pytest.mark.parametrize("snapshot", [None, {}, {"run_id": 3}, {
    "run_id": "x" * 257, "config_pin": "https://secret.invalid",
    "policy_pin": "X" * 64, "authority_epoch": True,
}])
def test_missing_or_invalid_optional_metadata_is_compatible(snapshot):
    trace = AgentTrace()
    trace.bind(snapshot)
    report = trace.finish({"status": "denied"})["agent_trace"]
    assert not {"run_id_hash", "config_pin", "policy_pin", "authority_epoch"} & set(report)
    assert report["events"][-1]["event"] == "run_finished"


def test_bounded_report_retains_terminal_event_and_discloses_truncation():
    trace = AgentTrace()
    trace.bind({"run_id": "r" * 128, "config_pin": "a" * 64,
                "policy_pin": "b" * 64, "authority_epoch": 2**53 - 1,
                "controller_instance_id": "d" * 32})
    for _ in range(10_000):
        trace.emit("model_request", operation_id="x" * 128,
                   status="reserved", reason="worker_privileged_credential_present")
    result = trace.finish({"status": "held", "reason": "model_outcome_unknown",
                           "usage": None, "unknown_model_outcome": True})
    report = result["agent_trace"]
    assert len(report["events"]) <= MAX_EVENTS
    assert len(serialized(result).encode()) <= MAX_REPORT_BYTES
    assert len(json.dumps(report).encode()) <= MAX_REPORT_BYTES
    assert report["truncated"] is True and report["dropped_events"] > 0
    assert report["events"][-1]["event"] == "run_finished"
    assert report["events"][-1]["status"] == "held"
    assert report["events"][-1]["reason"] == "model_outcome_unknown"
    assert result["usage"] is None and result["unknown_model_outcome"] is True


def test_monotonic_order_even_if_clock_moves_backwards(monkeypatch):
    readings = iter([100, 100.005, 99, 100.010])
    monkeypatch.setattr("integration.telemetry.time.monotonic", lambda: next(readings))
    trace = AgentTrace()
    trace.emit("model_started")
    trace.emit("model_finished")
    report = trace.finish({"status": "completed"})["agent_trace"]
    assert [e["seq"] for e in report["events"]] == [1, 2, 3]
    times = [e["elapsed_ms"] for e in report["events"]]
    assert times == sorted(times)
    assert all(type(value) is int and value >= 0 for value in times)


def test_finish_is_idempotent_and_preserves_all_existing_result_fields():
    trace = AgentTrace()
    result = {"status": "held", "reason": "controller_unavailable", "results": [],
              "usage": None, "unknown_action_outcome": True}
    first = trace.finish(result)
    trace.emit("action_result", status="allowed")
    second = trace.finish(result)
    assert first == second
    assert {key: second[key] for key in result} == result
    assert sum(e["event"] == "run_finished" for e in second["agent_trace"]["events"]) == 1


def test_optional_recorder_failure_does_not_change_worker_result(monkeypatch):
    trace = AgentTrace()
    def fail():
        raise RuntimeError("do-not-log-this-exception")
    monkeypatch.setattr("integration.telemetry.time.monotonic", fail)
    trace.emit("action_proposed", operation_id="operation")
    result = {"status": "held", "reason": "action_outcome_unknown", "usage": None}
    output = trace.finish(result)
    assert {key: output[key] for key in result} == result
    assert output["agent_trace"]["unavailable"] is True
    assert "do-not-log-this-exception" not in serialized(output)


def test_report_serialization_failure_uses_safe_unavailable_fallback(monkeypatch):
    trace = AgentTrace()
    def fail(_report):
        raise RuntimeError("private-exception-details")
    monkeypatch.setattr(trace, "_bytes", fail)
    output = trace.finish({"status": "blocked", "reason": "worker_identity_required"})
    assert output["status"] == "blocked"
    assert output["agent_trace"]["unavailable"] is True
    assert output["agent_trace"]["truncated"] is True
    assert "private-exception-details" not in serialized(output)


def test_invalid_structured_reasons_and_statuses_are_never_serialized():
    trace = AgentTrace()
    trace.emit("action_result", status={"secret": "credential"},
               reason=["credential"], operation_id={"secret": "credential"})
    report = trace.finish({"status": "denied"})["agent_trace"]
    event = report["events"][0]
    assert event["status"] == "unknown" and event["reason"] == "unrecognized_reason"
    assert "operation_id_hash" not in event
    assert "credential" not in json.dumps(report)
