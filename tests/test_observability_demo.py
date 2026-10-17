"""The renderer explains observed streams without inventing authority or order."""
from copy import deepcopy

import pytest

from demo.contract import _safe_agent_trace, _safe_controller_events
from demo.observe import render_report


ALLOWED = "a" * 64
DENIED = "b" * 64


def trace_report():
    bindings = {"config_pin": "c" * 64, "policy_pin": "d" * 64,
                "authority_epoch": 2, "controller_instance_id": "e" * 32,
                "run_id_hash": "0" * 64}
    agent = {
        "schema_version": 1, "source": "agent_sdk", "trust": "agent_reported_diagnostic",
        "invocation_id": "f" * 32, "model_mode": "scripted", **bindings,
        "run_id_hash": "0" * 64, "truncated": False, "dropped_events": 0,
        "unavailable": False,
        "events": [
            {"seq": 1, "elapsed_ms": 0, "event": "agent_started"},
            {"seq": 2, "elapsed_ms": 10, "event": "action_proposed", "operation_id_hash": ALLOWED},
            {"seq": 3, "elapsed_ms": 20, "event": "action_result", "operation_id_hash": ALLOWED,
             "status": "allowed", "reason": "result_released"},
            {"seq": 4, "elapsed_ms": 30, "event": "action_proposed", "operation_id_hash": DENIED},
            {"seq": 5, "elapsed_ms": 40, "event": "action_result", "operation_id_hash": DENIED,
             "status": "denied", "reason": "outside_scope"},
            {"seq": 6, "elapsed_ms": 41, "event": "run_finished", "status": "denied",
             "reason": "outside_scope"},
        ],
    }
    controller = []
    observations = [
        ("action_proposed", ALLOWED, {}),
        ("decision", ALLOWED, {"status": "reserved", "reason": "reserved"}),
        ("tool_started", ALLOWED, {}),
        ("tool_finished", ALLOWED, {"reason": "settled"}),
        ("result_release", ALLOWED, {"status": "allowed", "reason": "result_released"}),
        ("action_proposed", DENIED, {}),
        ("decision", DENIED, {"status": "denied", "reason": "outside_scope"}),
    ]
    for event_id, (name, operation_hash, codes) in enumerate(observations, 1):
        controller.append({"source": "controller", "event_id": event_id,
                           "at": 1000 - event_id, "event": name,
                           "operation_id_hash": operation_hash, **bindings, **codes})
    return {"mode": "synthetic_local_processes", "live_model_calls": 0, "aws_mutations": 0,
            "observability": {"agent_trace": agent,
                              "controller_trace": {"source": "controller", "events": controller}}}


def test_renderer_shows_actual_source_events_with_separate_ordering():
    rendered = render_report(trace_report(), "/private/contract-report.json")
    assert "Agent stream (reported):" in rendered
    assert "Controller journal:" in rendered
    assert "seq=2 +10ms: action_proposed" in rendered
    assert "event_id=2: decision [reserved, reserved]" in rendered
    assert "event_id=7: decision [denied, outside_scope]" in rendered
    assert "cross-process clocks are not ordered" in rendered
    assert "grant no authority" in rendered
    assert "Trace artifact: /private/contract-report.json" in rendered
    denied_journey = rendered.split("Operation " + DENIED)[1].split("Other SDK observations")[0]
    assert "tool_started" not in denied_journey
    assert "tool_finished" not in denied_journey
    assert "result_release" not in denied_journey


def test_missing_controller_events_never_turn_agent_claim_into_authority():
    report = trace_report()
    del report["observability"]["controller_trace"]
    rendered = render_report(report, "/private/report.json")
    assert "authorization and effects are unconfirmed" in rendered
    assert "execution is unconfirmed" in rendered
    assert "event_id=" not in rendered
    assert "seq=3 +20ms: action_result [allowed, result_released]" in rendered


def test_truncated_agent_trace_explicitly_warns_about_missing_observations():
    report = trace_report()
    report["observability"]["agent_trace"].update(truncated=True, dropped_events=3)
    rendered = render_report(report, "/private/report.json")
    assert "missing events do not establish that no action occurred" in rendered


def test_missing_evidence_does_not_claim_no_calls_or_actions():
    rendered = render_report({}, "/private/report.json")
    assert "no agent activity can be inferred" in rendered
    assert "authorization and effects are unconfirmed" in rendered
    assert "no live model calls" not in rendered
    assert "Operation " not in rendered


def test_projections_omit_nested_unreviewed_data_and_retain_only_safe_fields():
    report = trace_report()["observability"]
    agent = report["agent_trace"]
    controller = report["controller_trace"]["events"]
    for value in (agent, agent["events"][0], controller[0]):
        value.update(prompt="secret-prompt", token="secret-token",
                     receipt={"data": "secret-result"}, arbitrary={"nested": "secret-nested"})
    safe = repr((_safe_agent_trace(agent), _safe_controller_events(controller)))
    assert "secret" not in safe and "prompt" not in safe and "receipt" not in safe


@pytest.mark.parametrize("field,value", [("event", "secret-token"), ("reason", "secret-token"),
                                        ("operation_id_hash", "Bearer secret-token")])
def test_unreviewed_agent_labels_and_bindings_are_rejected(field, value):
    trace = deepcopy(trace_report()["observability"]["agent_trace"])
    trace["events"][0][field] = value
    with pytest.raises(RuntimeError):
        _safe_agent_trace(trace)


def test_agent_source_order_cannot_be_replaced_by_an_unsorted_stream():
    trace = trace_report()["observability"]["agent_trace"]
    trace["events"][1]["seq"] = 1
    with pytest.raises(RuntimeError, match="agent_trace_order_invalid"):
        _safe_agent_trace(trace)


@pytest.mark.parametrize("field,value", [("event", "secret-token"), ("reason", "secret-token"),
                                        ("source", "agent_sdk")])
def test_unreviewed_controller_labels_cannot_be_presented_as_authority(field, value):
    report = trace_report()
    report["observability"]["controller_trace"]["events"][0][field] = value
    rendered = render_report(report, "/private/report.json")
    assert "authorization and effects are unconfirmed" in rendered
    assert "secret-token" not in rendered
    assert "event_id=" not in rendered


def test_controller_journal_order_is_not_reconstructed_from_wall_clock():
    report = trace_report()
    events = report["observability"]["controller_trace"]["events"]
    # The valid fixture has decreasing wall-clock timestamps. Its event IDs are
    # authoritative source order; swapping those IDs must be rejected.
    events[0]["event_id"], events[1]["event_id"] = events[1]["event_id"], events[0]["event_id"]
    rendered = render_report(report, "/private/report.json")
    assert "authorization and effects are unconfirmed" in rendered
    assert "event_id=" not in rendered


def test_reused_operation_id_from_another_run_is_not_correlated():
    report = trace_report()
    report["observability"]["agent_trace"]["run_id_hash"] = "1" * 64
    rendered = render_report(report, "/private/report.json")
    assert "run bindings differ; their operations are not correlated" in rendered
    assert rendered.count("Operation " + ALLOWED) == 2
    assert rendered.count("Operation " + DENIED) == 2
    assert "No agent events recorded for this operation" in rendered
    assert "No controller events recorded for this operation; execution is unconfirmed" in rendered
