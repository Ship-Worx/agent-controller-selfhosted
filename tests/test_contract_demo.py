"""Exercise the published contract demo through its real process entrypoint."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

from demo.local import PROJECT
from integration.process import SDK_STARTUP_TIMEOUT


def test_contract_demo_proves_allowed_read_then_blocked_overreach(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "demo.contract", "--output-dir", str(tmp_path)],
        cwd=PROJECT, text=True, capture_output=True, timeout=SDK_STARTUP_TIMEOUT + 35,
        env={**os.environ, "OPENAI_AGENTS_DISABLE_TRACING": "1"},
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    summary = json.loads(result.stdout)
    report_path = Path(summary["report"])
    assert report_path.is_relative_to(tmp_path)
    report = json.loads(report_path.read_text())
    assert summary["passed"] == 8
    assert all(check["passed"] for check in report["checks"])
    assert report["scope"]["assigned_task"] == (
        "Read the assigned candidate and prepare an internal synthetic summary.")
    capabilities = report["scope"]["allowed_capabilities"]
    assert any(cap["action"] == "record.read" and cap["resource"] == "candidate-a"
               for cap in capabilities)
    assert not any(cap["resource"] == "candidate-b" for cap in capabilities)
    permitted, denied = report["observations"]
    assert permitted["status"] == "allowed"
    assert permitted["protected_tool_started"] is True
    assert permitted["effect_journal_entries"] == 1
    assert denied == {
        "operation_id_hash": hashlib.sha256(b"contract-outside-read").hexdigest(),
        "action": "record.read", "resource": "candidate-b", "status": "denied",
        "reason": "outside_scope", "protected_tool_started": False, "effect_journal_entries": 0,
    }
    assert (report["effects_before"], report["effects_after"]) == (0, 1)
    assert report["worker_status"] == "denied"
    assert report["task_completion_claimed"] is False
    assert report["live_model_calls"] == report["aws_mutations"] == 0
    traces = report["observability"]
    assert traces["join_keys"] == ["run_id_hash", "operation_id_hash"]
    assert traces["authority_source"] == "controller"
    agent = traces["agent_trace"]
    controller = traces["controller_trace"]["events"]
    assert agent["source"] == "agent_sdk" and agent["trust"] == "agent_reported_diagnostic"
    assert agent["model_mode"] == "scripted"
    assert agent["unavailable"] is agent["truncated"] is False
    assert agent["dropped_events"] == 0
    names = [event["event"] for event in agent["events"]]
    assert {"agent_started", "model_started", "model_finished", "tool_started",
            "tool_finished", "action_proposed", "action_result", "run_finished"} <= set(names)
    assert names[-1] == "run_finished"
    for observation in report["observations"]:
        operation_hash = observation["operation_id_hash"]
        local = [event for event in agent["events"] if event.get("operation_id_hash") == operation_hash]
        authoritative = [event for event in controller if event.get("operation_id_hash") == operation_hash]
        assert [event["event"] for event in local] == ["action_proposed", "action_result"]
        assert local[-1]["status"] == observation["status"]
        assert all(event["source"] == "controller" for event in authoritative)
        assert all(event["run_id_hash"] == agent["run_id_hash"] for event in authoritative)
        assert all(event["config_pin"] == agent["config_pin"]
                   and event["policy_pin"] == agent["policy_pin"]
                   and event["authority_epoch"] == agent["authority_epoch"]
                   and event["controller_instance_id"] == agent["controller_instance_id"]
                   for event in authoritative)
    denied_events = [event for event in controller
                     if event.get("operation_id_hash") == denied["operation_id_hash"]]
    assert [event["event"] for event in denied_events] == ["action_proposed", "decision"]
    assert denied_events[-1]["reason"] == "outside_scope"
    # Runtime DBs, readiness files, SDK receipts and raw plans must not survive
    # as demonstration artifacts. The report contains no record body or bearer.
    assert list(report_path.parent.iterdir()) == [report_path]
    for forbidden in ('"token"', '"ticket"', '"receipt"', '"data"',
                      '"job_id"', '"run_id"', "Fictional Ada", "Bearer "):
        assert forbidden not in report_path.read_text()
