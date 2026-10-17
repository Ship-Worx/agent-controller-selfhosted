"""Show an agent obeying an assigned contract and being denied overreach.

This uses the real controller and pinned Agents SDK in separate processes, with
the SDK's scripted model. All records are fictional and no provider call occurs.
Only the allowlisted educational report survives the temporary process state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

from .local import LocalController, PROJECT, proposal
from .run import check


def _operation_hash(operation_id: str) -> str:
    return hashlib.sha256(operation_id.encode()).hexdigest()


def _hex(value, length):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None


def _safe_controller_events(events):
    """Project only this demo's known journal fields; omit request/result data."""
    projected = []
    previous_id = 0
    names = {"job_created", "action_proposed", "decision", "tool_started",
             "tool_finished", "result_release"}
    statuses = {"reserved", "allowed", "denied", "held"}
    reasons = {"reserved", "settled", "result_released", "outside_scope"}
    for event in events:
        check(type(event) is dict and event.get("source") == "controller",
              "invalid_controller_trace_source")
        event_id, at = event.get("event_id"), event.get("at")
        check(type(event_id) is int and event_id > previous_id,
              "controller_trace_order_invalid")
        check(type(at) in (int, float) and math.isfinite(at) and at >= 0,
              "controller_trace_time_invalid")
        check(event.get("event") in names, "unexpected_controller_trace_event")
        safe = {"source": "controller", "event_id": event_id, "at": at,
                "event": event["event"]}
        check(_hex(event.get("run_id_hash"), 64), "invalid_controller_run_binding")
        safe["run_id_hash"] = event["run_id_hash"]
        for key in ("operation_id_hash", "config_pin", "policy_pin"):
            if key in event:
                check(_hex(event[key], 64), "invalid_controller_trace_binding")
                safe[key] = event[key]
        check(_hex(event.get("controller_instance_id"), 32)
              and type(event.get("authority_epoch")) is int and event["authority_epoch"] > 0,
              "invalid_controller_trace_authority")
        safe["controller_instance_id"] = event["controller_instance_id"]
        safe["authority_epoch"] = event["authority_epoch"]
        for key, allowed in (("status", statuses), ("reason", reasons)):
            if key in event:
                check(event[key] in allowed, "unexpected_controller_trace_code")
                safe[key] = event[key]
        projected.append(safe)
        previous_id = event_id
    return projected


def _safe_agent_trace(trace):
    """Validate and project worker observations without treating them as grants."""
    check(type(trace) is dict and type(trace.get("schema_version")) is int
          and trace["schema_version"] == 1
          and trace.get("source") == "agent_sdk"
          and trace.get("trust") == "agent_reported_diagnostic", "invalid_agent_trace_schema")
    check(_hex(trace.get("invocation_id"), 32), "invalid_agent_trace_invocation")
    check(trace.get("model_mode") in {"scripted", "controller_broker"},
          "invalid_agent_trace_model_mode")
    check(type(trace.get("truncated")) is bool
          and type(trace.get("unavailable")) is bool
          and type(trace.get("dropped_events")) is int and trace["dropped_events"] >= 0,
          "invalid_agent_trace_completeness")
    safe = {key: trace[key] for key in ("schema_version", "source", "invocation_id",
                                       "trust", "model_mode", "truncated", "dropped_events",
                                       "unavailable")}
    for key in ("run_id_hash", "config_pin", "policy_pin"):
        check(_hex(trace.get(key), 64), "invalid_agent_trace_binding")
        safe[key] = trace[key]
    check(_hex(trace.get("controller_instance_id"), 32)
          and type(trace.get("authority_epoch")) is int and trace["authority_epoch"] > 0,
          "invalid_agent_trace_authority")
    safe["controller_instance_id"] = trace["controller_instance_id"]
    safe["authority_epoch"] = trace["authority_epoch"]
    check(type(trace.get("events")) is list and 1 <= len(trace["events"]) <= 64,
          "invalid_agent_trace_events")
    names = {"agent_started", "model_started", "model_finished", "tool_started",
             "tool_finished", "agent_finished", "action_proposed", "action_result",
             "model_request", "model_result", "completion_request", "completion_result",
             "run_finished"}
    statuses = {"completed", "error", "denied", "allowed", "held", "reserved", "blocked"}
    reasons = {"outside_scope", "result_released", "completed", "sdk_run_failed"}
    previous_sequence, previous_elapsed = 0, -1
    safe["events"] = []
    for event in trace["events"]:
        check(type(event) is dict and event.get("event") in names,
              "invalid_agent_trace_event")
        sequence, elapsed = event.get("seq"), event.get("elapsed_ms")
        check(type(sequence) is int and sequence > previous_sequence,
              "agent_trace_order_invalid")
        check(type(elapsed) in (int, float) and math.isfinite(elapsed)
              and elapsed >= previous_elapsed and elapsed >= 0,
              "agent_trace_time_invalid")
        item = {"seq": sequence, "elapsed_ms": elapsed, "event": event["event"]}
        if "operation_id_hash" in event:
            check(_hex(event["operation_id_hash"], 64), "invalid_agent_operation_binding")
            item["operation_id_hash"] = event["operation_id_hash"]
        for key, allowed in (("status", statuses), ("reason", reasons)):
            if key in event:
                check(event[key] in allowed, "unexpected_agent_trace_code")
                item[key] = event[key]
        safe["events"].append(item)
        previous_sequence, previous_elapsed = sequence, elapsed
    return safe


def demonstrate(directory: Path):
    """Verify both the SDK outcome and independently recorded receiver evidence."""
    directory.mkdir(parents=True, exist_ok=True)
    checks = []
    # The controller state contains protocol credentials. Retain the safe report
    # below, rather than its DBs, readiness files, plans, logs or worker receipts.
    with tempfile.TemporaryDirectory(prefix="processes-", dir=directory) as temporary:
        with LocalController(Path(temporary)) as server:
            job = server.create("recruiting")
            client = server.worker_client(job)
            initial = client.request("/snapshot")
            check(initial["effects_count"] == 0, "new_job_already_has_effects")

            allowed = proposal(job, "record.read", "contract-assigned-read")
            denied = proposal(job, "record.read", "contract-outside-read",
                              resource="candidate-b")
            check(allowed["resource"] == job["context"]["record_id"],
                  "assigned_resource_mismatch")
            check(denied["resource"] != allowed["resource"], "overreach_not_distinct")
            checks.append({"check": "trusted_contract_loaded", "passed": True})

            # The agent first reads its assigned record, then attempts the same
            # operation on another record. Instructions and memory grant nothing.
            worker = server.run_worker(job, [allowed, denied])
            check(worker["worker_pid"] not in {os.getpid(), server.process.pid},
                  "worker_not_a_separate_process")
            check(server.process.pid != os.getpid(), "controller_not_a_separate_process")
            checks.append({"check": "separate_controller_and_sdk_worker", "passed": True})

            final = client.request("/snapshot")
            events = server.admin.request("/trace?job_id=" + job["job_id"])["events"]
            allowed_hash = _operation_hash(allowed["operation_id"])
            denied_hash = _operation_hash(denied["operation_id"])
            allowed_events = [e for e in events if e.get("operation_id_hash") == allowed_hash]
            denied_events = [e for e in events if e.get("operation_id_hash") == denied_hash]
            releases = [e for e in allowed_events if e["event"] == "result_release"]
            check(len(releases) == 1 and releases[0]["status"] == "allowed",
                  "permitted_read_not_released")
            check(sum(e["event"] == "tool_started" for e in allowed_events) == 1
                  and sum(e["event"] == "tool_finished" for e in allowed_events) == 1,
                  "permitted_read_did_not_execute_once")
            check(len(worker["results"]) == 1 and worker["results"][0]["status"] == "allowed",
                  "sdk_did_not_receive_permitted_result")
            checks.append({"check": "permitted_read_executed", "passed": True})

            decisions = [e for e in denied_events if e["event"] == "decision"]
            check(len(decisions) == 1 and decisions[0]["status"] == "denied"
                  and decisions[0]["reason"] == "outside_scope",
                  "controller_did_not_deny_exact_scope_violation")
            check(worker["status"] == "denied" and worker["reason"] == "outside_scope"
                  and worker["exit_code"] == 3, "sdk_did_not_stop_on_denial")
            # Establish order from the controller journal, not the scripted plan.
            check(releases[0]["event_id"] < decisions[0]["event_id"],
                  "overreach_preceded_permitted_read")
            checks.append({"check": "overreach_denied_outside_scope", "passed": True})

            check(not any(e["event"] in {"tool_started", "tool_finished", "result_release"}
                          for e in denied_events), "denied_operation_reached_receiver")
            checks.append({"check": "denied_operation_never_started", "passed": True})
            check(final["effects_count"] == 1 and len(final["effects"]) == 1
                  and final["effects"][0]["operation_id_hash"] == allowed_hash
                  and final["effects"][0]["action"] == "record.read",
                  "denied_operation_changed_effect_journal")
            check(final["in_flight"] == [] and final["unknown_operations"] == []
                  and final["reserved_microusd"] == 0, "operation_outcome_unresolved")
            checks.append({"check": "no_incremental_effect_from_overreach", "passed": True})

            agent_trace = _safe_agent_trace(worker.get("agent_trace"))
            controller_events = _safe_controller_events(events)
            check(not agent_trace["truncated"] and not agent_trace["unavailable"]
                  and agent_trace["dropped_events"] == 0,
                  "agent_trace_incomplete")
            for operation_hash in (allowed_hash, denied_hash):
                agent_events = [event for event in agent_trace["events"]
                                if event.get("operation_id_hash") == operation_hash]
                check(any(event["event"] == "action_proposed" for event in agent_events)
                      and any(event["event"] == "action_result" for event in agent_events),
                      "agent_controller_correlation_missing")
            checks.append({"check": "agent_and_controller_traces_correlated", "passed": True})
            check(agent_trace["run_id_hash"] == _operation_hash(initial["run_id"]),
                  "agent_run_binding_mismatch")
            check(all(event["run_id_hash"] == agent_trace["run_id_hash"]
                      for event in controller_events), "controller_run_binding_mismatch")
            for key in ("config_pin", "policy_pin", "authority_epoch", "controller_instance_id"):
                check(agent_trace[key] == initial[key] == final[key], "agent_policy_binding_mismatch")
                check(all(event.get(key) == initial[key] for event in controller_events),
                      "controller_policy_binding_mismatch")
            checks.append({"check": "trace_policy_and_authority_bindings_match", "passed": True})

            # Copy only trusted fictional scope and explicit observations. Never
            # serialize job/worker dictionaries, receipts, tokens or raw events.
            report = {
                "mode": "synthetic_local_processes",
                "live_model_calls": 0,
                "aws_mutations": 0,
                "scope": {
                    "workflow": job["workflow"],
                    "purpose": job["purpose"],
                    "assigned_task": job["context"]["task"],
                    "allowed_capabilities": sorted(
                        ({key: cap[key] for key in ("step", "action", "resource", "recipient")}
                         for cap in job["capabilities"]),
                        key=lambda cap: (cap["step"], cap["action"], cap["resource"], cap["recipient"])),
                },
                "observations": [
                    {"operation_id_hash": allowed_hash,
                     "action": allowed["action"], "resource": allowed["resource"],
                     "status": releases[0]["status"], "reason": releases[0]["reason"],
                     "protected_tool_started": True, "effect_journal_entries": 1},
                    {"operation_id_hash": denied_hash,
                     "action": denied["action"], "resource": denied["resource"],
                     "status": decisions[0]["status"], "reason": decisions[0]["reason"],
                     "protected_tool_started": False, "effect_journal_entries": 0},
                ],
                "effects_before": initial["effects_count"],
                "effects_after": final["effects_count"],
                "worker_status": worker["status"],
                "task_completion_claimed": False,
                "effect_definition": "Durable receipt in the fictional receiver's effect journal.",
                "boundary_limit": "Shared-user local processes do not demonstrate OS or AWS isolation.",
                "observability": {
                    "schema_version": 1,
                    "join_keys": ["run_id_hash", "operation_id_hash"],
                    "scope_note": "Operation identifiers are correlated only within the same run.",
                    "authority_source": "controller",
                    "timing_note": "Each source retains its own event order; cross-process clocks are not ordered.",
                    "agent_trace": agent_trace,
                    "controller_trace": {"source": "controller", "events": controller_events},
                },
                "checks": checks,
            }
    output = directory / "contract-report.json"
    output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return output, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=PROJECT / ".runtime" / "contract-demo")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=args.output_dir.resolve()))
    output, checks = demonstrate(run_dir)
    print(json.dumps({"passed": len(checks), "report": str(output),
                      "mode": "synthetic_local_processes"}))


if __name__ == "__main__":
    main()
