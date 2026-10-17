"""Show an agent obeying an assigned contract and being denied overreach.

This uses the real controller and pinned Agents SDK in separate processes, with
the SDK's scripted model. All records are fictional and no provider call occurs.
Only the allowlisted educational report survives the temporary process state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from .local import LocalController, PROJECT, proposal
from .run import check


def _operation_hash(operation_id: str) -> str:
    return hashlib.sha256(operation_id.encode()).hexdigest()


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
                    {"action": allowed["action"], "resource": allowed["resource"],
                     "status": releases[0]["status"], "reason": releases[0]["reason"],
                     "protected_tool_started": True, "effect_journal_entries": 1},
                    {"action": denied["action"], "resource": denied["resource"],
                     "status": decisions[0]["status"], "reason": decisions[0]["reason"],
                     "protected_tool_started": False, "effect_journal_entries": 0},
                ],
                "effects_before": initial["effects_count"],
                "effects_after": final["effects_count"],
                "worker_status": worker["status"],
                "task_completion_claimed": False,
                "effect_definition": "Durable receipt in the fictional receiver's effect journal.",
                "boundary_limit": "Shared-user local processes do not demonstrate OS or AWS isolation.",
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
