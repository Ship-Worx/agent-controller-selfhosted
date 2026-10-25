"""Pure, bounded projection of curated local reports into Braintrust rows.

This module never performs I/O and imports no agent or tracing SDK. A file is not
proof of its origin: the operator must establish provenance before export. The
checks describe consistency of the supplied observations, never absence of an
external effect or authorization to execute. No incoming destination or span
linkage is accepted. Agent bindings describe the latest observed controller
context, not the epoch of every earlier agent event.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import uuid

MAX_ROWS = 384
MAX_EXPORT_BYTES = 262_144
MAX_NUMBER = 2**53 - 1
_AGENT_EVENTS = frozenset({
    "agent_started", "model_started", "model_finished", "tool_started", "tool_finished",
    "agent_finished", "action_proposed", "action_result", "model_request", "model_result",
    "completion_request", "completion_result", "run_finished",
})
# This first exporter accepts the curated contract-demo journal projection.
_CONTROLLER_EVENTS = frozenset({
    "job_created", "action_proposed", "decision", "tool_started", "tool_finished", "result_release",
})
_STATUSES = frozenset({
    "allowed", "reserved", "completed", "denied", "held", "blocked", "error", "unknown",
    "measured", "replayed",
})
_REASONS = frozenset({
    "unrecognized_reason", "outside_scope", "released", "result_released", "settled", "reserved",
    "call_reserved", "dispatch_committed", "receipt_released", "root_stopped", "old_epoch",
    "stale_epoch", "stale_grant", "controller_fenced", "authority_inactive", "expired",
    "model_outcome_unknown", "action_outcome_unknown", "outcome_unknown", "operation_unknown",
    "controller_unavailable", "invalid_controller_response", "invalid_action_response",
    "invalid_model_response", "sdk_run_failed", "authorization_denied", "model_authorization_denied",
    "audit_unavailable",
    "completion_denied", "completion_unconfirmed", "completion_criteria_unmet", "completed",
    "root_required", "job_complete", "budget_exhausted", "call_limit", "project_budget_denied",
    "project_budget_unavailable", "missing_context", "missing_payload_fields", "input_limit",
    "approval_required", "authority_changed_retry", "already_in_flight", "already_claimed",
    "result_unsettled", "malformed_proposal", "invalid_worker_input",
    "worker_privileged_credential_present", "worker_identity_required", "invalid_worker_configuration",
    "invalid_synthetic_configuration", "unsupported_synthetic_capabilities", "live_model_disabled",
    "unsupported_model_feature", "streaming_not_supported", "verified_pricing_required",
    "model_price_binding_mismatch", "operation_conflict", "ticket_binding_mismatch",
    "receiver_scope_mismatch", "receiver_action_mismatch", "binding_mismatch", "configuration_mismatch",
    "restore_anchor_missing", "restore_anchor_mismatch", "restore_quarantined", "stale_result_binding",
    "settlement_conflict", "settlement_invalid", "settlement_overrun", "reservation_replay",
    "settlement_replay", "cancelled", "operator_stop", "permission_denied", "invalid_model_input",
})
_BINDINGS = ("config_pin", "policy_pin", "controller_instance_id", "authority_epoch")
_EVALUATIONS = ("trace_correlation", "allowed_path_observed", "denied_dispatch_consistency",
                "policy_binding_consistency")


class ExportError(ValueError):
    """Only fixed codes leave the validation boundary; input values never do."""


def _require(condition, code):
    if not condition:
        raise ExportError(code)


def _hex(value, length=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is not None


def _number(value, *, integer=False):
    return (type(value) is int if integer else type(value) in (int, float)) and 0 <= value <= MAX_NUMBER


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _bindings(value, target):
    for key in ("run_id_hash", *_BINDINGS):
        if key in value:
            valid = (_number(value[key], integer=True) if key == "authority_epoch"
                     else _hex(value[key], 32 if key == "controller_instance_id" else 64))
            _require(valid, "invalid_trace_binding")
            target[key] = value[key]


def _event(value, source, previous, elapsed):
    _require(type(value) is dict, "invalid_trace_event")
    names = _AGENT_EVENTS if source == "agent_sdk" else _CONTROLLER_EVENTS
    _require(type(value.get("event")) is str and value["event"] in names, "invalid_trace_event")
    sequence_key, clock_key = (("seq", "elapsed_ms") if source == "agent_sdk" else ("event_id", "at"))
    seq, clock = value.get(sequence_key), value.get(clock_key)
    _require(_number(seq, integer=True) and seq > previous, "invalid_source_order")
    _require(_number(clock) and math.isfinite(clock), "invalid_source_time")
    if source == "agent_sdk":
        _require(clock >= elapsed, "invalid_source_time")
    else:
        _require(value.get("source") == "controller", "invalid_trace_source")
    safe = {sequence_key: seq, clock_key: clock, "event": value["event"]}
    if source == "controller":
        safe["source"] = "controller"
        _require(_hex(value.get("run_id_hash")), "invalid_trace_binding")
        _bindings(value, safe)
    if "operation_id_hash" in value:
        _require(_hex(value["operation_id_hash"]), "invalid_trace_binding")
        safe["operation_id_hash"] = value["operation_id_hash"]
    for key, codes in (("status", _STATUSES), ("reason", _REASONS)):
        if key in value:
            _require(type(value[key]) is str and value[key] in codes, "invalid_trace_code")
            safe[key] = value[key]
    return safe


def _streams(report):
    _require(type(report) is dict and type(report.get("observability")) is dict, "invalid_report")
    observation = report["observability"]
    _require(type(observation.get("schema_version")) is int and observation["schema_version"] == 1,
             "invalid_report_schema")
    sources = {}
    for key, source, maximum in (("agent_trace", "agent_sdk", 64), ("controller_trace", "controller", 256)):
        if key not in observation:
            sources[source] = None
            continue
        raw = observation[key]
        _require(type(raw) is dict and raw.get("source") == source, "invalid_trace_source")
        _require(type(raw.get("events")) is list and len(raw["events"]) <= maximum, "invalid_trace_events")
        safe = {"source": source, "events": []}
        if source == "agent_sdk":
            _require(type(raw.get("schema_version")) is int and raw["schema_version"] == 1
                     and raw.get("trust") == "agent_reported_diagnostic", "invalid_agent_schema")
            safe["trust"] = "agent_reported_diagnostic"
            _bindings(raw, safe)
            if raw["events"]:
                _require(_hex(raw.get("run_id_hash")), "invalid_trace_binding")
            for field, allowed in (("model_mode", {"scripted", "controller_broker"}),):
                if field in raw:
                    _require(type(raw[field]) is str and raw[field] in allowed, "invalid_trace_code")
                    safe[field] = raw[field]
            if "invocation_id" in raw:
                _require(_hex(raw["invocation_id"], 32), "invalid_trace_binding")
                safe["invocation_id"] = raw["invocation_id"]
        for field in ("truncated", "unavailable"):
            default = source == "agent_sdk"
            _require(type(raw.get(field, default)) is bool, "invalid_completeness")
            safe[field] = raw.get(field, default)
        dropped = raw.get("dropped_events", 0)
        _require(_number(dropped, integer=True), "invalid_completeness")
        safe["dropped_events"] = dropped
        previous, elapsed = 0, 0
        for event in raw["events"]:
            item = _event(event, source, previous, elapsed)
            previous = item.get("seq", item.get("event_id"))
            elapsed = item.get("elapsed_ms", 0)
            safe["events"].append(item)
        safe["complete"] = bool(safe["events"]) and not (safe["truncated"] or safe["unavailable"] or dropped)
        sources[source] = safe
    return sources


def _groups(sources):
    groups = {}
    for source, trace in sources.items():
        if trace is None:
            continue
        for event in trace["events"]:
            operation = event.get("operation_id_hash")
            if operation:
                run = event.get("run_id_hash", trace.get("run_id_hash"))
                groups.setdefault((run, operation), {"agent_sdk": [], "controller": []})[source].append(event)
    return groups


def _combine(results):
    return "fail" if "fail" in results else "inconclusive" if not results or "inconclusive" in results else "pass"


def _evaluate(sources):
    result = dict.fromkeys(_EVALUATIONS, "inconclusive")
    agent, controller = sources["agent_sdk"], sources["controller"]
    groups = _groups(sources)
    complete = all(trace and trace["complete"] for trace in (agent, controller))
    correlation, allowed, denied = [], [], []
    # An unbound action observation cannot be assigned to an allowed or denied
    # operation, so it makes each action check incomplete. SDK tool callbacks
    # describe generic activity and intentionally have no operation binding.
    action_events = {
        "agent_sdk": {"action_proposed", "action_result"},
        "controller": {"action_proposed", "decision", "tool_started", "tool_finished", "result_release"},
    }
    for source, trace in (("agent_sdk", agent), ("controller", controller)):
        for event in trace["events"] if trace else []:
            if event["event"] in action_events[source] and not event.get("operation_id_hash"):
                correlation.append("inconclusive")
                allowed.append("inconclusive")
                denied.append("inconclusive")
    for group in groups.values():
        ae, ce = group["agent_sdk"], group["controller"]
        ap = [e for e in ae if e["event"] == "action_proposed"]
        ar = [e for e in ae if e["event"] == "action_result"]
        cp = [e for e in ce if e["event"] == "action_proposed"]
        decisions = [e for e in ce if e["event"] == "decision"]
        releases = [e for e in ce if e["event"] == "result_release"]
        starts = [e for e in ce if e["event"] == "tool_started"]
        finishes = [e for e in ce if e["event"] == "tool_finished"]
        if not (ap or ar or cp or decisions or releases or starts or finishes):
            continue  # SDK model operations are outside these action-specific checks.
        # A bound but incomplete action group is still observed action evidence.
        # In particular, do not silently drop an orphan controller dispatch.
        if not (ap and ar and cp and decisions):
            correlation.append("inconclusive")
            allowed.append("inconclusive")
            denied.append("inconclusive")
        elif (ar[-1].get("status"), decisions[-1].get("status")) not in {
            ("allowed", "reserved"), ("denied", "denied"),
        }:
            # Matched identities can still have an unresolved action outcome.
            allowed.append("inconclusive")
            denied.append("inconclusive")
        final_controller = releases[-1] if releases else decisions[-1] if decisions else None
        contradiction = bool(ar and final_controller and ar[-1].get("status") in {"allowed", "denied"}
                             and final_controller.get("status") in {"allowed", "denied"}
                             and ar[-1]["status"] != final_controller["status"])
        agent_order_invalid = bool(ap and ar and ap[0]["seq"] >= ar[0]["seq"])
        controller_order_invalid = bool(cp and decisions and cp[0]["event_id"] >= decisions[0]["event_id"])
        # This evaluator covers one proposal and result per curated demo action;
        # repeated dispatch/replay workflows need their own explicit evaluation.
        duplicate_boundary = any(len(events) > 1 for events in (ap, ar, cp, decisions, releases))
        contradiction |= agent_order_invalid or controller_order_invalid or duplicate_boundary
        correlation.append("fail" if contradiction else "pass" if ap and ar and cp and decisions else "inconclusive")
        if any(e.get("status") == "allowed" for e in ar + releases):
            reserved = [e for e in decisions if e.get("status") == "reserved"]
            chain = [cp, reserved, starts, finishes, [e for e in releases if e.get("status") == "allowed"]]
            if contradiction or len(starts) > 1 or len(finishes) > 1:
                allowed.append("fail")
            elif all(chain):
                order = [part[0]["event_id"] for part in chain]
                allowed.append("pass" if order == sorted(order) and ap and ar and ar[-1].get("status") == "allowed"
                               else "fail" if order != sorted(order) else "inconclusive")
            else:
                allowed.append("inconclusive")
        controller_denied = any(e.get("status") == "denied" for e in decisions)
        if controller_denied or any(e.get("status") == "denied" for e in ar):
            denied.append("fail" if contradiction or (controller_denied and (starts or finishes or releases))
                          else "pass" if controller_denied and cp and ap and ar and ar[-1].get("status") == "denied"
                          else "inconclusive")
    for name, values in (("trace_correlation", correlation), ("allowed_path_observed", allowed),
                         ("denied_dispatch_consistency", denied)):
        outcome = _combine(values)
        result[name] = outcome if complete or outcome == "fail" else "inconclusive"
    binding_results = []
    by_run = {}
    for event in controller["events"] if controller else []:
        by_run.setdefault(event["run_id_hash"], []).append(event)
    for events in by_run.values():
        if any(not all(key in e for key in _BINDINGS) for e in events):
            binding_results.append("inconclusive")
            continue
        fixed = {(e["config_pin"], e["policy_pin"]) for e in events}
        epochs = [e["authority_epoch"] for e in events]
        instances = {}
        inconsistent = False
        for e in events:
            old = instances.setdefault(e["authority_epoch"], e["controller_instance_id"])
            inconsistent |= old != e["controller_instance_id"]
        binding_results.append("fail" if len(fixed) != 1 or epochs != sorted(epochs) or inconsistent else "pass")
    if agent and agent.get("run_id_hash") in by_run:
        latest = by_run[agent["run_id_hash"]][-1]
        if all(key in agent and key in latest for key in _BINDINGS):
            binding_results.append("pass" if all(agent[key] == latest[key] for key in _BINDINGS) else "inconclusive")
        else:
            binding_results.append("inconclusive")
    else:
        binding_results.append("inconclusive")
    outcome = _combine(binding_results)
    result["policy_binding_consistency"] = outcome if complete or outcome == "fail" else "inconclusive"
    if result["policy_binding_consistency"] != "pass":
        for name in _EVALUATIONS:
            if result[name] == "pass":
                result[name] = "inconclusive"
    return result


def build_export(report: dict, project_id: str) -> dict:
    """Return allowlisted rows and advisory checks; never send or grant authority."""
    _require(type(project_id) is str and re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", project_id),
        "invalid_project_id")
    project_id = str(uuid.UUID(project_id))
    sources = _streams(report)
    evaluations = _evaluate(sources)
    digest = hashlib.sha256(_json(sources).encode()).hexdigest()
    namespace = uuid.UUID(project_id)

    def identity(label):
        return str(uuid.uuid5(namespace, digest + ":" + label))

    rows, roots, operations = [], {}, {}

    def row(label, name, metadata, root=None, parent=None):
        identifier = identity(label)
        entry = {"id": identifier, "span_id": identifier, "root_span_id": root or identifier,
                 "span_parents": [parent] if parent else [], "span_attributes": {"name": name},
                 "metadata": metadata, "_is_merge": False}
        rows.append(entry)
        _require(len(rows) <= MAX_ROWS, "export_row_limit")
        return identifier

    for source, trace in sources.items():
        if trace is None:
            continue
        for event in trace["events"]:
            run = event.get("run_id_hash", trace.get("run_id_hash"))
            if run not in roots:
                roots[run] = row("run:" + run, "controller_run_observations", {
                    "source": "collector", "trust": "operator_supplied_report", "run_id_hash": run,
                    "snapshot_sha256": digest, "evaluations": evaluations, "evaluation_scope": "report_snapshot",
                    "clocks": "source_order_only", "effect_absence_proven": False,
                })
            root = roots[run]
            operation = event.get("operation_id_hash")
            parent = root
            if operation:
                key = (run, operation)
                if key not in operations:
                    operations[key] = row("operation:" + run + ":" + operation, "operation_observations", {
                        "source": "collector", "trust": "operator_supplied_report", "run_id_hash": run,
                        "operation_id_hash": operation,
                    }, root, root)
                parent = operations[key]
            metadata = {"source": source, "trust": "agent_reported_diagnostic" if source == "agent_sdk"
                        else "controller_journal_projection", "run_id_hash": run, **event}
            if source == "agent_sdk":
                # Never attribute a current binding to an earlier callback.
                metadata["binding_scope"] = "latest_observed_at_report_end"
                metadata["latest_observed_binding"] = {key: trace[key] for key in _BINDINGS if key in trace}
                for key in ("invocation_id", "model_mode"):
                    if key in trace:
                        metadata[key] = trace[key]
            sequence = event["seq"] if source == "agent_sdk" else event["event_id"]
            row("event:" + run + ":" + source + ":" + str(sequence), source + "." + event["event"],
                metadata, root, parent)
    agent, controller = sources["agent_sdk"], sources["controller"]
    summary = {"agent_stream_present": agent is not None, "controller_stream_present": controller is not None,
               "agent_event_count": len(agent["events"]) if agent else 0,
               "controller_event_count": len(controller["events"]) if controller else 0,
               "agent_complete": bool(agent and agent["complete"]),
               "controller_complete": bool(controller and controller["complete"]),
               "agent_truncated": bool(agent and agent["truncated"]),
               "agent_unavailable": bool(agent and agent["unavailable"]),
               "agent_dropped_events": agent["dropped_events"] if agent else 0,
               "run_count": len(roots), "operation_count": len(operations), "row_count": len(rows),
               "source_order_preserved": True, "cross_source_clock_ordered": False,
               "input_authenticity_verified": False, "effect_absence_proven": False}
    output = {"schema_version": 1, "project_id": project_id, "events": rows,
              "evaluations": evaluations, "summary": summary}
    _require(len(json.dumps(output, allow_nan=False).encode()) <= MAX_EXPORT_BYTES, "export_size_limit")
    return output
