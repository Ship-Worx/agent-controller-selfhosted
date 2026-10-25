"""Bounded local SDK observations, never execution authority or remote traces.

Hooks deliberately ignore their SDK arguments: those can contain prompts, tool
arguments, outputs and credentials. The controller journal remains authoritative
for decisions, protected effects and measured provider usage.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from agents import RunHooks


MAX_EVENTS = 64
MAX_REPORT_BYTES = 16_384
_TERMINAL_RESERVE_BYTES = 512
_EVENTS = frozenset({
    "agent_started", "model_started", "model_finished", "tool_started",
    "tool_finished", "agent_finished", "action_proposed", "action_result",
    "model_request", "model_result", "completion_request", "completion_result",
    "run_finished",
})
_STATUSES = frozenset({
    "allowed", "reserved", "completed", "denied", "held", "blocked", "error",
    "unknown", "measured", "replayed",
})
_TERMINAL_STATUSES = frozenset({"completed", "denied", "held", "blocked", "error"})
# Safe lexical shape is insufficient: a secret can itself be alphanumeric.
# Only reviewed protocol codes can enter this independent diagnostic record.
_REASONS = frozenset({
    "unrecognized_reason", "outside_scope", "released", "result_released",
    "settled", "reserved", "call_reserved", "dispatch_committed",
    "receipt_released", "root_stopped", "old_epoch", "stale_epoch",
    "stale_grant", "controller_fenced", "authority_inactive", "expired",
    "model_outcome_unknown", "action_outcome_unknown", "outcome_unknown",
    "operation_unknown", "controller_unavailable", "invalid_controller_response",
    "invalid_action_response", "invalid_model_response", "sdk_run_failed",
    "authorization_denied", "model_authorization_denied", "audit_unavailable", "completion_denied",
    "completion_unconfirmed", "completion_criteria_unmet", "completed",
    "root_required", "job_complete", "budget_exhausted", "call_limit",
    "project_budget_denied", "project_budget_unavailable", "missing_context",
    "missing_payload_fields", "input_limit", "approval_required",
    "authority_changed_retry", "already_in_flight", "already_claimed",
    "result_unsettled", "malformed_proposal", "invalid_worker_input",
    "worker_privileged_credential_present", "worker_identity_required",
    "invalid_worker_configuration", "invalid_synthetic_configuration",
    "unsupported_synthetic_capabilities", "live_model_disabled",
    "unsupported_model_feature", "streaming_not_supported",
    "verified_pricing_required", "model_price_binding_mismatch",
    "operation_conflict", "ticket_binding_mismatch", "receiver_scope_mismatch",
    "receiver_action_mismatch", "binding_mismatch", "configuration_mismatch",
    "restore_anchor_missing", "restore_anchor_mismatch", "restore_quarantined",
    "stale_result_binding", "settlement_conflict", "settlement_invalid",
    "settlement_overrun", "reservation_replay", "settlement_replay",
    "cancelled", "operator_stop", "permission_denied", "invalid_model_input",
})


class AgentTrace(RunHooks):
    """No-I/O, best-effort observations from one agent invocation.

    Optional authenticated snapshot metadata identifies the controller revision
    being observed. It does not grant authority. Event order and elapsed time
    apply within this invocation; clocks do not establish cross-process order.
    A missing or truncated trace never establishes that an action had no effect.
    """

    def __init__(self, model_mode="scripted"):
        self.events = []
        self._metadata = {}
        self._sequence = 0
        self._last_elapsed_ms = 0
        self._dropped = 0
        self._finished = False
        self._unavailable = False
        self.model_mode = model_mode if type(model_mode) is str and model_mode in {
            "scripted", "controller_broker"} else "unknown"
        try:
            self.invocation_id = secrets.token_hex(16)
            self._started = time.monotonic()
        except Exception:
            self.invocation_id = None
            self._started = 0
            self._unavailable = True

    def bind(self, snapshot):
        """Accept only optional correlation metadata, never snapshot contents."""
        try:
            if type(snapshot) is not dict:
                return
            run_id = snapshot.get("run_id")
            if type(run_id) is str and 1 <= len(run_id.encode()) <= 256:
                self._metadata["run_id_hash"] = hashlib.sha256(run_id.encode()).hexdigest()
            for name in ("run_id_hash", "config_pin", "policy_pin"):
                value = snapshot.get(name)
                if type(value) is str and re.fullmatch("[0-9a-f]{64}", value):
                    self._metadata[name] = value
            controller_id = snapshot.get("controller_instance_id")
            if type(controller_id) is str and re.fullmatch("[0-9a-f]{32}", controller_id):
                self._metadata["controller_instance_id"] = controller_id
            epoch = snapshot.get("authority_epoch")
            if type(epoch) is int and 0 <= epoch <= 2**53 - 1:
                self._metadata["authority_epoch"] = epoch
        except Exception:
            self._unavailable = True

    def _report(self):
        return {
            "schema_version": 1, "source": "agent_sdk",
            "trust": "agent_reported_diagnostic", "invocation_id": self.invocation_id,
            "model_mode": self.model_mode, **self._metadata,
            "events": list(self.events), "truncated": self._dropped > 0,
            "dropped_events": self._dropped, "unavailable": self._unavailable,
        }

    @staticmethod
    def _bytes(report):
        # Bound normal json.dumps output too, not only a compact representation.
        return len(json.dumps(report, allow_nan=False).encode())

    def _drop(self):
        self._dropped = min(self._dropped + 1, 1_000_000_000)

    def emit(self, event, *, operation_id=None, status=None, reason=None):
        """Observe fixed labels and hash operation IDs without retaining inputs."""
        try:
            if self._finished or type(event) is not str or event not in _EVENTS:
                return
            terminal = event == "run_finished"
            self._sequence = min(self._sequence + 1, 2**53 - 1)
            elapsed = min(max(int((time.monotonic() - self._started) * 1000),
                              self._last_elapsed_ms), 2**53 - 1)
            self._last_elapsed_ms = elapsed
            entry = {"seq": self._sequence, "elapsed_ms": elapsed, "event": event}
            if type(operation_id) is str and 1 <= len(operation_id.encode()) <= 256:
                entry["operation_id_hash"] = hashlib.sha256(operation_id.encode()).hexdigest()
            if status is not None:
                entry["status"] = status if type(status) is str and status in _STATUSES else "unknown"
            if reason is not None:
                entry["reason"] = reason if type(reason) is str and reason in _REASONS else "unrecognized_reason"
            if len(self.events) >= MAX_EVENTS - (0 if terminal else 1):
                self._drop()
                return
            candidate = self._report()
            candidate["events"].append(entry)
            limit = MAX_REPORT_BYTES - (0 if terminal else _TERMINAL_RESERVE_BYTES)
            if self._bytes(candidate) > limit:
                self._drop()
                return
            self.events.append(entry)
            if terminal:
                self._finished = True
        except Exception:
            # Diagnostic failure must not authorize, retry or change the request.
            self._unavailable = True

    def finish(self, result):
        """Add a safe trace without changing any existing worker result field."""
        try:
            status = result.get("status")
            self.emit("run_finished", status=status if type(status) is str
                      and status in _TERMINAL_STATUSES else "error",
                      reason=result.get("reason"))
            report = self._report()
            if self._bytes(report) > MAX_REPORT_BYTES:
                raise ValueError("trace_size_limit")
        except Exception:
            report = {"schema_version": 1, "source": "agent_sdk",
                      "trust": "agent_reported_diagnostic", "events": [],
                      "unavailable": True, "truncated": True}
        return {**result, "agent_trace": report}

    async def on_agent_start(self, context, agent):
        self.emit("agent_started")

    async def on_agent_end(self, context, agent, output):
        self.emit("agent_finished")

    async def on_llm_start(self, context, agent, system_prompt, input_items):
        self.emit("model_started")

    async def on_llm_end(self, context, agent, response):
        self.emit("model_finished")

    async def on_tool_start(self, context, agent, tool):
        self.emit("tool_started")

    async def on_tool_end(self, context, agent, tool, result):
        self.emit("tool_finished")
