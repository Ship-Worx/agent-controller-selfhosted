"""Two fictional business policies selected only by the trusted operator."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path

from controller.engine import Binding, Capability, Contract, Limits, ValidationOutcome
from controller.validators import _bind_validator

PRICES = {"record.read": 2, "report.write": 5, "report.slow": 5}


@dataclass(frozen=True)
class Workflow:
    name: str
    resource: str
    purpose: str
    task: str
    record: dict

    @property
    def context(self):
        return {"record_id": self.resource, "task": self.task}

    @property
    def completion_criteria(self):
        return "An authorized read and internal report have durable receipts."

    def contract(self, runtime_seconds=60, *, live_model=False):
        contract = Contract(
            workflow_id=self.name, version="1", purpose=self.purpose,
            capabilities=frozenset({
                Capability("read", "record.read", self.resource, "worker"),
                Capability("write", "report.write", self.resource, "internal"),
                Capability("slow", "report.slow", self.resource, "internal"),
            }),
            required_context={"read": ("record_id", "task"),
                              "write": ("record_id", "task"),
                              "slow": ("record_id", "task")},
            limits=Limits(budget_calls=12, runtime_seconds=runtime_seconds,
                          max_children=4, max_depth=2),
            allowed_principals=frozenset({("synthetic", "operator")}),
            payload_fields={"record.read": (), "report.write": ("summary",), "report.slow": ()},
            handoff_actions=frozenset(),
            delegable_context_fields=frozenset({"record_id", "task"}),
            step_dependencies={"read": (), "write": ("read",), "slow": ()},
            validation_policy="synthetic-business:" + self.name,
        )

        if live_model:
            from controller.live_model import MODEL_CAPABILITY
            contract = replace(
                contract, version="1-live",
                capabilities=contract.capabilities | {MODEL_CAPABILITY},
                required_context={**contract.required_context, "model": ("record_id", "task")},
                payload_fields={**contract.payload_fields, "model.respond": ("prompt", "pricing_pin")},
                step_dependencies={**contract.step_dependencies, "model": ()},
            )
        return contract

    def validator(self, contract, *, pricing_pin=None):
        # Source and contract are trusted deployment inputs, never HTTP parameters.
        def validate(attempt, context):
            if context.get("record_id") != self.resource:
                return ValidationOutcome.deny("record_context_mismatch")
            if attempt.action == "report.write":
                summary = attempt.payload.get("summary")
                if type(summary) is not str or not 1 <= len(summary) <= 256:
                    return ValidationOutcome.deny("invalid_summary")
            if attempt.action == "model.respond":
                from controller.live_model import MAX_PROMPT_BYTES
                prompt = attempt.payload.get("prompt")
                if (type(prompt) is not str or not 1 <= len(prompt.encode()) <= MAX_PROMPT_BYTES
                        or pricing_pin is None or attempt.payload.get("pricing_pin") != pricing_pin):
                    return ValidationOutcome.deny("invalid_model_request")
            return ValidationOutcome.allow()

        source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        return _bind_validator(
            {"mode": "reviewed", "policy_id": contract.validation_policy,
             "policy_version": "1", "definition_sha256": source_hash,
             "fixture_sha256": hashlib.sha256(json.dumps(self.record, sort_keys=True).encode()).hexdigest(),
             "pricing_pin": pricing_pin},
            "controller", validate, (contract.workflow_id, contract.version),
        )

    def binding(self, worker="root"):
        return Binding("synthetic", "operator", "session-" + worker, worker)


WORKFLOWS = {
    "recruiting": Workflow(
        "recruiting", "candidate-a", "Review one fictional candidate for a Python role.",
        "Read the assigned candidate and prepare an internal synthetic summary.",
        {"name": "Fictional Ada", "skill": "Python", "candidate_id": "candidate-a"},
    ),
    "document-processing": Workflow(
        "document-processing", "document-a", "Check completeness of one fictional document.",
        "Read the assigned document and prepare an internal synthetic summary.",
        {"name": "Fictional Ada", "address": None, "document_id": "document-a"},
    ),
}
