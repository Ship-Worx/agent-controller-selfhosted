"""Hermetic, single-process reference controller; NOT an isolation boundary.

Only Worker methods are the modeled untrusted interface. Controller construction,
registration, admission, approvals, narrowing, rotation, Stop and inspection are
trusted operator surfaces. A Python caller with arbitrary object/process access
can bypass this model. Real identity, durable state, fencing and receiver access
restrictions require a separate deployment proof. The authority lock never covers adapter calls;
Stop cannot retract earlier committed dispatch or physically cancel adapters.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import re
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("JSON object keys must be strings")
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError("Only finite JSON data is accepted")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    return value


def _encoded(value: Any) -> bytes:
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def _names(*names: str) -> None:
    if any(not isinstance(n, str) or not n or len(n) > 512 for n in names):
        raise ValueError("Identifiers must be nonempty strings of at most 512 characters")


@dataclass(frozen=True)
class Binding:
    tenant: str
    principal: str
    session: str
    worker: str

    def __post_init__(self):
        _names(self.tenant, self.principal, self.session, self.worker)


@dataclass(frozen=True, order=True)
class Capability:
    step: str
    action: str
    resource: str
    recipient: str

    def __post_init__(self):
        _names(self.step, self.action, self.resource, self.recipient)


@dataclass(frozen=True)
class Limits:
    budget_calls: int = 20
    input_bytes: int = 16384
    runtime_seconds: float = 60
    max_children: int = 4
    max_depth: int = 3

    def __post_init__(self):
        for n in (self.budget_calls, self.input_bytes, self.max_children, self.max_depth):
            if type(n) is not int or n < 0:
                raise ValueError("Integer limits must be nonnegative")
        if (type(self.runtime_seconds) not in (int, float)
                or not math.isfinite(self.runtime_seconds) or self.runtime_seconds <= 0):
            raise ValueError("Runtime must be finite and positive")


@dataclass(frozen=True)
class Contract:
    workflow_id: str
    version: str
    purpose: str
    capabilities: frozenset[Capability]
    required_context: Mapping[str, tuple[str, ...]]
    limits: Limits
    exact_approval_actions: frozenset[str] = frozenset()
    allowed_principals: frozenset[tuple[str, str]] = frozenset()
    payload_fields: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    handoff_actions: frozenset[str] = frozenset({"handoff"})
    delegable_context_fields: frozenset[str] = frozenset()
    step_dependencies: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    validation_policy: str | None = None

    def __post_init__(self):
        _names(self.workflow_id, self.version, self.purpose)
        if self.validation_policy is not None:
            _names(self.validation_policy)
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        object.__setattr__(self, "exact_approval_actions", frozenset(self.exact_approval_actions))
        object.__setattr__(self, "allowed_principals", frozenset(self.allowed_principals))
        object.__setattr__(self, "handoff_actions", frozenset(self.handoff_actions))
        object.__setattr__(self, "delegable_context_fields", frozenset(self.delegable_context_fields))
        object.__setattr__(self, "required_context", _freeze(self.required_context))
        object.__setattr__(self, "payload_fields", _freeze(self.payload_fields))
        object.__setattr__(self, "step_dependencies", _freeze(self.step_dependencies))


@dataclass(frozen=True)
class Attempt:
    operation_id: str
    step: str
    action: str
    resource: str
    recipient: str
    payload: Mapping[str, Any]

    def __post_init__(self):
        _names(self.operation_id, self.step, self.action, self.resource, self.recipient)
        if not isinstance(self.payload, Mapping):
            raise ValueError("Payload must be a JSON object")
        object.__setattr__(self, "payload", _freeze(self.payload))


class _CallbackAttempt(Attempt):
    """Detached JSON containers for trusted adapters; never the ledger's input."""
    def __post_init__(self):
        pass


def _callback_attempt(attempt):
    return _CallbackAttempt(attempt.operation_id, attempt.step, attempt.action,
                            attempt.resource, attempt.recipient, _plain(attempt.payload))


@dataclass(frozen=True)
class ValidationOutcome:
    """Trusted validator decision. Reasons are safe codes, never input excerpts."""
    status: str
    reason: str

    def __post_init__(self):
        if not self.valid():
            raise ValueError("Validation needs an explicit status and safe reason code")

    def valid(self):
        return (type(self.status) is str and self.status in {"allow", "hold", "deny"}
                and type(self.reason) is str
                and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", self.reason) is not None)

    @classmethod
    def allow(cls, reason="validated"):
        return cls("allow", reason)

    @classmethod
    def hold(cls, reason):
        return cls("hold", reason)

    @classmethod
    def deny(cls, reason):
        return cls("deny", reason)


@dataclass(frozen=True)
class Result:
    status: str
    reason: str
    receipt: Any = None
    replayed: bool = False


class GateError(Exception):
    def __init__(self, result: Result):
        self.result = result
        super().__init__(result.reason)


@dataclass(frozen=True)
class AuditEvent:
    root_id: str
    run_id: str
    operation_id: str | None
    status: str
    reason: str
    generation: int
    at: float


@dataclass(frozen=True)
class Snapshot:
    root_id: str
    run_id: str
    parent_id: str | None
    binding: Binding
    workflow_id: str
    version: str
    purpose: str
    generation: int
    stopped: bool
    budget_used: int
    budget_limit: int
    children: int
    depth: int
    deadline: float
    capabilities: frozenset[Capability]
    context: Mapping[str, Any]
    unknown_operations: tuple[str, ...]
    audit: tuple[AuditEvent, ...]
    completed_steps: frozenset[str] = frozenset()
    in_flight_operations: tuple[str, ...] = ()


@dataclass
class _Operation:
    fingerprint: str
    status: str = "reserved"
    receipt: Any = None
    child_token: str | None = None
    lineage: tuple = ()


@dataclass
class _Run:
    run_id: str
    root_id: str
    parent_id: str | None
    binding: Binding
    pin: str
    capabilities: frozenset[Capability]
    context: Mapping[str, Any]
    deadline: float
    depth: int
    token: str
    generation: int = 0
    ancestor_sessions: tuple = ()


@dataclass
class _Root:
    limit: int
    stopped: bool = False
    used: int = 0
    children: int = 0
    operations: dict[str, _Operation] = field(default_factory=dict)
    audit: list[AuditEvent] = field(default_factory=list)
    completed_steps: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class _Dispatch:
    root_id: str
    run_id: str
    attempt: Attempt
    fingerprint: str


class Worker:
    """Modeled dispatch facade, bound by an opaque token rather than claimed IDs.

    Execute returns settlement evidence for earlier committed dispatch, including
    after Stop. Hosts that expose results to agents must use release_result first;
    this facade alone does not demonstrate a separate result-disclosure boundary.
    """
    __slots__ = ("_controller", "token")

    def __init__(self, controller: Controller, token: str):
        self._controller, self.token = controller, token

    def execute(self, attempt: Attempt, *, binding=None, approval_id=None) -> Result:
        return self._controller.execute(self.token, attempt, binding=binding, approval_id=approval_id)

    def delegate(self, binding: Binding, capabilities, context, *, runtime_seconds=None) -> Worker:
        return self._controller.delegate(self.token, binding, capabilities, context,
                                         runtime_seconds=runtime_seconds)

    def handoff(self, attempt, receiver_binding, capabilities, context, *, approval_id=None):
        return self._controller.handoff(self.token, attempt, receiver_binding,
                                        capabilities, context, approval_id=approval_id)


class Controller:
    """Trusted local reference state; never hand this object to real workers.

    Validators/adapters are reviewed code, not pinned by the declaration digest.
    Admission is a trusted operator action, not real caller authentication. Audit
    callbacks must accept safe events and may fail; local denials always close the
    fence. No validator, audit sink or effect adapter holds the authority lock. A committed
    dispatch can finish after Stop; Stop prevents later dispatch and child issue.
    State, including denial evidence, is process-local and is not crash authority.
    """
    def __init__(self, adapter: Callable, *, clock=time.monotonic, audit_sink=None):
        self._adapter, self._clock, self._audit_sink = adapter, clock, audit_sink
        self._lock = threading.RLock()
        self._contracts, self._runs, self._roots, self._tokens, self._approvals = {}, {}, {}, {}, {}
        self._ancestors = {}

    def register_contract(self, contract: Contract, validator=None) -> str:
        """Approve a complete declaration. Validator must return ValidationOutcome."""
        with self._lock:
            actions = {c.action for c in contract.capabilities}
            steps = {c.step for c in contract.capabilities}
            if not actions <= set(contract.payload_fields):
                raise ValueError("Every capability action needs an exact payload schema")
            if not steps <= set(contract.required_context):
                raise ValueError("Every capability step needs an explicit required_context declaration")
            if set(contract.step_dependencies) != steps:
                raise ValueError("Every capability step needs an explicit graph declaration")
            if not contract.exact_approval_actions <= actions:
                raise ValueError("Approval actions must be declared capabilities")
            for mapping in (contract.payload_fields, contract.required_context, contract.step_dependencies):
                for name, fields in mapping.items():
                    _names(name, *fields)
                    if not isinstance(fields, tuple) or len(set(fields)) != len(fields):
                        raise ValueError("Schema fields must be unique sequences")
            for tenant, principal in contract.allowed_principals:
                _names(tenant, principal)
            ancestors = {}
            def visit(step, active):
                if step not in steps or step in active:
                    raise ValueError("Step graph must be a declared acyclic graph")
                if step not in ancestors:
                    found = set(contract.step_dependencies[step])
                    for dependency in contract.step_dependencies[step]:
                        found.update(visit(dependency, active | {step}))
                    ancestors[step] = frozenset(found)
                return ancestors[step]
            for step in steps:
                visit(step, set())
            declaration = {
                "id": contract.workflow_id, "version": contract.version, "purpose": contract.purpose,
                "caps": [list(vars(c).values()) for c in sorted(contract.capabilities)],
                "context": contract.required_context, "limits": vars(contract.limits),
                "approvals": sorted(contract.exact_approval_actions),
                "principals": sorted(contract.allowed_principals), "payload": contract.payload_fields,
                "handoffs": sorted(contract.handoff_actions),
                "delegable_context": sorted(contract.delegable_context_fields),
                "step_dependencies": contract.step_dependencies,
            }
            pin = hashlib.sha256(_encoded(declaration)).hexdigest()
            if pin in self._contracts and self._contracts[pin][1] is not validator:
                raise ValueError("Cannot replace a registered contract validator")
            self._contracts[pin], self._ancestors[pin] = (contract, validator), ancestors
            return pin

    @staticmethod
    def _token(worker):
        return worker.token if isinstance(worker, Worker) else worker

    def _resolve(self, worker):
        token = self._token(worker)
        if not isinstance(token, str) or token not in self._tokens:
            raise GateError(Result("denied", "unknown_credential"))
        return self._runs[self._tokens[token][0]]

    def _lineage(self, run):
        while run is not None:
            yield run
            run = self._runs.get(run.parent_id)

    def _effective(self, run):
        caps = run.capabilities
        for ancestor in self._lineage(run):
            caps = caps & ancestor.capabilities
        return caps

    def _epoch(self, run):
        return tuple((r.run_id, r.generation, r.binding.session) for r in self._lineage(run))

    def _event(self, run, status, reason, operation_id=None):
        """Append local evidence with the lock held; external delivery is separate."""
        event = AuditEvent(run.root_id, run.run_id, operation_id, status, reason,
                           run.generation, self._clock())
        self._roots[run.root_id].audit.append(event)
        return event

    def _deliver(self, event):
        try:
            if self._audit_sink is not None:
                self._audit_sink(event)
            return True
        except Exception:
            with self._lock:
                self._roots[event.root_id].stopped = True
            return False

    def _audit(self, run, status, reason, operation_id=None):
        with self._lock:
            event = self._event(run, status, reason, operation_id)
        return self._deliver(event)

    def _deny(self, run, reason, operation_id=None):
        # Denial evidence is local even if the optional external audit sink fails.
        self._roots[run.root_id].stopped = True
        self._event(run, "denied", reason, operation_id)
        return Result("denied", reason)

    def _live(self, worker, binding=None):
        run = self._resolve(worker)
        token = self._token(worker)
        ancestors = tuple((r.run_id, r.token) for r in list(self._lineage(run))[1:])
        if (token != run.token or self._tokens[token][1] != run.binding
                or ancestors != run.ancestor_sessions
                or (binding is not None and binding != run.binding)):
            return run, self._deny(run, "binding_mismatch")
        if self._roots[run.root_id].stopped:
            return run, Result("denied", "root_stopped")
        if self._clock() >= min(r.deadline for r in self._lineage(run)):
            return run, self._deny(run, "expired")
        return run, None

    def admit(self, contract_pin, binding, context, *, capabilities=None,
              budget_calls=None, runtime_seconds=None):
        """Trusted admission; no clock, quota or Stop reset on session rotation."""
        with self._lock:
            if contract_pin not in self._contracts:
                raise GateError(Result("denied", "unapproved_contract"))
            contract = self._contracts[contract_pin][0]
            if (binding.tenant, binding.principal) not in contract.allowed_principals:
                raise GateError(Result("denied", "unapproved_principal"))
            caps = contract.capabilities if capabilities is None else frozenset(capabilities)
            if not caps <= contract.capabilities:
                raise GateError(Result("denied", "scope_widening"))
            context = _freeze(context)
            if not isinstance(context, Mapping) or len(_encoded(context)) > contract.limits.input_bytes:
                raise GateError(Result("held", "context_limit"))
            budget = contract.limits.budget_calls if budget_calls is None else budget_calls
            duration = contract.limits.runtime_seconds if runtime_seconds is None else runtime_seconds
            if type(budget) is not int or not 0 <= budget <= contract.limits.budget_calls:
                raise ValueError("Admission may only narrow lifetime budget")
            if type(duration) not in (int, float) or not 0 < duration <= contract.limits.runtime_seconds:
                raise ValueError("Admission may only narrow lifetime deadline")
            rid, token = secrets.token_hex(16), secrets.token_urlsafe(32)
            run = _Run(rid, rid, None, binding, contract_pin, caps, context,
                       self._clock() + duration, 0, token)
            self._runs[rid], self._roots[rid] = run, _Root(budget)
            self._tokens[token] = (rid, binding)
        if not self._audit(run, "admitted", "approved_contract"):
            raise GateError(Result("denied", "audit_unavailable"))
        with self._lock:
            _, blocked = self._live(token)
            if blocked:
                raise GateError(blocked)
        return Worker(self, token)

    def _fingerprint(self, run, attempt, envelope=None):
        return hashlib.sha256(_encoded({"run": run.run_id, "pin": run.pin,
                                       "attempt": vars(attempt), "handoff": envelope})).hexdigest()

    def _graph_check(self, run, attempt):
        root = self._roots[run.root_id]
        ancestors = self._ancestors[run.pin]
        if (not ancestors[attempt.step] <= root.completed_steps
                or any(attempt.step in ancestors[done] for done in root.completed_steps)):
            return self._deny(run, "step_out_of_order", attempt.operation_id)
        return None

    def _check(self, worker, attempt, binding, envelope):
        """Pure local gate under lock, including conflict checks before replay."""
        try:
            run, blocked = self._live(worker, binding)
        except GateError as exc:
            return exc.result
        if blocked:
            return blocked
        if not isinstance(attempt, Attempt):
            return self._deny(run, "malformed_attempt")
        root, (contract, validator) = self._roots[run.root_id], self._contracts[run.pin]
        if attempt.action in contract.handoff_actions and envelope is None:
            return self._deny(run, "handoff_interface_required", attempt.operation_id)
        capability = Capability(attempt.step, attempt.action, attempt.resource, attempt.recipient)
        if capability not in self._effective(run):
            return self._deny(run, "outside_scope", attempt.operation_id)
        try:
            fingerprint = self._fingerprint(run, attempt, envelope)
        except (TypeError, ValueError, RecursionError):
            return self._deny(run, "malformed_attempt", attempt.operation_id)
        previous = root.operations.get(attempt.operation_id)
        if previous and previous.fingerprint != fingerprint:
            return self._deny(run, "operation_conflict", attempt.operation_id)
        if any(k not in run.context or run.context[k] is None for k in contract.required_context[attempt.step]):
            return Result("held", "missing_context")
        expected = set(contract.payload_fields[attempt.action])
        if set(attempt.payload) - expected:
            return self._deny(run, "unexpected_payload_fields", attempt.operation_id)
        if expected - set(attempt.payload):
            return Result("held", "missing_payload_fields")
        if len(_encoded(attempt.payload)) + len(_encoded(run.context)) > contract.limits.input_bytes:
            return Result("held", "input_limit")
        if previous is None or previous.status != "allowed":
            blocked = self._graph_check(run, attempt)
            if blocked:
                return blocked
        return run, root, contract, validator, fingerprint, previous

    def _prepare(self, worker, attempt, *, binding=None, approval_id=None, envelope=None):
        worker = self._token(worker)
        with self._lock:
            checked = self._check(worker, attempt, binding, envelope)
            if isinstance(checked, Result):
                return checked
            run, _, _, validator, _, _ = checked
            context = _plain(run.context)
        if validator is not None:
            try:
                validation = validator(_callback_attempt(attempt), context)
            except Exception:
                with self._lock:
                    return self._deny(run, "validator_unavailable", attempt.operation_id)
            try:
                valid_outcome = type(validation) is ValidationOutcome and ValidationOutcome.valid(validation)
            except (AttributeError, TypeError, ValueError):
                valid_outcome = False
            if not valid_outcome:
                with self._lock:
                    return self._deny(run, "validator_result_invalid", attempt.operation_id)
            if validation.status == "deny":
                with self._lock:
                    return self._deny(run, validation.reason, attempt.operation_id)
            if validation.status == "hold":
                with self._lock:
                    checked = self._check(worker, attempt, binding, envelope)
                    return checked if isinstance(checked, Result) else Result("held", validation.reason)
        if not self._audit(run, "candidate", "validated", attempt.operation_id):
            return Result("denied", "audit_unavailable")
        with self._lock:
            checked = self._check(worker, attempt, binding, envelope)
            if isinstance(checked, Result):
                return checked
            run, root, contract, _, fingerprint, previous = checked
            if previous:
                if previous.status == "allowed":
                    return Result("allowed", "replay", previous.receipt, True)
                if previous.status in {"reserved", "dispatched"}:
                    return Result("held", "operation_in_flight")
                return Result("held", "operation_unknown" if previous.status == "unknown" else "operation_cancelled")
            if any(op.status == "unknown" for op in root.operations.values()):
                return Result("held", "operation_unknown")
            approval = None
            if attempt.action in contract.exact_approval_actions:
                if approval_id is None:
                    return Result("held", "approval_required")
                approval = self._approvals.get(approval_id)
                if approval != (fingerprint, self._epoch(run), False):
                    return self._deny(run, "invalid_approval", attempt.operation_id)
            if root.used >= root.limit:
                return Result("held", "budget_exhausted")
            root.used += 1
            operation = _Operation(fingerprint, lineage=self._epoch(run))
            root.operations[attempt.operation_id] = operation
            if approval is not None:
                self._approvals[approval_id] = (approval[0], approval[1], True)
            reserved = self._event(run, "reserved", "call_reserved", attempt.operation_id)
        audit_ok = self._deliver(reserved)
        with self._lock:
            if not audit_ok:
                operation.status = "cancelled"
                return Result("denied", "audit_unavailable")
            # Reservation audit can block: recheck the live fence before dispatch.
            checked = self._check(worker, attempt, binding, envelope)
            if isinstance(checked, Result):
                operation.status = "cancelled"
                return checked
            if approval is not None and self._approvals.get(approval_id) != (fingerprint, self._epoch(run), True):
                operation.status = "cancelled"
                return self._deny(run, "invalid_approval", attempt.operation_id)
            if any(op.status == "unknown" for op in root.operations.values()):
                operation.status = "cancelled"
                return Result("held", "operation_unknown")
            operation.status = "dispatched"
            self._event(run, "dispatched", "dispatch_committed", attempt.operation_id)
            return _Dispatch(run.root_id, run.run_id, attempt, fingerprint)

    def _unknown(self, dispatch):
        with self._lock:
            operation = self._roots[dispatch.root_id].operations[dispatch.attempt.operation_id]
            operation.status = "unknown"
            run = self._runs[dispatch.run_id]
        self._audit(run, "unknown", "adapter_interrupted", dispatch.attempt.operation_id)
        return Result("unknown", "adapter_interrupted")

    def _finish(self, dispatch, receipt):
        try:
            receipt = _freeze(receipt)
        except (TypeError, ValueError, RecursionError):
            return self._unknown(dispatch)
        run = self._runs[dispatch.run_id]
        audit_ok = self._audit(run, "completed", "receipt_observed", dispatch.attempt.operation_id)
        with self._lock:
            root = self._roots[dispatch.root_id]
            operation = root.operations[dispatch.attempt.operation_id]
            operation.receipt = receipt
            if not audit_ok:
                operation.status = "unknown"
                return Result("unknown", "audit_unavailable", receipt)
            operation.status = "allowed"
            root.completed_steps.add(dispatch.attempt.step)
            return Result("allowed", "executed", receipt)

    def execute(self, worker, attempt, *, binding=None, approval_id=None):
        """Dispatch and settle; receipt is host evidence, not fresh disclosure approval."""
        return self._execute(worker, attempt, binding=binding, approval_id=approval_id)

    def _execute(self, worker, attempt, *, binding=None, approval_id=None, envelope=None):
        dispatch = self._prepare(worker, attempt, binding=binding, approval_id=approval_id, envelope=envelope)
        if isinstance(dispatch, Result):
            return dispatch
        try:
            receipt = self._adapter(dispatch.root_id, dispatch.run_id, _callback_attempt(attempt))
        except BaseException as exc:
            result = self._unknown(dispatch)
            if not isinstance(exc, Exception):
                raise
            return result
        return self._finish(dispatch, receipt)

    async def execute_async(self, worker, attempt, *, adapter, binding=None, approval_id=None):
        """Host-selected async adapter; settle earlier dispatch even after Stop.

        A host must separately call release_result before exposing the receipt.
        Neither settlement nor this return authorizes disclosure under old grants.
        """
        dispatch = self._prepare(worker, attempt, binding=binding, approval_id=approval_id)
        if isinstance(dispatch, Result):
            return dispatch
        try:
            receipt = await adapter(dispatch.root_id, dispatch.run_id, _callback_attempt(attempt))
        except BaseException as exc:
            result = self._unknown(dispatch)
            if not isinstance(exc, Exception):
                raise
            return result
        return self._finish(dispatch, receipt)

    def release_result(self, worker, attempt, *, binding=None):
        """Authorize disclosure of a settled ordinary operation under current grants.

        This opt-in trusted host API retrieves the protected receipt by the exact
        original Attempt. It never dispatches, charges, or accepts a caller-supplied
        receipt. The SDK uses it before projection; raw execute settlement semantics
        remain unchanged. Handoffs retain their separate envelope-bound interface.
        """
        with self._lock:
            checked = self._check(self._token(worker), attempt, binding, None)
            if isinstance(checked, Result):
                return checked
            run, _, _, _, _, operation = checked
            if operation is None or operation.status != "allowed":
                return Result("held", "result_unsettled")
            if operation.lineage != self._epoch(run):
                return self._deny(run, "stale_result_binding", attempt.operation_id)
            self._event(run, "released", "receipt_released", attempt.operation_id)
            return Result("allowed", "result_released", operation.receipt)

    def issue_approval(self, worker, attempt):
        with self._lock:
            run, blocked = self._live(worker)
            if blocked:
                raise GateError(blocked)
            token = secrets.token_urlsafe(32)
            self._approvals[token] = (self._fingerprint(run, attempt), self._epoch(run), False)
            return token

    def issue_handoff_approval(self, worker, attempt, binding, capabilities, context):
        with self._lock:
            plan = self._child_plan(worker, binding, capabilities, context, None)
            token = secrets.token_urlsafe(32)
            envelope = self._envelope(binding, plan[1], plan[2])
            self._approvals[token] = (self._fingerprint(plan[0], attempt, envelope), self._epoch(plan[0]), False)
            return token

    def narrow_permissions(self, worker, capabilities):
        with self._lock:
            run = self._resolve(worker)
            caps = frozenset(capabilities)
            if not caps <= run.capabilities:
                raise ValueError("Permissions can only be narrowed")
            run.capabilities, run.generation = caps, run.generation + 1
        self._audit(run, "authority_changed", "permissions_narrowed")

    def rotate_session(self, worker, new_session):
        with self._lock:
            run = self._resolve(worker)
            run.binding = Binding(run.binding.tenant, run.binding.principal, new_session, run.binding.worker)
            run.generation += 1
            run.token = secrets.token_urlsafe(32)
            token = run.token
            self._tokens[token] = (run.run_id, run.binding)
        self._audit(run, "authority_changed", "session_rotated")
        return Worker(self, token)

    def stop_root(self, worker, reason="operator_stop"):
        with self._lock:
            run = self._resolve(worker)
            self._roots[run.root_id].stopped = True
        self._audit(run, "stopped", "operator_stop")

    def _child_plan(self, worker, binding, capabilities, context, runtime_seconds, *, replay=False):
        run, blocked = self._live(worker)
        if blocked:
            raise GateError(blocked)
        contract, root = self._contracts[run.pin][0], self._roots[run.root_id]
        try:
            caps, context = frozenset(capabilities), _freeze(context)
        except (TypeError, ValueError, RecursionError):
            raise GateError(self._deny(run, "malformed_delegation"))
        if not isinstance(binding, Binding) or not all(isinstance(c, Capability) for c in caps):
            raise GateError(self._deny(run, "malformed_delegation"))
        if (binding.tenant != run.binding.tenant
                or (binding.tenant, binding.principal) not in contract.allowed_principals
                or not caps <= self._effective(run)):
            raise GateError(self._deny(run, "delegation_widening"))
        if not replay and (root.children >= contract.limits.max_children or run.depth >= contract.limits.max_depth):
            raise GateError(Result("held", "child_limit"))
        if not replay and any(op.status == "unknown" for op in root.operations.values()):
            raise GateError(Result("held", "operation_unknown"))
        if not isinstance(context, Mapping) or len(_encoded(context)) > contract.limits.input_bytes:
            raise GateError(Result("held", "context_limit"))
        if not set(context) <= contract.delegable_context_fields or any(
                k not in run.context or _encoded(v) != _encoded(run.context[k]) for k, v in context.items()):
            raise GateError(self._deny(run, "delegation_context_changed"))
        for cap in caps:
            if any(k not in context or context[k] is None for k in contract.required_context[cap.step]):
                raise GateError(Result("held", "missing_context"))
        deadline = min(r.deadline for r in self._lineage(run))
        if runtime_seconds is not None:
            if type(runtime_seconds) not in (int, float) or not math.isfinite(runtime_seconds) or runtime_seconds <= 0:
                raise GateError(self._deny(run, "invalid_child_deadline"))
            deadline = min(deadline, self._clock() + runtime_seconds)
        return run, caps, context, deadline

    def _child(self, worker, plan, binding):
        # The original immutable proposal/deadline survives all slow callbacks.
        parent, caps, context, deadline = plan
        current = self._child_plan(worker, binding, caps, context, None)
        deadline = min(deadline, current[3])
        if self._clock() >= deadline:
            raise GateError(self._deny(parent, "child_deadline_expired"))
        rid, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        run = _Run(rid, parent.root_id, parent.run_id, binding, parent.pin, caps,
                   context, deadline, parent.depth + 1, token,
                   ancestor_sessions=tuple((r.run_id, r.token) for r in self._lineage(parent)))
        self._runs[rid], self._tokens[token] = run, (rid, binding)
        self._roots[parent.root_id].children += 1
        return Worker(self, token)

    def delegate(self, worker, binding, capabilities, context, *, runtime_seconds=None):
        worker = self._token(worker)
        with self._lock:
            plan = self._child_plan(worker, binding, capabilities, context, runtime_seconds)
        if not self._audit(plan[0], "delegated", "child_candidate"):
            raise GateError(Result("denied", "audit_unavailable"))
        with self._lock:
            return self._child(worker, plan, binding)

    def handoff(self, worker, attempt, receiver_binding, capabilities, context, *, approval_id=None):
        """Deliver before child issue; a later fence can deny child with receipt retained."""
        worker = self._token(worker)
        try:
            with self._lock:
                run, blocked = self._live(worker)
                if blocked:
                    return blocked, None
                if not isinstance(attempt, Attempt) or not isinstance(receiver_binding, Binding):
                    return self._deny(run, "malformed_handoff"), None
                contract = self._contracts[run.pin][0]
                if attempt.action not in contract.handoff_actions or attempt.recipient != receiver_binding.worker:
                    return self._deny(run, "handoff_binding_mismatch"), None
                previous = self._roots[run.root_id].operations.get(attempt.operation_id)
                plan = self._child_plan(worker, receiver_binding, capabilities, context, None,
                                        replay=previous is not None)
                envelope = self._envelope(receiver_binding, plan[1], plan[2])
                if previous and previous.child_token:
                    _, blocked = self._live(previous.child_token)
                    if blocked:
                        return blocked, None
        except GateError as exc:
            return exc.result, None
        result = self._execute(worker, attempt, approval_id=approval_id, envelope=envelope)
        if result.status != "allowed":
            return result, None
        try:
            with self._lock:
                operation = self._roots[run.root_id].operations[attempt.operation_id]
                # Another identical caller may have issued the child while we awaited.
                if operation.child_token:
                    self._child_plan(worker, receiver_binding, plan[1], plan[2], None, replay=True)
                    _, blocked = self._live(operation.child_token)
                    if blocked:
                        raise GateError(blocked)
                    return result, Worker(self, operation.child_token)
                child = self._child(worker, plan, receiver_binding)
                operation.child_token = child.token
                return result, child
        except GateError as exc:
            failure = exc.result
            return Result(failure.status, "child_not_issued_" + failure.reason,
                          result.receipt, result.replayed), None

    @staticmethod
    def _envelope(binding, capabilities, context):
        return {"binding": vars(binding), "capabilities": [vars(c) for c in sorted(capabilities)],
                "context": context}

    def snapshot(self, worker):
        with self._lock:
            run = self._resolve(worker)
            root, contract = self._roots[run.root_id], self._contracts[run.pin][0]
            return Snapshot(run.root_id, run.run_id, run.parent_id, run.binding,
                            contract.workflow_id, contract.version, contract.purpose,
                            run.generation, root.stopped, root.used, root.limit, root.children,
                            run.depth, min(r.deadline for r in self._lineage(run)), self._effective(run),
                            run.context, tuple(k for k, op in root.operations.items() if op.status == "unknown"),
                            tuple(root.audit), frozenset(root.completed_steps),
                            tuple(k for k, op in root.operations.items()
                                  if op.status in {"reserved", "dispatched"}))
