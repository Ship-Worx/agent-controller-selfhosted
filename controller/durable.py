"""SQLite reference authority; synthetic costs and trusted supervisor/receiver only.

The authority and independent ``.fence.sqlite`` high-water anchor use attached
rollback-journal transactions with FULL synchronization. WAL is deliberately not
used: SQLite does not promise atomic multi-file commits in WAL mode. Never copy
or restore both files as an allegedly safe rollback. Restoring the authority
alone is detected; loss/rollback of the independent anchor requires an external
operator recovery proof. No process isolation, IAM, filesystem tamper-resistance,
real identity authentication, or real provider monetary bound is established.
SQLite's attached-transaction conditions: https://www.sqlite.org/lang_attach.html

A reservation is not dispatch permission. The isolated receiving service must
call claim immediately before its effect and settle the observed result. No
transaction is held while that service performs an effect. Stop closes future
claims, not already claimed effects. Uncertain costs stay reserved indefinitely.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields, is_dataclass
import hashlib
import json
import math
from pathlib import Path
import secrets
import sqlite3
import time
from types import MappingProxyType
from typing import Any, Mapping

from .engine import Attempt, Binding, Capability, Contract, ValidationOutcome
from .validators import ValidatorBinding


class DurableError(RuntimeError):
    """Fail-closed trusted control/storage error with a non-sensitive reason."""


def _plain(value):
    if is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("JSON keys must be strings")
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((_plain(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("Finite JSON data required")


def _json(value):
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _caps(value):
    return frozenset(Capability(**v) for v in json.loads(value))


@dataclass(frozen=True)
class Dispatch:
    ticket: str
    root_id: str
    run_id: str
    attempt: Attempt
    reserved_microusd: int
    epoch: int


@dataclass(frozen=True)
class DurableResult:
    status: str
    reason: str
    ticket: str | None = None
    receipt: Any = None
    replayed: bool = False
    dispatch: Dispatch | None = None


@dataclass(frozen=True)
class DurableSnapshot:
    root_id: str
    run_id: str
    stopped: bool
    generation: int
    deadline: float
    children: int
    calls_used: int
    budget_microusd: int
    reserved_microusd: int
    settled_microusd: int
    exposure_microusd: int
    unknown_operations: tuple[str, ...]
    capabilities: frozenset[Capability]
    context: Mapping
    purpose: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), authority_id TEXT NOT NULL,
 schema_version INTEGER NOT NULL, epoch INTEGER NOT NULL, revision INTEGER NOT NULL,
 config_pin TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS roots(
 root_id TEXT PRIMARY KEY, stopped INTEGER NOT NULL DEFAULT 0,
 budget_microusd INTEGER NOT NULL, call_limit INTEGER NOT NULL,
 children INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS runs(
 run_id TEXT PRIMARY KEY, root_id TEXT NOT NULL, parent_id TEXT,
 token TEXT UNIQUE NOT NULL, binding TEXT NOT NULL, capabilities TEXT NOT NULL,
 context TEXT NOT NULL, deadline REAL NOT NULL, depth INTEGER NOT NULL,
 generation INTEGER NOT NULL DEFAULT 0, ancestry TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY,run_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(
 approval_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, lineage TEXT NOT NULL,
 epoch INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS operations(
 ticket TEXT PRIMARY KEY, root_id TEXT NOT NULL, run_id TEXT NOT NULL,
 operation_id TEXT NOT NULL, fingerprint TEXT NOT NULL, attempt TEXT NOT NULL,
 status TEXT NOT NULL, max_cost INTEGER NOT NULL, actual_cost INTEGER,
 receipt TEXT, epoch INTEGER NOT NULL, lineage TEXT NOT NULL, approval_id TEXT,
 UNIQUE(root_id,operation_id));
CREATE TABLE IF NOT EXISTS audit(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT,root_id TEXT,run_id TEXT,
 ticket TEXT,event TEXT NOT NULL,at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS fence.anchor(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), authority_id TEXT NOT NULL,
 epoch INTEGER NOT NULL, revision INTEGER NOT NULL);
"""


class DurableAuthority:
    """Trusted service API. Do not expose this object or its DB to workers.

    A factory-bound semantic policy is mandatory and is pinned with the contract.
    Approved controller and receiver roles can use different callbacks under the
    same policy pin. Generic tests must explicitly select a synthetic-test policy;
    missing callbacks and policy changes never fall back to structural checks.
    """

    def __init__(self, path, contract: Contract, validator=None, *, prices: Mapping[str, int],
                 budget_microusd: int, clock=time.time, epoch=None):
        self.path = str(Path(path).resolve())
        self.fence_path = self.path + ".fence.sqlite"
        self.contract, self.validator, self.clock = contract, validator, clock
        self._validator_binding = validator
        self.prices = dict(prices)
        self.budget_microusd, self.epoch = budget_microusd, epoch
        actions = {cap.action for cap in contract.capabilities}
        if (type(budget_microusd) is not int or budget_microusd < 0
                or not actions <= self.prices.keys()
                or any(type(v) is not int or v < 0 for v in self.prices.values())):
            raise ValueError("Trusted nonnegative integer prices and budget are required")
        if not actions <= contract.payload_fields.keys():
            raise ValueError("Exact payload schemas required")
        steps = {cap.step for cap in contract.capabilities}
        self.dependencies = dict(getattr(contract, "step_dependencies", {}))
        if not steps <= self.dependencies.keys() or not steps <= contract.required_context.keys():
            raise ValueError("Explicit step dependencies and required context are required")
        self._validate_graph(steps)
        self._check_validator()
        self.config_pin = _digest({"contract": contract, "prices": self.prices,
                                   "budget_microusd": budget_microusd,
                                   "validation_policy": validator.policy})
        exists, fence_exists = Path(self.path).exists(), Path(self.fence_path).exists()
        if exists != fence_exists:
            raise DurableError("restore_anchor_missing")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = self._connection()
        try:
            conn.executescript(_SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
            meta = conn.execute("SELECT * FROM meta WHERE singleton=1").fetchone()
            anchor = conn.execute("SELECT * FROM fence.anchor WHERE singleton=1").fetchone()
            if meta is None and anchor is None:
                authority_id = secrets.token_hex(16)
                conn.execute("INSERT INTO meta VALUES(1,?,1,0,0,?)", (authority_id, self.config_pin))
                conn.execute("INSERT INTO fence.anchor VALUES(1,?,0,0)", (authority_id,))
            elif meta is None or anchor is None:
                raise DurableError("restore_anchor_mismatch")
            self._check(conn, check_epoch=False)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _check_validator(self):
        if type(self._validator_binding) is not ValidatorBinding:
            raise DurableError("validator_required")
        if self.validator is not self._validator_binding:
            raise DurableError("validator_binding_changed")
        try:
            self.validator.check(self.contract)
        except (AttributeError, TypeError, ValueError) as exc:
            raise DurableError(str(exc) if isinstance(exc, ValueError)
                               else "validator_binding_changed") from exc
        expected = getattr(self.contract, "validation_policy", None)
        policy = self.validator.policy
        if ((expected is None and policy.get("mode") != "synthetic_test")
                or (expected is not None and (policy.get("mode") != "reviewed"
                    or policy.get("policy_id") != expected))):
            raise DurableError("validator_policy_mismatch")

    def require_validator(self, expected_binding):
        """Trusted host verifies its required policy and role before setup effects."""
        self._check_validator()
        if type(expected_binding) is not ValidatorBinding:
            raise DurableError("validator_required")
        try:
            expected_binding.check(self.contract)
        except (AttributeError, TypeError, ValueError) as exc:
            raise DurableError("validator_binding_mismatch") from exc
        if (self.validator.policy_pin != expected_binding.policy_pin
                or self.validator.role != expected_binding.role):
            raise DurableError("validator_binding_mismatch")

    def _validate_graph(self, steps):
        visiting, seen = set(), set()
        def visit(step):
            if step in visiting or step not in steps:
                raise ValueError("Workflow graph must be acyclic and use declared steps")
            if step in seen:
                return
            visiting.add(step)
            for before in self.dependencies[step]:
                visit(before)
            visiting.remove(step)
            seen.add(step)
        for step in steps:
            visit(step)

    def _connection(self):
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("ATTACH DATABASE ? AS fence", (self.fence_path,))
        conn.execute("PRAGMA fence.synchronous=FULL")
        # Cross-file crash atomicity depends on rollback journals for BOTH files.
        for db in ("main", "fence"):
            if conn.execute(f"PRAGMA {db}.journal_mode").fetchone()[0].lower() != "delete":
                conn.close()
                raise DurableError("unsafe_journal_mode")
        return conn

    def _check(self, conn, *, check_epoch=True):
        self._check_validator()
        meta = conn.execute("SELECT * FROM meta WHERE singleton=1").fetchone()
        anchor = conn.execute("SELECT * FROM fence.anchor WHERE singleton=1").fetchone()
        if (not meta or not anchor or meta["schema_version"] != 1
                or meta["authority_id"] != anchor["authority_id"]
                or meta["epoch"] != anchor["epoch"] or meta["revision"] != anchor["revision"]):
            raise DurableError("restore_quarantined")
        if meta["config_pin"] != self.config_pin:
            raise DurableError("configuration_mismatch")
        if check_epoch and (self.epoch is None or self.epoch != anchor["epoch"]):
            raise DurableError("controller_fenced")
        return meta

    @contextmanager
    def _transaction(self, *, check_epoch=True):
        conn = self._connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._check(conn, check_epoch=check_epoch)
            initial = conn.total_changes
            yield conn
            if conn.total_changes != initial:
                conn.execute("UPDATE meta SET revision=revision+1 WHERE singleton=1")
                conn.execute("UPDATE fence.anchor SET revision=revision+1 WHERE singleton=1")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def activate(self):
        """Supervisor cutover; prior controller handles and unclaimed tickets fence."""
        with self._transaction(check_epoch=False) as conn:
            current = self._check(conn, check_epoch=False)["epoch"] + 1
            conn.execute("UPDATE meta SET epoch=? WHERE singleton=1", (current,))
            conn.execute("UPDATE fence.anchor SET epoch=? WHERE singleton=1", (current,))
        self.epoch = current
        return self

    def reopen(self):
        self._check_validator()
        return type(self)(self.path, self.contract, self.validator, prices=self.prices,
                          budget_microusd=self.budget_microusd, clock=self.clock, epoch=self.epoch)

    def _now(self):
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise DurableError("clock_unavailable")
        return now

    def _audit(self, conn, run, event, ticket=None):
        conn.execute("INSERT INTO audit(root_id,run_id,ticket,event,at) VALUES(?,?,?,?,?)",
                     (run["root_id"], run["run_id"], ticket, event, self._now()))

    def _run(self, conn, token):
        if not isinstance(token, str):
            raise DurableError("unknown_credential")
        row = conn.execute("SELECT r.* FROM tokens t JOIN runs r USING(run_id) WHERE t.token=?",
                           (token,)).fetchone()
        if row is None:
            raise DurableError("unknown_credential")
        return row

    def _lineage(self, conn, run):
        result = [run]
        while result[-1]["parent_id"] is not None:
            parent = conn.execute("SELECT * FROM runs WHERE run_id=?", (result[-1]["parent_id"],)).fetchone()
            if parent is None:
                raise DurableError("lineage_integrity_failure")
            result.append(parent)
        return result

    def _scope(self, conn, run):
        lineage = self._lineage(conn, run)
        caps = _caps(run["capabilities"])
        for ancestor in lineage:
            caps &= _caps(ancestor["capabilities"])
        epoch = _json([(r["run_id"], r["generation"], json.loads(r["binding"])["session"])
                       for r in lineage])
        return caps, min(r["deadline"] for r in lineage), epoch

    def _deny(self, conn, run, reason, ticket=None):
        conn.execute("UPDATE roots SET stopped=1 WHERE root_id=?", (run["root_id"],))
        self._audit(conn, run, reason, ticket)
        return DurableResult("denied", reason, ticket)

    def _live(self, conn, run, token=None):
        if token is not None and run["token"] != token:
            return self._deny(conn, run, "binding_mismatch")
        current_ancestors = [(r["run_id"], r["token"]) for r in self._lineage(conn, run)[1:]]
        if run["ancestry"] != _json(current_ancestors):
            return self._deny(conn, run, "ancestor_binding_mismatch")
        root = conn.execute("SELECT * FROM roots WHERE root_id=?", (run["root_id"],)).fetchone()
        if root["stopped"]:
            return DurableResult("denied", "root_stopped")
        if self._now() >= self._scope(conn, run)[1]:
            return self._deny(conn, run, "expired")
        return None

    def _bounded_json(self, value):
        encoded = _json(value)
        if len(encoded.encode()) > self.contract.limits.input_bytes:
            raise DurableError("input_limit")
        return encoded

    def admit(self, binding: Binding, context, *, capabilities=None):
        if (binding.tenant, binding.principal) not in self.contract.allowed_principals:
            raise DurableError("unapproved_principal")
        caps = self.contract.capabilities if capabilities is None else frozenset(capabilities)
        if not caps <= self.contract.capabilities:
            raise DurableError("scope_widening")
        if not isinstance(context, Mapping):
            raise DurableError("context_invalid")
        context_json = self._bounded_json(context)
        with self._transaction() as conn:
            rid, token = secrets.token_hex(16), secrets.token_urlsafe(32)
            conn.execute("INSERT INTO roots(root_id,budget_microusd,call_limit) VALUES(?,?,?)",
                         (rid, self.budget_microusd, self.contract.limits.budget_calls))
            conn.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,0,?)",
                         (rid, rid, None, token, _json(binding), _json(caps), context_json,
                          self._now() + self.contract.limits.runtime_seconds, 0, "[]"))
            conn.execute("INSERT INTO tokens VALUES(?,?)", (token, rid))
            self._audit(conn, self._run(conn, token), "admitted")
        return token

    def delegate(self, token, binding: Binding, capabilities, context, *, runtime_seconds=None):
        result = None
        with self._transaction() as conn:
            parent = self._run(conn, token)
            blocked = self._live(conn, parent, token)
            caps = frozenset(capabilities)
            permitted, deadline, _ = self._scope(conn, parent)
            old = json.loads(parent["context"])
            if blocked:
                result = blocked
            elif (binding.tenant != json.loads(parent["binding"])["tenant"]
                  or (binding.tenant, binding.principal) not in self.contract.allowed_principals
                  or not caps <= permitted or not isinstance(context, Mapping)
                  or not set(context) <= self.contract.delegable_context_fields
                  or any(k not in old or _json(v) != _json(old[k]) for k, v in context.items())):
                result = self._deny(conn, parent, "delegation_widening")
            else:
                root = conn.execute("SELECT * FROM roots WHERE root_id=?", (parent["root_id"],)).fetchone()
                if (root["children"] >= self.contract.limits.max_children
                        or parent["depth"] >= self.contract.limits.max_depth):
                    result = DurableResult("held", "child_limit")
                elif any(k not in context or context[k] is None for cap in caps
                         for k in self.contract.required_context[cap.step]):
                    result = DurableResult("held", "missing_context")
                elif self._has_uncertain(conn, parent["root_id"]):
                    result = DurableResult("held", "operation_unknown")
                else:
                    if runtime_seconds is not None:
                        if type(runtime_seconds) not in (int, float) or not math.isfinite(runtime_seconds) or runtime_seconds <= 0:
                            raise DurableError("invalid_child_deadline")
                        deadline = min(deadline, self._now() + runtime_seconds)
                    rid, child = secrets.token_hex(16), secrets.token_urlsafe(32)
                    ancestry = _json([(r["run_id"], r["token"]) for r in self._lineage(conn, parent)])
                    conn.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,0,?)",
                                 (rid, parent["root_id"], parent["run_id"], child, _json(binding),
                                  _json(caps), self._bounded_json(context), deadline,
                                  parent["depth"] + 1, ancestry))
                    conn.execute("INSERT INTO tokens VALUES(?,?)", (child, rid))
                    conn.execute("UPDATE roots SET children=children+1 WHERE root_id=?", (parent["root_id"],))
                    self._audit(conn, parent, "delegated")
        if result:
            raise DurableError(result.reason)
        return child

    def _fingerprint(self, run, attempt):
        return _digest({"run": run["run_id"], "contract": self.config_pin, "attempt": attempt})

    def _has_uncertain(self, conn, root_id):
        return conn.execute("SELECT 1 FROM operations WHERE root_id=? AND status IN ('dispatched','unknown') LIMIT 1",
                            (root_id,)).fetchone() is not None

    def _totals(self, conn, root_id):
        row = conn.execute("""SELECT count(*) calls,
          COALESCE(sum(CASE WHEN status IN ('settled','overrun') THEN actual_cost ELSE 0 END),0) settled,
          COALESCE(sum(CASE WHEN status NOT IN ('settled','overrun') THEN max_cost ELSE 0 END),0) reserved
          FROM operations WHERE root_id=?""", (root_id,)).fetchone()
        return row["calls"], row["settled"], row["reserved"]

    def _validate(self, conn, run, attempt, *, replay=False):
        if not isinstance(attempt, Attempt):
            return self._deny(conn, run, "malformed_attempt")
        if attempt.action in self.contract.handoff_actions:
            return self._deny(conn, run, "durable_handoff_not_enabled")
        if Capability(attempt.step, attempt.action, attempt.resource, attempt.recipient) not in self._scope(conn, run)[0]:
            return self._deny(conn, run, "outside_scope")
        context = json.loads(run["context"])
        if any(k not in context or context[k] is None for k in self.contract.required_context[attempt.step]):
            return DurableResult("held", "missing_context")
        expected = set(self.contract.payload_fields[attempt.action])
        if set(attempt.payload) - expected:
            return self._deny(conn, run, "unexpected_payload_fields")
        if expected - set(attempt.payload):
            return DurableResult("held", "missing_payload_fields")
        if len((_json(attempt.payload) + run["context"]).encode()) > self.contract.limits.input_bytes:
            return DurableResult("held", "input_limit")
        if not replay:
            completed = {json.loads(r[0])["step"] for r in conn.execute(
                "SELECT attempt FROM operations WHERE root_id=? AND status='settled'", (run["root_id"],))}
            if not set(self.dependencies[attempt.step]) <= completed:
                return self._deny(conn, run, "step_out_of_order")
            pending = [step for step in completed if step != attempt.step]
            while pending:
                step = pending.pop()
                if attempt.step in self.dependencies[step]:
                    return self._deny(conn, run, "step_out_of_order")
                pending.extend(self.dependencies[step])
        return None

    def _preflight(self, token=None, attempt=None, *, ticket=None, allowed_recipients=None,
                   allowed_actions=None):
        """Capture checked immutable inputs; run callbacks after releasing storage."""
        with self._transaction() as conn:
            if ticket is None:
                run = self._run(conn, token)
                previous = conn.execute("SELECT * FROM operations WHERE root_id=? AND operation_id=?",
                                        (run["root_id"], attempt.operation_id if isinstance(attempt, Attempt) else "")).fetchone()
            else:
                previous = conn.execute("SELECT * FROM operations WHERE ticket=?", (ticket,)).fetchone()
                if previous is None:
                    return DurableResult("denied", "unknown_ticket")
                run = conn.execute("SELECT * FROM runs WHERE run_id=?", (previous["run_id"],)).fetchone()
                attempt = Attempt(**json.loads(previous["attempt"]))
                if allowed_actions is not None and attempt.action not in allowed_actions:
                    return self._deny(conn, run, "receiver_action_mismatch", ticket)
                if allowed_recipients is not None and attempt.recipient not in allowed_recipients:
                    return self._deny(conn, run, "receiver_scope_mismatch", ticket)
            blocked = self._live(conn, run, token)
            if blocked:
                return blocked
            checked = self._validate(conn, run, attempt, replay=ticket is None and bool(previous))
            if checked:
                return checked
            if previous and previous["fingerprint"] != self._fingerprint(run, attempt):
                return self._deny(conn, run, "operation_conflict", previous["ticket"])
            context = _freeze(json.loads(run["context"]))
            revision = self._check(conn)["revision"]
        try:
            outcome = self.validator(Attempt(**json.loads(_json(attempt))), context)
        except Exception:
            outcome = ValidationOutcome.deny("validator_unavailable")
        if not isinstance(outcome, ValidationOutcome) or not outcome.valid():
            outcome = ValidationOutcome.deny("validator_result_invalid")
        return revision, outcome

    def _apply_validation(self, conn, run, prepared):
        revision, outcome = prepared
        if outcome.status == "deny":
            return self._deny(conn, run, outcome.reason)
        if self._check(conn)["revision"] != revision:
            return DurableResult("held", "authority_changed_retry")
        if outcome.status == "hold":
            return DurableResult("held", outcome.reason)
        return None

    def issue_approval(self, token, attempt):
        approval_id = secrets.token_urlsafe(32)
        with self._transaction() as conn:
            run = self._run(conn, token)
            blocked = self._live(conn, run, token)
            if blocked:
                raise DurableError(blocked.reason)
            conn.execute("INSERT INTO approvals VALUES(?,?,?,?,0)",
                         (approval_id, self._fingerprint(run, attempt), self._scope(conn, run)[2], self.epoch))
            self._audit(conn, run, "approval_issued")
        return approval_id

    def reserve(self, token, attempt, *, approval_id=None):
        try:
            prepared = self._preflight(token, attempt)
            if isinstance(prepared, DurableResult):
                return prepared
            with self._transaction() as conn:
                run = self._run(conn, token)
                blocked = self._live(conn, run, token)
                if blocked:
                    return blocked
                validation = self._apply_validation(conn, run, prepared)
                if validation:
                    return validation
                if not isinstance(attempt, Attempt):
                    return self._deny(conn, run, "malformed_attempt")
                fingerprint = self._fingerprint(run, attempt)
                old = conn.execute("SELECT * FROM operations WHERE root_id=? AND operation_id=?",
                                   (run["root_id"], attempt.operation_id)).fetchone()
                if old and old["fingerprint"] != fingerprint:
                    return self._deny(conn, run, "operation_conflict", old["ticket"])
                checked = self._validate(conn, run, attempt, replay=bool(old))
                if checked:
                    return checked
                if old:
                    if old["status"] == "settled":
                        if old["epoch"] != self.epoch or old["lineage"] != self._scope(conn, run)[2]:
                            return DurableResult("denied", "stale_result_binding", old["ticket"])
                        return DurableResult("allowed", "replay", old["ticket"], _freeze(json.loads(old["receipt"])), True)
                    if old["status"] == "reserved" and old["epoch"] == self.epoch:
                        return DurableResult("reserved", "reservation_replay", old["ticket"], replayed=True)
                    return DurableResult("held", "operation_unknown", old["ticket"])
                if self._has_uncertain(conn, run["root_id"]):
                    return DurableResult("held", "operation_unknown")
                lineage = self._scope(conn, run)[2]
                if attempt.action in self.contract.exact_approval_actions:
                    if approval_id is None:
                        return DurableResult("held", "approval_required")
                    approval = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
                    if (not approval or approval["consumed"] or approval["epoch"] != self.epoch
                            or approval["fingerprint"] != fingerprint or approval["lineage"] != lineage):
                        return self._deny(conn, run, "invalid_approval")
                calls, settled, reserved = self._totals(conn, run["root_id"])
                root = conn.execute("SELECT * FROM roots WHERE root_id=?", (run["root_id"],)).fetchone()
                maximum = self.prices[attempt.action]
                if calls >= root["call_limit"] or settled + reserved + maximum > root["budget_microusd"]:
                    return DurableResult("held", "budget_exhausted")
                ticket = secrets.token_urlsafe(32)
                conn.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,'reserved',?,NULL,NULL,?,?,?)",
                             (ticket, run["root_id"], run["run_id"], attempt.operation_id, fingerprint,
                              _json(attempt), maximum, self.epoch, lineage, approval_id))
                if attempt.action in self.contract.exact_approval_actions:
                    conn.execute("UPDATE approvals SET consumed=1 WHERE approval_id=?", (approval_id,))
                self._audit(conn, run, "reserved", ticket)
                return DurableResult("reserved", "reserved", ticket)
        except (DurableError, sqlite3.Error) as exc:
            return DurableResult("denied", str(exc) if isinstance(exc, DurableError) else "storage_unavailable")

    def claim(self, ticket, *, allowed_recipients=None, allowed_actions=None):
        """Claim under current authority and the trusted endpoint's action/recipient scope."""
        try:
            prepared = self._preflight(ticket=ticket, allowed_recipients=allowed_recipients,
                                       allowed_actions=allowed_actions)
            if isinstance(prepared, DurableResult):
                return prepared
            with self._transaction() as conn:
                operation = conn.execute("SELECT * FROM operations WHERE ticket=?", (ticket,)).fetchone()
                if operation is None:
                    return DurableResult("denied", "unknown_ticket")
                run = conn.execute("SELECT * FROM runs WHERE run_id=?", (operation["run_id"],)).fetchone()
                blocked = self._live(conn, run)
                if blocked:
                    return blocked
                validation = self._apply_validation(conn, run, prepared)
                if validation:
                    return validation
                if operation["epoch"] != self.epoch:
                    return DurableResult("denied", "ticket_fenced", ticket)
                if operation["status"] != "reserved":
                    return DurableResult("held", "already_claimed", ticket)
                if self._has_uncertain(conn, run["root_id"]):
                    return DurableResult("held", "operation_unknown", ticket)
                if operation["lineage"] != self._scope(conn, run)[2]:
                    return self._deny(conn, run, "stale_grant", ticket)
                attempt = Attempt(**json.loads(operation["attempt"]))
                if allowed_actions is not None and attempt.action not in allowed_actions:
                    return self._deny(conn, run, "receiver_action_mismatch", ticket)
                if allowed_recipients is not None and attempt.recipient not in allowed_recipients:
                    return self._deny(conn, run, "receiver_scope_mismatch", ticket)
                checked = self._validate(conn, run, attempt)
                if checked:
                    return checked
                if operation["approval_id"]:
                    approval = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (operation["approval_id"],)).fetchone()
                    if (not approval or not approval["consumed"] or approval["epoch"] != self.epoch
                            or approval["fingerprint"] != operation["fingerprint"]
                            or approval["lineage"] != operation["lineage"]):
                        return self._deny(conn, run, "invalid_approval", ticket)
                conn.execute("UPDATE operations SET status='dispatched' WHERE ticket=?", (ticket,))
                self._audit(conn, run, "dispatch_authorized", ticket)
                return DurableResult("allowed", "dispatch_authorized", ticket,
                                     dispatch=Dispatch(ticket, run["root_id"], run["run_id"], attempt,
                                                       operation["max_cost"], self.epoch))
        except (DurableError, sqlite3.Error) as exc:
            return DurableResult("denied", str(exc) if isinstance(exc, DurableError) else "storage_unavailable")

    def settle(self, ticket, receipt, actual_microusd):
        try:
            receipt_json = self._bounded_json(receipt)
            with self._transaction() as conn:
                op = conn.execute("SELECT * FROM operations WHERE ticket=?", (ticket,)).fetchone()
                if op is None:
                    return DurableResult("denied", "unknown_ticket")
                run = conn.execute("SELECT * FROM runs WHERE run_id=?", (op["run_id"],)).fetchone()
                if type(actual_microusd) is not int or actual_microusd < 0:
                    return self._deny(conn, run, "settlement_invalid", ticket)
                if op["status"] in ("settled", "overrun"):
                    if op["receipt"] == receipt_json and op["actual_cost"] == actual_microusd:
                        if op["status"] == "overrun":
                            return DurableResult("denied", "settlement_overrun", ticket, replayed=True)
                        return DurableResult("allowed", "settlement_replay", ticket,
                                             _freeze(json.loads(receipt_json)), True)
                    return self._deny(conn, run, "settlement_conflict", ticket)
                if op["status"] not in ("dispatched", "unknown"):
                    return self._deny(conn, run, "not_dispatched", ticket)
                if actual_microusd > op["max_cost"]:
                    conn.execute("UPDATE operations SET status='overrun',receipt=?,actual_cost=? WHERE ticket=?",
                                 (receipt_json, actual_microusd, ticket))
                    return self._deny(conn, run, "settlement_overrun", ticket)
                conn.execute("UPDATE operations SET status='settled',receipt=?,actual_cost=? WHERE ticket=?",
                             (receipt_json, actual_microusd, ticket))
                self._audit(conn, run, "settled", ticket)
                return DurableResult("allowed", "settled", ticket, _freeze(json.loads(receipt_json)))
        except (DurableError, ValueError, sqlite3.Error) as exc:
            return DurableResult("denied", str(exc) if isinstance(exc, DurableError) else "settlement_invalid")

    def mark_unknown(self, ticket):
        with self._transaction() as conn:
            op = conn.execute("SELECT * FROM operations WHERE ticket=?", (ticket,)).fetchone()
            if op is None or op["status"] not in ("dispatched", "unknown"):
                raise DurableError("not_dispatched")
            conn.execute("UPDATE operations SET status='unknown' WHERE ticket=?", (ticket,))
            run = conn.execute("SELECT * FROM runs WHERE run_id=?", (op["run_id"],)).fetchone()
            self._audit(conn, run, "outcome_unknown", ticket)
        return DurableResult("held", "operation_unknown", ticket)

    def release_result(self, ticket, *, allowed_recipients=None, allowed_actions=None):
        """Authorize receipt release under current authority and endpoint scope.

        Trusted settlement remains separate; an endpoint may record an old effect
        without being allowed to disclose its receipt or handle its action family.
        """
        try:
            with self._transaction() as conn:
                op = conn.execute("SELECT * FROM operations WHERE ticket=?", (ticket,)).fetchone()
                if op is None:
                    return DurableResult("denied", "unknown_ticket")
                run = conn.execute("SELECT * FROM runs WHERE run_id=?", (op["run_id"],)).fetchone()
                blocked = self._live(conn, run)
                if blocked:
                    return blocked
                attempt = Attempt(**json.loads(op["attempt"]))
                if allowed_actions is not None and attempt.action not in allowed_actions:
                    return self._deny(conn, run, "receiver_action_mismatch", ticket)
                if allowed_recipients is not None and attempt.recipient not in allowed_recipients:
                    return self._deny(conn, run, "receiver_scope_mismatch", ticket)
                if op["epoch"] != self.epoch or op["lineage"] != self._scope(conn, run)[2]:
                    return DurableResult("denied", "stale_result_binding", ticket)
                if op["status"] != "settled":
                    return DurableResult("held", "result_unsettled", ticket)
                checked = self._validate(conn, run, attempt, replay=True)
                if checked:
                    return checked
                return DurableResult("allowed", "result_released", ticket,
                                     _freeze(json.loads(op["receipt"])))
        except (DurableError, sqlite3.Error) as exc:
            return DurableResult("denied", str(exc) if isinstance(exc, DurableError) else "storage_unavailable")

    def deny_ticket(self, ticket, reason):
        """Trusted endpoint rejection bound only to a genuine issued ticket.

        An unknown ticket cannot select a root to Stop. A known ticket fences
        its stored root without claiming the operation, invoking a receiver,
        releasing a receipt, or changing its existing budget reservation.
        ``reason`` is a trusted safe code, never caller-provided request text.
        """
        ValidationOutcome.deny(reason)
        if type(ticket) is not str:
            return DurableResult("denied", "unknown_ticket")
        try:
            with self._transaction() as conn:
                op = conn.execute("SELECT run_id FROM operations WHERE ticket=?", (ticket,)).fetchone()
                if op is None:
                    return DurableResult("denied", "unknown_ticket")
                run = conn.execute("SELECT * FROM runs WHERE run_id=?", (op["run_id"],)).fetchone()
                if run is None:
                    raise DurableError("operation_binding_missing")
                return self._deny(conn, run, reason, ticket)
        except (DurableError, sqlite3.Error) as exc:
            return DurableResult("denied", str(exc) if isinstance(exc, DurableError) else "storage_unavailable")

    def stop_root(self, token, reason="operator_stop"):
        with self._transaction() as conn:
            run = self._run(conn, token)
            conn.execute("UPDATE roots SET stopped=1 WHERE root_id=?", (run["root_id"],))
            self._audit(conn, run, "operator_stop")

    def narrow_permissions(self, token, capabilities):
        caps = frozenset(capabilities)
        with self._transaction() as conn:
            run = self._run(conn, token)
            if not caps <= _caps(run["capabilities"]):
                raise DurableError("scope_widening")
            conn.execute("UPDATE runs SET capabilities=?,generation=generation+1 WHERE run_id=?",
                         (_json(caps), run["run_id"]))
            self._audit(conn, run, "permissions_narrowed")

    def rotate_session(self, token, new_session):
        with self._transaction() as conn:
            run = self._run(conn, token)
            binding = json.loads(run["binding"])
            binding["session"] = new_session
            checked = Binding(**binding)
            new_token = secrets.token_urlsafe(32)
            conn.execute("UPDATE runs SET token=?,binding=?,generation=generation+1 WHERE run_id=?",
                         (new_token, _json(checked), run["run_id"]))
            conn.execute("INSERT INTO tokens VALUES(?,?)", (new_token, run["run_id"]))
            self._audit(conn, run, "session_rotated")
        return new_token

    def snapshot(self, token):
        with self._transaction() as conn:
            run = self._run(conn, token)
            root = conn.execute("SELECT * FROM roots WHERE root_id=?", (run["root_id"],)).fetchone()
            calls, settled, reserved = self._totals(conn, run["root_id"])
            caps, deadline, _ = self._scope(conn, run)
            unknown = tuple(r[0] for r in conn.execute(
                "SELECT operation_id FROM operations WHERE root_id=? AND status IN ('dispatched','unknown') ORDER BY operation_id",
                (run["root_id"],)))
            return DurableSnapshot(run["root_id"], run["run_id"], bool(root["stopped"]),
                                   run["generation"], deadline, root["children"], calls,
                                   root["budget_microusd"], reserved, settled, reserved + settled,
                                   unknown, caps, _freeze(json.loads(run["context"])), self.contract.purpose)
