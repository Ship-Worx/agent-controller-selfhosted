"""Local authenticated broker. Shared-UID development is not an OS sandbox.

Only this trusted service owns authority, receiver effects and operator credentials.
HTTP workers propose actions; they never receive a raw protected-tool callback.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
from functools import wraps
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qs, urlparse

from controller.durable import DurableAuthority, DurableError
from controller.engine import Attempt, Capability
from workflows.definitions import PRICES, WORKFLOWS


def plain(value):
    from collections.abc import Mapping
    if isinstance(value, Mapping):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, frozenset, set)):
        return [plain(item) for item in value]
    return value


def encoded(value):
    return json.dumps(plain(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result
    def nonfinite(_value):
        raise ValueError("nonfinite_number")
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    if type(value) is not dict:
        raise ValueError("object_required")
    return value


def fields(value, required=(), optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or set(value) - set(required) - set(optional):
        raise ValueError("invalid_fields")


def owned(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._operation():
            return method(self, *args, **kwargs)
    return call


class Broker:
    def __init__(self, state_dir, admin_token, *, live_model=None, startup_check=None,
                 live_model_factory=None):
        if type(admin_token) is not str or len(admin_token) < 24:
            raise ValueError("CONTROLLER_ADMIN_TOKEN needs at least 24 characters")
        if live_model is not None and live_model_factory is not None:
            raise ValueError("ambiguous_live_model_setup")
        self.admin_token = admin_token
        self.live_model = live_model
        self.state_dir = Path(state_dir).resolve()
        if startup_check is None:
            self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = self.state_dir / "broker.sqlite"
        self._lifecycle = threading.Condition()
        self._depth = threading.local()
        self._users = 0
        self._closing = False
        self._owner_pid = os.getpid()
        self.controller_instance_id = secrets.token_hex(16)
        self._owner_file = None
        # Keep this inode for the lifetime of the state directory. Unlinking it
        # would let another process lock a different file for the same state.
        owner_path = self.state_dir / ".broker.lock"
        if startup_check is None:
            owner_file = owner_path.open("a+b")
        else:
            # Guarded deployment startup never bootstraps an absent lock or
            # follows a symlink. Mount verification must precede construction.
            owner_file = os.fdopen(os.open(owner_path, os.O_RDWR | os.O_NOFOLLOW), "r+b")
        try:
            fcntl.flock(owner_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            owner_file.close()
            raise DurableError("state_directory_in_use") from None
        except BaseException:
            owner_file.close()
            raise
        self._owner_file = owner_file
        try:
            if startup_check is not None:
                startup_check(owner_file)
            if live_model_factory is not None:
                self.live_model = live_model_factory()
            self._initialize()
        except BaseException:
            self.close()
            raise

    def _initialize(self):
        # Ownership precedes schema changes, epoch advancement and recovery.
        if not self.db.exists() and any(self.state_dir.glob("*.sqlite")):
            raise ValueError("registry_missing_for_existing_authority")
        self.lock = threading.RLock()
        self.authorities = {}
        self.gates = {}
        self.active = {}
        with self.connect() as conn:
            conn.executescript("""
              CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY,workflow TEXT NOT NULL,
                budget INTEGER NOT NULL,runtime REAL NOT NULL,epoch INTEGER NOT NULL,
                root_token TEXT NOT NULL,root_id TEXT NOT NULL,final_outcome TEXT);
              CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,job_id TEXT NOT NULL,
                run_id TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS effects(ticket TEXT PRIMARY KEY,job_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,action TEXT NOT NULL,receipt TEXT NOT NULL,cost INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS trace(event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,run_id TEXT NOT NULL,at REAL NOT NULL,event TEXT NOT NULL,data TEXT NOT NULL);
            """)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(jobs)")}
            if "live_enabled" not in columns:
                conn.execute("ALTER TABLE jobs ADD COLUMN live_enabled INTEGER NOT NULL DEFAULT 0")
                conn.execute("ALTER TABLE jobs ADD COLUMN pricing_pin TEXT")
            jobs = conn.execute("SELECT * FROM jobs").fetchall()
        for job in jobs:
            authority = self.authority(job)
            authority.activate()
            with self.connect() as conn:
                conn.execute("UPDATE jobs SET epoch=? WHERE job_id=?", (authority.epoch, job["job_id"]))
            self.record(job, job["root_id"], "service_restarted", reason="previous_epoch_fenced")
            # A committed synthetic receipt can reconcile both an interrupted
            # dispatch and a later unknown hold. No effects are replayed.
            with authority._transaction() as conn:
                pending = conn.execute("SELECT ticket,status FROM operations WHERE status IN ('dispatched','unknown')").fetchall()
            for pending_op in pending:
                with self.connect() as conn:
                    effect = conn.execute("SELECT * FROM effects WHERE ticket=?", (pending_op["ticket"],)).fetchone()
                if effect:
                    authority.settle(pending_op["ticket"], json.loads(effect["receipt"]), effect["cost"])
                elif pending_op["status"] == "dispatched":
                    authority.mark_unknown(pending_op["ticket"])

    @contextmanager
    def _operation(self):
        # Count operations without serializing them: Stop must remain usable
        # while an effect is in flight. Nested calls may finish during close.
        with self._lifecycle:
            depth = getattr(self._depth, "value", 0)
            if (self._owner_file is None or self._owner_pid != os.getpid()
                    or (self._closing and not depth)):
                raise DurableError("broker_closed")
            self._users += 1
            self._depth.value = depth + 1
        try:
            yield
        finally:
            with self._lifecycle:
                self._depth.value -= 1
                self._users -= 1
                self._lifecycle.notify_all()

    def close(self):
        with self._lifecycle:
            if self._owner_file is None:
                return
            if self._owner_pid != os.getpid():
                # Closing a fork's descriptor must not explicitly unlock the
                # original process's shared open-file description.
                self._owner_file.close()
                self._owner_file = None
                return
            if getattr(self._depth, "value", 0):
                raise DurableError("broker_operation_in_progress")
            self._closing = True
            while self._users:
                self._lifecycle.wait()
            if self._owner_file is not None:
                self._owner_file.close()
                self._owner_file = None

    def __enter__(self):
        with self._operation():
            return self

    def __exit__(self, *_exc):
        self.close()

    @contextmanager
    def connect(self):
        with self._operation(), self._connect() as conn:
            yield conn

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=FULL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @owned
    def authority(self, job):
        with self.lock:
            if job["job_id"] not in self.authorities:
                workflow = WORKFLOWS[job["workflow"]]
                live = bool(job["live_enabled"])
                if live and (self.live_model is None or job["pricing_pin"] != self.live_model.prices.pin):
                    raise ValueError("live_model_configuration_required")
                contract = workflow.contract(job["runtime"], live_model=live)
                prices = {**PRICES, **({"model.respond": self.live_model.max_cost_microusd} if live else {})}
                self.authorities[job["job_id"]] = DurableAuthority(
                    self.state_dir / (job["job_id"] + ".sqlite"), contract,
                    workflow.validator(contract, pricing_pin=job["pricing_pin"]), prices=prices,
                    budget_microusd=job["budget"], epoch=job["epoch"])
            return self.authorities[job["job_id"]]

    @owned
    def job(self, job_id):
        if type(job_id) is not str:
            raise ValueError("invalid_job_id")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise ValueError("unknown_job")
        return row

    def gate(self, job):
        # Serialize terminal job metadata with admission/claim. Never hold this
        # across a protected effect, delay, provider call or worker callback.
        with self.lock:
            return self.gates.setdefault(job["job_id"], threading.RLock())

    @owned
    def authenticate(self, token):
        if type(token) is not str or not 1 <= len(token) <= 512:
            raise PermissionError("unauthorized")
        if secrets.compare_digest(token, self.admin_token):
            return None
        with self.connect() as conn:
            session = conn.execute("SELECT * FROM sessions WHERE token_hash=?", (digest(token),)).fetchone()
        if session is None:
            raise PermissionError("unauthorized")
        job = self.job(session["job_id"])
        authority = self.authority(job)
        with authority._transaction() as conn:
            run = authority._run(conn, token)
            if run["token"] != token or run["run_id"] != session["run_id"]:
                raise PermissionError("unauthorized")
        return job, session["run_id"]

    @owned
    def observation_context(self, job, run_id):
        """Non-secret correlation metadata; never an execution capability."""
        authority = self.authority(job)
        return {"run_id_hash": digest(run_id), "config_pin": authority.config_pin,
                "policy_pin": authority.validator.policy_pin, "authority_epoch": authority.epoch,
                "controller_instance_id": self.controller_instance_id}

    @owned
    def record(self, job, run_id, event, **data):
        # Callers supply safe codes, trusted workflow names, hashes and numbers.
        # Never serialize raw requests, bearer tokens, tickets, payloads or receipts.
        with self.connect() as conn:
            conn.execute("INSERT INTO trace(job_id,run_id,at,event,data) VALUES(?,?,?,?,?)",
                         (job["job_id"], run_id, time.time(), event,
                          encoded({**data, "schema_version": 1, "source": "controller",
                                   **self.observation_context(job, run_id)})))

    @owned
    def create(self, body):
        fields(body, ("workflow",), ("budget_microusd", "runtime_seconds", "live_model"))
        workflow = WORKFLOWS.get(body["workflow"])
        live = body.get("live_model", False)
        if type(live) is not bool or (live and self.live_model is None):
            raise ValueError("live_model_configuration_required")
        pin = self.live_model.prices.pin if live else None
        prices = {**PRICES, **({"model.respond": self.live_model.max_cost_microusd} if live else {})}
        budget, runtime = body.get("budget_microusd", 30), body.get("runtime_seconds", 60)
        if workflow is None or type(budget) is not int or not 0 <= budget <= 1_000_000:
            raise ValueError("invalid_job")
        if type(runtime) not in (int, float) or not 0 < runtime <= 3600:
            raise ValueError("invalid_runtime")
        runtime = float(runtime)  # SQLite REAL restores float; keep the config pin stable.
        job_id = secrets.token_hex(16)
        contract = workflow.contract(runtime, live_model=live)
        authority = DurableAuthority(self.state_dir / (job_id + ".sqlite"), contract,
                                     workflow.validator(contract, pricing_pin=pin), prices=prices,
                                     budget_microusd=budget).activate()
        token = authority.admit(workflow.binding(), workflow.context)
        snapshot = authority.snapshot(token)
        with self.connect() as conn:
            conn.execute("INSERT INTO jobs(job_id,workflow,budget,runtime,epoch,root_token,root_id,"
                         "final_outcome,live_enabled,pricing_pin) VALUES(?,?,?,?,?,?,?,NULL,?,?)",
                         (job_id, workflow.name, budget, runtime, authority.epoch, token, snapshot.root_id,
                          int(live), pin))
            conn.execute("INSERT INTO sessions VALUES(?,?,?)", (digest(token), job_id, snapshot.run_id))
        with self.lock:
            self.authorities[job_id] = authority
        job = self.job(job_id)
        self.record(job, snapshot.run_id, "job_created", workflow=workflow.name,
                    budget_microusd=budget, expires_at=snapshot.deadline)
        return {**self.snapshot(job, token), "token": token,
                "completion_criteria": workflow.completion_criteria}

    @owned
    def snapshot(self, job, token):
        snap = self.authority(job).snapshot(token)
        with self.lock:
            active = [value[1] for value in self.active.values() if value[0] == job["job_id"]]
        with self.connect() as conn:
            effects = conn.execute("SELECT operation_id,action,receipt,cost FROM effects WHERE job_id=?", (job["job_id"],)).fetchall()
        effects = [row for row in effects if not json.loads(row["receipt"]).get("cancelled", False)]
        return {"job_id": job["job_id"], "root_id": snap.root_id, "run_id": snap.run_id,
                **self.observation_context(job, snap.run_id),
                "workflow": job["workflow"], "purpose": snap.purpose, "stopped": snap.stopped,
                "live_model": bool(job["live_enabled"]),
                "context": plain(snap.context), "capabilities": [asdict(cap) for cap in sorted(snap.capabilities)],
                "deadline": snap.deadline, "calls_used": snap.calls_used,
                "children": snap.children,
                "budget_microusd": snap.budget_microusd, "settled_microusd": snap.settled_microusd,
                "reserved_microusd": snap.reserved_microusd, "exposure_microusd": snap.exposure_microusd,
                "unknown_operations": [digest(op) for op in snap.unknown_operations],
                "in_flight": active, "final_outcome": self.job(job["job_id"])["final_outcome"],
                "effects_count": len(effects), "effects": [
                    {"operation_id_hash": digest(row["operation_id"]), "action": row["action"],
                     "cost_microusd": row["cost"]} for row in effects]}

    def attempt(self, body):
        fields(body, ("attempt",))
        value = body["attempt"]
        fields(value, ("operation_id", "step", "action", "resource", "recipient", "payload"))
        return Attempt(**value)

    def result(self, result, *, receipt=True):
        value = {"status": result.status, "reason": result.reason, "replayed": result.replayed}
        if result.ticket:
            value["ticket"] = result.ticket
        if receipt and result.receipt is not None:
            value["receipt"] = plain(result.receipt)
        return value

    @owned
    def authorize(self, job, token, run_id, attempt):
        with self.gate(job):
            return self._authorize(job, token, run_id, attempt)

    def _authorize(self, job, token, run_id, attempt):
        authority = self.authority(job)
        trusted_steps = {cap.step for cap in authority.contract.capabilities}
        trusted_actions = set(PRICES)
        operation_hash = digest(attempt.operation_id)
        self.record(job, run_id, "action_proposed", operation_id_hash=operation_hash,
                    step_id=attempt.step if attempt.step in trusted_steps else "unrecognized",
                    action=attempt.action if attempt.action in trusted_actions else "unrecognized",
                    proposal_sha256=digest(encoded({"step": attempt.step, "action": attempt.action,
                        "resource": attempt.resource, "recipient": attempt.recipient,
                        "payload": plain(attempt.payload)})))
        final = self.job(job["job_id"])["final_outcome"]
        if final:
            reason = "root_stopped" if final == "stopped" else "job_complete"
            self.record(job, run_id, "decision", status="denied", reason=reason, operation_id_hash=operation_hash)
            return {"status": "denied", "reason": reason}
        result = authority.reserve(token, attempt)
        # A core replay result must still use the dedicated disclosure gate.
        if result.status == "allowed":
            result = authority.release_result(result.ticket, allowed_actions=frozenset(PRICES),
                                               allowed_recipients={"worker", "internal"})
            value = self.result(result)
            value["replayed"] = True
        else:
            value = self.result(result, receipt=False)
        self.record(job, run_id, "decision", status=value["status"], reason=value["reason"],
                    operation_id_hash=operation_hash)
        return value

    @owned
    def execute(self, job, token, run_id, ticket):
        if type(ticket) is not str or not 1 <= len(ticket) <= 512:
            raise ValueError("invalid_ticket")
        authority = self.authority(job)
        if self.job(job["job_id"])["final_outcome"] == "completed":
            self.record(job, run_id, "decision", status="denied", reason="job_complete")
            return {"status": "denied", "reason": "job_complete"}
        with authority._transaction() as conn:
            op = conn.execute("SELECT * FROM operations WHERE ticket=?", (ticket,)).fetchone()
        if op is None or op["run_id"] != run_id:
            self.record(job, run_id, "decision", status="denied", reason="ticket_binding_mismatch")
            return {"status": "denied", "reason": "ticket_binding_mismatch"}
        scope = {"allowed_actions": frozenset(PRICES), "allowed_recipients": {"worker", "internal"}}
        operation_hash = digest(op["operation_id"])
        with self.connect() as conn:
            old = conn.execute("SELECT * FROM effects WHERE ticket=?", (ticket,)).fetchone()
        if old:
            authority.settle(ticket, json.loads(old["receipt"]), old["cost"])
            result = authority.release_result(ticket, **scope)
            try:
                self.record(job, run_id, "execution_replayed", status=result.status, reason=result.reason,
                            operation_id_hash=operation_hash)
            except Exception:
                # Keep the settled receipt private when replay logging fails.
                return {"status": "held", "reason": "outcome_unknown"}
            value = self.result(result)
            value["replayed"] = True
            return value
        # Register before claim so Stop can cancel even a just-authorized dispatch.
        event = threading.Event()
        with self.lock:
            if ticket in self.active:
                return {"status": "held", "reason": "already_in_flight"}
            self.active[ticket] = (job["job_id"], operation_hash, event)
        claimed, settled = None, None
        try:
            with self.gate(job):
                if self.job(job["job_id"])["final_outcome"] == "completed":
                    self.record(job, run_id, "decision", status="denied", reason="job_complete")
                    return {"status": "denied", "reason": "job_complete"}
                claimed = authority.claim(ticket, **scope)
            if claimed.status != "allowed":
                self.record(job, run_id, "decision", status=claimed.status, reason=claimed.reason,
                            operation_id_hash=operation_hash)
                return self.result(claimed, receipt=False)
            attempt = claimed.dispatch.attempt
            self.record(job, run_id, "tool_started", operation_id_hash=operation_hash,
                        step_id=attempt.step, action=attempt.action, usage={"tokens": None, "microusd": None})
            cancelled = attempt.action == "report.slow" and event.wait(2.0)
            if cancelled:
                receipt, cost = {"cancelled": True, "effect": False}, 0
            elif attempt.action == "record.read":
                receipt = {"record_id": attempt.resource, "data": WORKFLOWS[job["workflow"]].record}
                cost = PRICES[attempt.action]
            else:
                receipt = {"record_id": attempt.resource, "accepted": True,
                           "kind": "synthetic_report", "summary": plain(attempt.payload).get("summary", "slow report")}
                cost = PRICES[attempt.action]
            # The synthetic protected effect IS this durable journal row. Real
            # external systems need destination idempotency and reconciliation.
            with self.connect() as conn:
                conn.execute("INSERT INTO effects VALUES(?,?,?,?,?,?)",
                             (ticket, job["job_id"], attempt.operation_id, attempt.action, encoded(receipt), cost))
            settled = authority.settle(ticket, receipt, cost)
            self.record(job, run_id, "tool_finished", operation_id_hash=operation_hash,
                        reason="cancelled" if cancelled else settled.reason,
                        usage={"tokens": None, "microusd": cost})
            result = authority.release_result(ticket, **scope)
            value = self.result(result)
            if cancelled:
                value["cancellation"] = "acknowledged"
            self.record(job, run_id, "result_release", status=result.status, reason=result.reason,
                        operation_id_hash=operation_hash)
            return value
        except Exception:
            if (claimed is not None and claimed.status == "allowed"
                    and not (settled is not None and settled.status == "allowed")):
                try:
                    authority.mark_unknown(ticket)
                except Exception:
                    pass  # A claimed or settled ticket cannot trigger a new effect.
            try:
                self.record(job, run_id, "tool_error", reason="outcome_unknown", operation_id_hash=operation_hash,
                            usage={"tokens": None, "microusd": None})
            except Exception:
                pass  # Missing diagnostics do not change the durable outcome.
            return {"status": "held", "reason": "outcome_unknown"}
        finally:
            with self.lock:
                self.active.pop(ticket, None)

    @owned
    def model(self, job, token, run_id, body):
        fields(body, ("operation_id", "prompt"))
        if type(body["operation_id"]) is not str:
            raise ValueError("invalid_model_input")
        key = "model:" + digest(run_id + ":" + body["operation_id"])
        with self.gate(job):
            final = self.job(job["job_id"])["final_outcome"]
            if final:
                return {"status": "denied", "reason": "root_stopped" if final == "stopped" else "job_complete"}
            if not job["live_enabled"] or self.live_model is None:
                return {"status": "denied", "reason": "live_model_disabled"}
            with self.lock:
                if key in self.active:
                    return {"status": "held", "reason": "already_in_flight"}
                self.active[key] = (job["job_id"], digest(body["operation_id"]), threading.Event())
        try:
            result = self.live_model.respond(
                self.authority(job), token, body,
                record=lambda event, **data: self.record(job, run_id, event, **data))
            try:
                self.record(job, run_id, "model_decision", status=result["status"], reason=result["reason"],
                            operation_id_hash=digest(body["operation_id"]))
            except Exception:
                # Do not disclose a result when its decision cannot be recorded.
                # Any claimed or settled operation keeps its durable state.
                return {"status": "held", "reason": "model_outcome_unknown", "usage": None}
            return result
        finally:
            with self.lock:
                self.active.pop(key, None)

    @owned
    def delegate(self, job, token, run_id, body):
        with self.gate(job):
            return self._delegate(job, token, run_id, body)

    def _delegate(self, job, token, run_id, body):
        fields(body, ("capabilities", "context_fields"), ("runtime_seconds",))
        if type(body["capabilities"]) is not list or type(body["context_fields"]) is not list:
            raise ValueError("invalid_delegation")
        authority = self.authority(job)
        final = self.job(job["job_id"])["final_outcome"]
        if final:
            reason = "root_stopped" if final == "stopped" else "job_complete"
            self.record(job, run_id, "handoff_denied", reason=reason)
            return {"status": "denied", "reason": reason}
        context = authority.snapshot(token).context
        if any(type(key) is not str or key not in context for key in body["context_fields"]):
            raise ValueError("invalid_context_projection")
        caps = []
        for value in body["capabilities"]:
            fields(value, ("step", "action", "resource", "recipient"))
            caps.append(Capability(**value))
        projected = {key: plain(context[key]) for key in body["context_fields"]}
        try:
            child = authority.delegate(token, WORKFLOWS[job["workflow"]].binding(secrets.token_hex(8)),
                                       caps, projected, runtime_seconds=body.get("runtime_seconds"))
        except DurableError as exc:
            self.record(job, run_id, "handoff_denied", reason=str(exc))
            return {"status": "denied", "reason": str(exc)}
        snapshot = authority.snapshot(child)
        with self.connect() as conn:
            conn.execute("INSERT INTO sessions VALUES(?,?,?)", (digest(child), job["job_id"], snapshot.run_id))
        self.record(job, run_id, "handoff", child_run_id=snapshot.run_id,
                    context_fields=sorted(projected), deadline=snapshot.deadline,
                    budget_policy="shared_root_allocation")
        return {"status": "allowed", **self.snapshot(job, child), "token": child}

    @owned
    def stop(self, job):
        with self.gate(job):
            return self._stop(job)

    def _stop(self, job):
        authority = self.authority(job)
        authority.stop_root(job["root_token"])
        with self.lock:
            pending = [value for value in self.active.values() if value[0] == job["job_id"]]
            uncancellable_models = [value[1] for key, value in self.active.items()
                                    if key.startswith("model:") and value[0] == job["job_id"]]
            for _job_id, _operation, event in pending:
                event.set()
        self.record(job, job["root_id"], "stop", reason="operator_stop",
                    in_flight=[value[1] for value in pending], cancellation="requested",
                    uncancellable_model_calls=uncancellable_models)
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET final_outcome='stopped' WHERE job_id=?", (job["job_id"],))
        return {**self.snapshot(job, job["root_token"]), "cancellation": "requested",
                "already_in_flight": [value[1] for value in pending],
                "uncancellable_model_calls": uncancellable_models}

    @owned
    def complete(self, job, token, run_id):
        with self.gate(job):
            return self._complete(job, token, run_id)

    def _complete(self, job, token, run_id):
        authority = self.authority(job)
        snap = authority.snapshot(token)
        if run_id != snap.root_id:
            return {"status": "denied", "reason": "root_required"}
        if snap.stopped or time.time() >= snap.deadline:
            return {"status": "denied", "reason": "authority_inactive"}
        with self.lock:
            if any(value[0] == job["job_id"] for value in self.active.values()):
                return {"status": "held", "reason": "completion_criteria_unmet"}
        with authority._transaction() as conn:
            actions = {json.loads(row[0])["action"] for row in conn.execute(
                "SELECT attempt FROM operations WHERE root_id=? AND status='settled'", (snap.root_id,))}
            pending = conn.execute("SELECT 1 FROM operations WHERE root_id=? AND status!='settled'", (snap.root_id,)).fetchone()
        if pending or snap.unknown_operations or not {"record.read", "report.write"} <= actions:
            return {"status": "held", "reason": "completion_criteria_unmet"}
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET final_outcome='completed' WHERE job_id=?", (job["job_id"],))
        self.record(job, run_id, "final_outcome", reason="completed")
        return {"status": "allowed", "reason": "completed"}

    @owned
    def trace(self, job, run_id=None):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM trace WHERE job_id=? ORDER BY event_id", (job["job_id"],)).fetchall()
        return {"events": [{"event_id": row["event_id"], "root_id": job["root_id"],
                            "run_id": row["run_id"], "at": row["at"], "event": row["event"],
                            **json.loads(row["data"])} for row in rows if run_id is None or row["run_id"] == run_id]}


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentController/1"

    def log_message(self, *_args):
        pass  # Default access logs can contain caller-controlled URL secrets.

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        broker = self.server.broker
        identity = None
        try:
            self.connection.settimeout(10)
            raw = self.headers.get("Authorization", "")
            if len(self.headers.get_all("Authorization", [])) != 1 or not raw.startswith("Bearer "):
                raise PermissionError("unauthorized")
            token = raw[7:]
            identity = broker.authenticate(token)
            parsed = urlparse(self.path)
            path = parsed.path
            body = {}
            if self.command == "POST":
                if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                    raise ValueError("unsupported_framing")
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 32768:
                    raise ValueError("body_limit")
                body = strict_json(self.rfile.read(size))
            if identity is None:
                if self.command == "POST" and path == "/jobs":
                    value = broker.create(body)
                elif self.command == "POST" and path == "/stop":
                    fields(body, ("job_id",))
                    value = broker.stop(broker.job(body["job_id"]))
                elif self.command == "GET" and path in {"/trace", "/snapshot"}:
                    query = parse_qs(parsed.query)
                    fields(query, ("job_id",))
                    if len(query["job_id"]) != 1:
                        raise ValueError("invalid_job_id")
                    job = broker.job(query["job_id"][0])
                    value = broker.trace(job) if path == "/trace" else broker.snapshot(job, job["root_token"])
                else:
                    raise PermissionError("role_forbidden")
            else:
                job, run_id = identity
                if parsed.query:
                    raise PermissionError("scope_forbidden")
                if self.command == "GET" and path == "/snapshot":
                    value = broker.snapshot(job, token)
                elif self.command == "GET" and path == "/trace":
                    value = broker.trace(job, run_id)
                elif self.command == "POST" and path in {"/authorize", "/act"}:
                    attempt = broker.attempt(body)
                    value = broker.authorize(job, token, run_id, attempt)
                    if path == "/act" and value["status"] == "reserved":
                        value = broker.execute(job, token, run_id, value["ticket"])
                elif self.command == "POST" and path == "/model":
                    value = broker.model(job, token, run_id, body)
                elif self.command == "POST" and path == "/execute":
                    fields(body, ("ticket",))
                    value = broker.execute(job, token, run_id, body["ticket"])
                elif self.command == "POST" and path == "/delegate":
                    value = broker.delegate(job, token, run_id, body)
                elif self.command == "POST" and path == "/complete":
                    fields(body)
                    value = broker.complete(job, token, run_id)
                else:
                    raise PermissionError("role_forbidden")
            if identity is not None:
                job, run_id = identity
                value = {**value, "trace_context": broker.observation_context(job, run_id)}
            self.respond(200, value)
        except PermissionError:
            self.respond(403, {"status": "denied", "reason": "unauthorized"})
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            if identity:
                broker.record(identity[0], identity[1], "request_rejected", reason="malformed_request")
            self.respond(400, {"status": "denied", "reason": "malformed_request"})
        except Exception:
            if identity:
                broker.record(identity[0], identity[1], "request_error", reason="service_unavailable")
            self.respond(503, {"status": "denied", "reason": "service_unavailable"})

    def respond(self, code, value):
        body = encoded(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def state_startup_check(policy_file, state_dir):
    """Build a guarded startup check without creating state or acquiring a lease."""
    from deploy.state_guard import StatePolicy, StateGuardError, verify_mount, verify_existing_state
    policy_data = strict_json(Path(policy_file).read_text())
    fields(policy_data, ("mountpoint", "state_dir", "volume_id", "filesystem_uuid", "uid", "gid"))
    policy = StatePolicy(**policy_data)
    if Path(state_dir) != policy.state_dir:
        raise StateGuardError("state_policy_path_mismatch")
    verify_mount(policy)
    return lambda lease: verify_existing_state(policy, lease=lease)


def configured_live_model():
    from controller.installation import load_installation
    from controller.live_model import LiveModelGateway
    from controller.project_budget import ProjectBudgetLedger
    if not os.environ.get("CONTROLLER_LIVE_CONFIG"):
        return None
    installation_path = os.environ.get("CONTROLLER_INSTALLATION_CONFIG")
    if not installation_path:
        raise ValueError("trusted_installation_config_required")
    installation = load_installation(installation_path)
    ledger_path = os.environ.get("CONTROLLER_PROJECT_LEDGER")
    if not ledger_path or not Path(ledger_path).is_file():
        raise ValueError("existing_project_ledger_required")
    return LiveModelGateway.from_environment(ProjectBudgetLedger.open_existing(ledger_path, installation=installation))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--state-policy", help="Reviewed existing-volume policy JSON; never bootstrap state")
    args = parser.parse_args()
    os.umask(0o077)
    startup_check = state_startup_check(args.state_policy, args.state_dir) if args.state_policy else None
    # The factory runs after the guard, before recovery of live-enabled jobs.
    # No listener exists until durable state and model setup both succeed.
    with Broker(args.state_dir, os.environ.pop("CONTROLLER_ADMIN_TOKEN", None),
                startup_check=startup_check, live_model_factory=configured_live_model) as broker:
        with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
            # Idle HTTP connections must not delay shutdown. Broker.close()
            # separately drains active operations before releasing ownership.
            server.daemon_threads = True
            server.broker = broker
            ready = Path(args.ready_file)
            ready.parent.mkdir(parents=True, exist_ok=True)
            ready.write_text(encoded({"url": f"http://127.0.0.1:{server.server_port}", "pid": os.getpid()}))
            try:
                server.serve_forever(poll_interval=0.1)
            finally:
                ready.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
