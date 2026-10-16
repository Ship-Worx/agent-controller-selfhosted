"""Trusted-operator project spending ledger; never expose it to agent HTTP routes.

Amounts are integer micro-US dollars. This ledger is separate from fictional
workflow prices. A successful *new* reservation is the sole permission to make
one paid request; every replay is denied, including after an uncertain crash.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Iterator, Sequence

from .installation import InstallationConfig, load_installation

_MAX_SQLITE_INT = 2**63 - 1
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,511}\Z")
_CREDENTIAL = re.compile(
    r"sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{12,}|ASIA[A-Z0-9]{12,}|"
    r"gh[pousr]_[A-Za-z0-9_]{12,}|aws_secret_access_key|-----BEGIN",
    re.IGNORECASE,
)


class BudgetConflict(RuntimeError):
    """An operation would change immutable accounting or trusted identity."""


def _amount(value: int, *, positive: bool = False) -> int:
    if type(value) is not int or not (int(positive) <= value <= _MAX_SQLITE_INT):
        raise ValueError("Costs must be bounded integer microusd with the required sign")
    return value


def _reference(value: str) -> str:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value) or _CREDENTIAL.search(value):
        raise ValueError("Use a non-secret evidence/operation reference identifier")
    return value


def _references(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)) or not values:
        raise ValueError("At least one trusted source/evidence reference is required")
    if len(values) > 32:
        raise ValueError("Too many evidence references")
    return sorted(set(_reference(value) for value in values))


def _timestamp(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("A timezone-aware ISO reconciliation timestamp is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("A timezone-aware ISO reconciliation timestamp is required") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Reconciliation timestamp must include its timezone")
    parsed = parsed.astimezone(timezone.utc)
    if parsed.timestamp() > datetime.now(timezone.utc).timestamp() + 300:
        raise ValueError("Reconciliation timestamp cannot be in the future")
    return parsed.isoformat()


class ProjectBudgetLedger:
    """A single project's ledger, held by a trusted operator/provider gateway.

    The process identity and filesystem permissions provide the trust boundary.
    An agent must receive neither this object, this SQLite file, nor a route that
    invokes reconciliation/settlement on its behalf. See docs/COST_CONTROL.md.
    """

    def __init__(self, path: str | Path, *, installation: InstallationConfig):
        self._bind(path, installation)
        if Path(self.path).exists():
            # Reject mismatched/empty existing databases before any writable
            # connection or schema initialization; legacy schemas are retained.
            self._check_existing()
        else:
            self._initialize_new()

    def _bind(self, path, installation):
        if type(installation) is not InstallationConfig:
            raise BudgetConflict("An explicit trusted installation identity is required")
        self.installation = installation
        self.path = str(Path(path).resolve())

    def _initialize_new(self):
        try:
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise BudgetConflict("Refusing to initialize an existing project ledger") from None
        os.close(descriptor)
        with self._transaction(initialize=True) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS project_budget (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                project_id TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
                limit_microusd INTEGER NOT NULL CHECK(limit_microusd>0),
                prior_spent INTEGER, external_reserved INTEGER,
                reconciliation TEXT, stopped INTEGER NOT NULL DEFAULT 0,
                stop_reason TEXT
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS project_operations (
                operation_id TEXT PRIMARY KEY, maximum INTEGER NOT NULL CHECK(maximum>0),
                status TEXT NOT NULL CHECK(status IN ('reserved','unknown','settled','overrun')),
                actual INTEGER, reserve_evidence TEXT NOT NULL,
                outcome_evidence TEXT, created_at TEXT NOT NULL
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS project_budget_trace (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                event TEXT NOT NULL, operation_id TEXT, details TEXT NOT NULL
            )""")
            conn.execute("""INSERT OR IGNORE INTO project_budget
                (singleton,project_id,account_id,region,limit_microusd) VALUES(1,?,?,?,?)""",
                self.installation.identity)
            self._check_identity(conn)

    @classmethod
    def create_new(cls, path: str | Path, *, installation: InstallationConfig):
        ledger = cls.__new__(cls)
        ledger._bind(path, installation)
        ledger._initialize_new()
        return ledger

    @classmethod
    def open_existing(cls, path: str | Path, *, installation: InstallationConfig):
        ledger = cls.__new__(cls)
        ledger._bind(path, installation)
        ledger._check_existing()
        return ledger

    def _check_identity(self, conn):
        row = self._project(conn)
        if row is None or tuple(row[key] for key in (
                "project_id", "account_id", "region", "limit_microusd")) != self.installation.identity:
            raise BudgetConflict("Existing ledger identity or immutable maximum does not match")

    def _check_existing(self):
        try:
            conn = sqlite3.connect(Path(self.path).as_uri() + "?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA query_only=ON")
                self._check_identity(conn)
                # A partial or empty replacement is not a fresh installation.
                conn.execute("SELECT * FROM project_operations LIMIT 0")
                conn.execute("SELECT * FROM project_budget_trace LIMIT 0")
            finally:
                conn.close()
        except sqlite3.DatabaseError:
            raise BudgetConflict("Existing project ledger is incomplete or invalid") from None

    @contextmanager
    def _transaction(self, *, initialize=False) -> Iterator[sqlite3.Connection]:
        # Existing ledgers must never be silently recreated after removal.
        target = self.path if initialize else Path(self.path).as_uri() + "?mode=rw"
        conn = sqlite3.connect(target, timeout=30, isolation_level=None, uri=not initialize)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            if not initialize:
                self._check_identity(conn)
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _project(conn: sqlite3.Connection) -> sqlite3.Row:
        return conn.execute("SELECT * FROM project_budget WHERE singleton=1").fetchone()

    @staticmethod
    def _event(conn: sqlite3.Connection, event: str, operation_id: str | None = None,
               **details: object) -> None:
        conn.execute("INSERT INTO project_budget_trace(timestamp,event,operation_id,details) VALUES(?,?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), event, operation_id,
                      json.dumps(details, sort_keys=True)))

    @staticmethod
    def _operation(row: sqlite3.Row) -> dict:
        return {"operation_id": row["operation_id"], "max_cost_microusd": row["maximum"],
                "status": row["status"], "actual_cost_microusd": row["actual"],
                "reserve_evidence_refs": json.loads(row["reserve_evidence"]),
                "outcome_evidence_refs": json.loads(row["outcome_evidence"]) if row["outcome_evidence"] else None,
                "created_at": row["created_at"]}

    def _snapshot(self, conn: sqlite3.Connection) -> dict:
        project = self._project(conn)
        operations = {row["operation_id"]: self._operation(row) for row in
                      conn.execute("SELECT * FROM project_operations ORDER BY operation_id")}
        known = project["reconciliation"] is not None
        local_spent = sum(op["actual_cost_microusd"] for op in operations.values()
                          if op["status"] in ("settled", "overrun"))
        local_reserved = sum(op["max_cost_microusd"] for op in operations.values()
                             if op["status"] in ("reserved", "unknown"))
        spent = project["prior_spent"] + local_spent if known else None
        reserved = project["external_reserved"] + local_reserved if known else None
        exposure = spent + reserved if known else None
        return {"project_id": project["project_id"], "account_id": project["account_id"], "region": project["region"],
                "limit_microusd": project["limit_microusd"], "reconciled": known,
                "stopped": bool(project["stopped"]), "stop_reason": project["stop_reason"],
                "prior_spent_microusd": project["prior_spent"],
                "external_reserved_microusd": project["external_reserved"],
                "spent_microusd": spent, "reserved_microusd": reserved,
                "exposure_microusd": exposure,
                "remaining_microusd": max(0, project["limit_microusd"] - exposure) if known else None,
                "reconciliation": json.loads(project["reconciliation"]) if known else None,
                "operations": operations}

    def snapshot(self) -> dict:
        with self._transaction() as conn:
            return self._snapshot(conn)

    def trace(self) -> list[dict]:
        with self._transaction() as conn:
            return [{"sequence": row["sequence"], "timestamp": row["timestamp"],
                     "event": row["event"], "operation_id": row["operation_id"],
                     "details": json.loads(row["details"])}
                    for row in conn.execute("SELECT * FROM project_budget_trace ORDER BY sequence")]

    def stop(self, reason_ref: str, evidence_refs: Sequence[str]) -> dict:
        """Persist an operator stop, for example upon new external cost uncertainty."""
        reason, evidence = _reference(reason_ref), _references(evidence_refs)
        with self._transaction() as conn:
            conn.execute("""UPDATE project_budget SET stopped=1,
                stop_reason=COALESCE(stop_reason,?) WHERE singleton=1""", (reason,))
            self._event(conn, "project_stopped", reason=reason, evidence_refs=evidence)
            return self._snapshot(conn)

    def reconcile(self, *, prior_spent_microusd: int, outstanding_reserved_microusd: int,
                  evidence_refs: Sequence[str], as_of: str) -> dict:
        """Import a verified baseline once; exact replay is harmless, changes fail.

        Unknown external liabilities must already have conservative finite upper
        bounds in outstanding_reserved_microusd. Unbounded/unknown prior costs
        cannot be represented as zero; leave this ledger unreconciled instead.
        """
        prior = _amount(prior_spent_microusd)
        reserved = _amount(outstanding_reserved_microusd)
        evidence = _references(evidence_refs)
        record = {"prior_spent_microusd": prior, "outstanding_reserved_microusd": reserved,
                  "evidence_refs": evidence, "as_of": _timestamp(as_of)}
        encoded = json.dumps(record, sort_keys=True)
        with self._transaction() as conn:
            current = self._project(conn)
            if current["reconciliation"] is not None:
                if current["reconciliation"] != encoded:
                    raise BudgetConflict("Verified historical spend and external reservations cannot be reset")
                return self._snapshot(conn)
            conn.execute("""UPDATE project_budget SET prior_spent=?,external_reserved=?,
                reconciliation=? WHERE singleton=1""", (prior, reserved, encoded))
            self._event(conn, "reconciled", **record)
            if prior + reserved > current["limit_microusd"]:
                conn.execute("UPDATE project_budget SET stopped=1,stop_reason='reconciled_over_cap' WHERE singleton=1")
                self._event(conn, "project_stopped", reason="reconciled_over_cap")
            return self._snapshot(conn)

    def reserve(self, operation_id: str, max_cost_microusd: int,
                evidence_refs: Sequence[str]) -> dict:
        operation_id = _reference(operation_id)
        maximum = _amount(max_cost_microusd, positive=True)
        evidence = json.dumps(_references(evidence_refs), sort_keys=True)
        with self._transaction() as conn:
            existing = conn.execute("SELECT * FROM project_operations WHERE operation_id=?", (operation_id,)).fetchone()
            state = self._snapshot(conn)
            if not state["reconciled"]:
                reason = "reconciliation_required"
            elif state["stopped"]:
                reason = "project_stopped"
            elif existing:
                if existing["maximum"] != maximum or existing["reserve_evidence"] != evidence:
                    reason = "idempotency_conflict"
                else:
                    reason = {"reserved": "already_reserved", "unknown": "outcome_unknown",
                              "settled": "already_settled", "overrun": "already_settled"}[existing["status"]]
            elif state["exposure_microusd"] + maximum > state["limit_microusd"]:
                reason = "project_budget_exhausted"
            else:
                conn.execute("""INSERT INTO project_operations
                    (operation_id,maximum,status,reserve_evidence,created_at) VALUES(?,?,'reserved',?,?)""",
                    (operation_id, maximum, evidence, datetime.now(timezone.utc).isoformat()))
                row = conn.execute("SELECT * FROM project_operations WHERE operation_id=?", (operation_id,)).fetchone()
                self._event(conn, "reserved", operation_id, max_cost_microusd=maximum,
                            evidence_refs=json.loads(evidence))
                return {"approved": True, "reason": "reserved", "operation": self._operation(row)}
            self._event(conn, "reservation_denied", operation_id, reason=reason,
                        max_cost_microusd=maximum, evidence_refs=json.loads(evidence))
            return {"approved": False, "reason": reason,
                    "operation": self._operation(existing) if existing else None}

    def mark_unknown(self, operation_id: str, evidence_refs: Sequence[str]) -> dict:
        operation_id, evidence = _reference(operation_id), _references(evidence_refs)
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM project_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None or row["status"] not in ("reserved", "unknown"):
                raise BudgetConflict("Only an unsettled reservation can have an unknown outcome")
            previous = json.loads(row["outcome_evidence"]) if row["outcome_evidence"] else []
            combined = sorted(set(previous + evidence))
            conn.execute("UPDATE project_operations SET status='unknown',outcome_evidence=? WHERE operation_id=?",
                         (json.dumps(combined), operation_id))
            self._event(conn, "outcome_unknown", operation_id, retained_microusd=row["maximum"],
                        evidence_refs=evidence)
            return self._operation(conn.execute("SELECT * FROM project_operations WHERE operation_id=?", (operation_id,)).fetchone())
    def settle(self, operation_id: str, actual_cost_microusd: int,
               evidence_refs: Sequence[str]) -> dict:
        operation_id, actual = _reference(operation_id), _amount(actual_cost_microusd)
        evidence = _references(evidence_refs)
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM project_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                raise BudgetConflict("A known reservation must precede settlement")
            if row["status"] in ("settled", "overrun"):
                if row["actual"] != actual or json.loads(row["outcome_evidence"]) != evidence:
                    raise BudgetConflict("A settlement cannot be changed or discounted")
                return self._operation(row)
            status = "overrun" if actual > row["maximum"] else "settled"
            conn.execute("UPDATE project_operations SET status=?,actual=?,outcome_evidence=? WHERE operation_id=?",
                         (status, actual, json.dumps(evidence), operation_id))
            self._event(conn, status, operation_id, actual_cost_microusd=actual,
                        reserved_microusd=row["maximum"], evidence_refs=evidence)
            if status == "overrun":
                conn.execute("UPDATE project_budget SET stopped=1,stop_reason='reservation_overrun' WHERE singleton=1")
                self._event(conn, "project_stopped", operation_id, reason="reservation_overrun")
            return self._operation(conn.execute("SELECT * FROM project_operations WHERE operation_id=?", (operation_id,)).fetchone())


def main(argv=None):
    """Initialize accounting only; never reconcile, reserve or invoke a provider."""
    parser = argparse.ArgumentParser(description="Initialize a new unreconciled installation budget ledger.")
    parser.add_argument("command", choices=["init"])
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args(argv)
    installation = load_installation(args.installation)
    if not args.ledger.is_absolute():
        raise ValueError("absolute_project_ledger_required")
    if args.ledger.is_symlink():
        raise BudgetConflict("Refusing to initialize an existing project ledger")
    ledger = ProjectBudgetLedger.create_new(args.ledger, installation=installation)
    print(json.dumps({"status": "initialized_unreconciled", **ledger.snapshot()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
