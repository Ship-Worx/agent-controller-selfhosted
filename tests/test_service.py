"""Broker regressions with independent durable effect observations."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from controller.engine import Attempt
from controller.service import Broker


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.broker = Broker(self.temp.name, "test-admin-" + "x" * 32)
        self.addCleanup(self.broker.close)
        self.created = self.broker.create({"workflow": "recruiting"})
        self.job = self.broker.job(self.created["job_id"])
        self.token = self.created["token"]
        self.run = self.created["run_id"]

    def read(self, operation="read-1"):
        return Attempt(operation, "read", "record.read", "candidate-a", "worker", {})

    def reserve(self, attempt=None):
        return self.broker.authorize(self.job, self.token, self.run, attempt or self.read())

    def effects(self):
        with sqlite3.connect(Path(self.temp.name) / "broker.sqlite") as conn:
            return conn.execute("SELECT action,receipt,cost FROM effects").fetchall()

    def test_allowed_receipt_and_trace_exclude_credentials(self):
        reserved = self.reserve()
        result = self.broker.execute(self.job, self.token, self.run, reserved["ticket"])
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(len(self.effects()), 1)
        trace = json.dumps(self.broker.trace(self.job))
        for secret in (self.token, reserved["ticket"], self.broker.admin_token):
            self.assertNotIn(secret, trace)
        self.assertIn('"tokens": null', trace)

    def test_unknown_dispatch_survives_restart_without_refund_or_retry(self):
        reserved = self.reserve()
        authority = self.broker.authority(self.job)
        self.assertEqual(authority.claim(reserved["ticket"]).status, "allowed")
        self.broker.close()
        restarted = Broker(self.temp.name, "test-admin-" + "x" * 32)
        self.addCleanup(restarted.close)
        snap = restarted.snapshot(self.job, self.token)
        self.assertEqual(snap["reserved_microusd"], 2)
        self.assertEqual(len(snap["unknown_operations"]), 1)
        result = restarted.execute(self.job, self.token, self.run, reserved["ticket"])
        self.assertNotEqual(result["status"], "allowed")
        self.assertEqual(self.effects(), [])

    def test_receipt_reconciles_crash_without_repeating_effect(self):
        reserved = self.reserve()
        authority = self.broker.authority(self.job)
        authority.claim(reserved["ticket"])
        receipt = {"record_id": "candidate-a", "data": {"name": "Fictional Ada"}}
        with self.broker.connect() as conn:
            conn.execute("INSERT INTO effects VALUES(?,?,?,?,?,?)", (reserved["ticket"], self.job["job_id"],
                         "read-1", "record.read", json.dumps(receipt), 2))
        self.broker.close()
        restarted = Broker(self.temp.name, "test-admin-" + "x" * 32)
        self.addCleanup(restarted.close)
        snap = restarted.snapshot(self.job, self.token)
        self.assertEqual((snap["settled_microusd"], snap["reserved_microusd"]), (2, 0))
        restarted.execute(self.job, self.token, self.run, reserved["ticket"])
        self.assertEqual(len(self.effects()), 1)

    def test_unknown_without_receipt_survives_restart_without_refund_or_retry(self):
        reserved = self.reserve()
        authority = self.broker.authority(self.job)
        authority.claim(reserved["ticket"])
        authority.mark_unknown(reserved["ticket"])
        self.broker.close()
        restarted = Broker(self.temp.name, "test-admin-" + "x" * 32)
        self.addCleanup(restarted.close)
        snap = restarted.snapshot(self.job, self.token)
        self.assertEqual((snap["settled_microusd"], snap["reserved_microusd"]), (0, 2))
        self.assertEqual(len(snap["unknown_operations"]), 1)
        result = restarted.execute(self.job, self.token, self.run, reserved["ticket"])
        self.assertNotEqual(result["status"], "allowed")
        self.assertNotIn("receipt", result)
        self.assertEqual(self.effects(), [])

    def _check_unknown_receipt_recovery(self, *, stopped):
        reserved = self.reserve()
        authority = self.broker.authority(self.job)
        authority.claim(reserved["ticket"])
        receipt = {"record_id": "candidate-a", "data": {"name": "Fictional Ada"}}
        with self.broker.connect() as conn:
            conn.execute("INSERT INTO effects VALUES(?,?,?,?,?,?)", (reserved["ticket"], self.job["job_id"],
                         "read-1", "record.read", json.dumps(receipt), 2))
        # The receiver journal committed, but settlement failed before the
        # exception path retained the authority operation as unknown.
        authority.mark_unknown(reserved["ticket"])
        if stopped:
            self.broker.stop(self.job)
        before = self.effects()
        self.broker.close()
        restarted = Broker(self.temp.name, "test-admin-" + "x" * 32)
        self.addCleanup(restarted.close)
        snap = restarted.snapshot(self.job, self.token)
        self.assertEqual((snap["settled_microusd"], snap["reserved_microusd"]), (2, 0))
        self.assertEqual(snap["unknown_operations"], [])
        self.assertEqual(snap["stopped"], stopped)
        result = restarted.execute(self.job, self.token, self.run, reserved["ticket"])
        self.assertNotEqual(result["status"], "allowed")
        self.assertNotIn("receipt", result)
        if stopped:
            self.assertEqual(result["reason"], "root_stopped")
        self.assertEqual(self.effects(), before)
        self.assertEqual(len(before), 1)

    def test_unknown_receipt_reconciles_without_repeating_or_releasing_effect(self):
        self._check_unknown_receipt_recovery(stopped=False)

    def test_unknown_receipt_reconciles_after_stop_without_releasing_effect(self):
        self._check_unknown_receipt_recovery(stopped=True)

    def test_supported_cancellation_reports_inflight_then_acknowledges(self):
        slow = Attempt("slow-1", "slow", "report.slow", "candidate-a", "internal", {})
        reserved = self.reserve(slow)
        with ThreadPoolExecutor() as pool:
            pending = pool.submit(self.broker.execute, self.job, self.token, self.run, reserved["ticket"])
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if any(item["event"] == "tool_started" for item in self.broker.trace(self.job)["events"]):
                    break
                time.sleep(.01)
            stopped = self.broker.stop(self.job)
            self.assertTrue(stopped["already_in_flight"])
            result = pending.result(timeout=3)
        self.assertEqual(result["cancellation"], "acknowledged")
        self.assertEqual(result["status"], "denied")
        self.assertEqual(json.loads(self.effects()[0][1]), {"cancelled": True, "effect": False})
        self.assertEqual(self.broker.snapshot(self.job, self.token)["in_flight"], [])

    def test_child_uses_parent_allocation_and_cannot_spend_parent_ticket(self):
        child = self.broker.delegate(self.job, self.token, self.run,
            {"capabilities": [self.created["capabilities"][0]], "context_fields": ["record_id", "task"],
             "runtime_seconds": 10000})
        self.assertEqual(child["budget_microusd"], 30)
        self.assertLessEqual(child["deadline"], self.created["deadline"])
        reserved = self.reserve()
        result = self.broker.execute(self.job, child["token"], child["run_id"], reserved["ticket"])
        self.assertEqual(result["reason"], "ticket_binding_mismatch")
        self.assertEqual(self.effects(), [])

    def test_missing_registry_cannot_reset_existing_authority(self):
        self.broker.close()
        Path(self.temp.name, "broker.sqlite").unlink()
        with self.assertRaisesRegex(ValueError, "registry_missing"):
            Broker(self.temp.name, "test-admin-" + "x" * 32)


if __name__ == "__main__":
    unittest.main()
