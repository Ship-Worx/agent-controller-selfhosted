"""Synthetic regressions for audit failures around durable dispatch and settlement."""
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from controller.engine import Attempt
from controller.installation import InstallationConfig
from controller.live_model import LiveModelGateway, MODEL_CONTEXT_TOKENS, MODEL_ID, PriceCard
from controller.project_budget import ProjectBudgetLedger
from controller.service import Broker


class AuditCallbackRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.ledger = ProjectBudgetLedger(
            root / "project.sqlite",
            installation=InstallationConfig("example/agent-controller", "0" * 11 + "1", "us-east-1", 200_000_000),
        )
        self.ledger.reconcile(prior_spent_microusd=0, outstanding_reserved_microusd=0,
                              evidence_refs=["test:synthetic-baseline"], as_of="2026-01-01T00:00:00Z")
        now = int(time.time())
        self.prices = PriceCard(MODEL_ID, 400_000, 1_600_000, MODEL_CONTEXT_TOKENS,
                                now - 1, now + 1000, "https://openai.com/api/pricing/", "test:fixture")
        self.calls = []
        self.transport_error = False

        def transport(prompt, operation_key):
            self.calls.append((prompt, operation_key))
            if self.transport_error:
                raise TimeoutError("synthetic provider failure")
            return {"id": "resp_fixture", "model": MODEL_ID, "service_tier": "default",
                    "status": "completed",
                    "output": [{"type": "message", "content": [{"type": "output_text", "text": "Done."}]}],
                    "usage": {"input_tokens": 50, "output_tokens": 10, "total_tokens": 60}}

        self.gateway = LiveModelGateway(self.prices, self.ledger, transport)
        self.broker = Broker(root / "service", "test-admin-" + "x" * 32, live_model=self.gateway)
        self.addCleanup(self.broker.close)
        created = self.broker.create({"workflow": "recruiting", "live_model": True, "budget_microusd": 1_000_000})
        self.job = self.broker.job(created["job_id"])
        self.token, self.run = created["token"], created["run_id"]
        self.body = {"operation_id": "model-callback", "prompt": "Fictional test prompt."}

    def fail_records(self, *events):
        original = self.broker.record

        def record(job, run, event, **data):
            if event in events:
                raise RuntimeError("synthetic audit failure")
            return original(job, run, event, **data)

        return patch.object(self.broker, "record", side_effect=record)

    def operation_status(self, operation_id):
        with self.broker.authority(self.job)._transaction() as conn:
            return conn.execute("SELECT status FROM operations WHERE operation_id=?", (operation_id,)).fetchone()[0]

    def model(self):
        return self.broker.model(self.job, self.token, self.run, self.body)

    def reserve_read(self):
        attempt = Attempt("tool-callback", "read", "record.read", "candidate-a", "worker", {})
        result = self.broker.authorize(self.job, self.token, self.run, attempt)
        self.assertEqual(result["status"], "reserved")
        return result["ticket"]

    def effects_count(self):
        with self.broker.connect() as conn:
            return conn.execute("SELECT count(*) FROM effects WHERE job_id=?", (self.job["job_id"],)).fetchone()[0]

    def test_model_proposal_audit_failure_denies_before_reservation(self):
        with self.fail_records("model_proposed"):
            result = self.model()
        self.assertEqual((result["status"], result["reason"]), ("denied", "audit_unavailable"))
        self.assertNotIn("receipt", result)
        with self.broker.authority(self.job)._transaction() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM operations").fetchone()[0], 0)
        self.assertEqual(self.ledger.snapshot()["operations"], {})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.model()["status"], "allowed")
        self.assertEqual(len(self.calls), 1)

    def test_model_start_audit_failure_retains_both_reservations_without_transport(self):
        with self.fail_records("model_started", "model_unknown", "model_decision"):
            result = self.model()
        self.assertEqual((result["status"], result["reason"]), ("held", "model_outcome_unknown"))
        self.assertNotIn("receipt", result)
        self.assertEqual(self.operation_status(self.body["operation_id"]), "unknown")
        project = self.ledger.snapshot()
        self.assertEqual(project["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertEqual(next(iter(project["operations"].values()))["status"], "unknown")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.model()["reason"], "operation_unknown")
        self.assertEqual(self.calls, [])

    def test_model_unknown_write_failure_keeps_claim_and_prevents_transport(self):
        authority = self.broker.authority(self.job)
        with patch.object(authority, "mark_unknown", side_effect=RuntimeError("synthetic state failure")), \
                self.fail_records("model_started"):
            result = self.model()
        self.assertEqual((result["status"], result["reason"]), ("held", "model_outcome_unknown"))
        self.assertEqual(self.operation_status(self.body["operation_id"]), "dispatched")
        project = self.ledger.snapshot()
        self.assertEqual(project["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.model()["reason"], "operation_unknown")
        self.assertEqual(self.calls, [])

    def test_project_unknown_write_failure_keeps_reservation_and_prevents_transport(self):
        with patch.object(self.ledger, "mark_unknown", side_effect=RuntimeError("synthetic ledger failure")), \
                self.fail_records("model_started"):
            result = self.model()
        self.assertEqual((result["status"], result["reason"]), ("held", "model_outcome_unknown"))
        self.assertEqual(self.operation_status(self.body["operation_id"]), "unknown")
        project = self.ledger.snapshot()
        self.assertEqual(project["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertEqual(next(iter(project["operations"].values()))["status"], "reserved")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.model()["reason"], "operation_unknown")
        self.assertEqual(self.calls, [])

    def test_model_finish_audit_failure_keeps_settlement_and_replays_without_transport(self):
        with self.fail_records("model_finished"):
            result = self.model()
        self.assertEqual((result["status"], result["reason"]), ("held", "model_outcome_unknown"))
        self.assertNotIn("receipt", result)
        self.assertEqual(self.operation_status(self.body["operation_id"]), "settled")
        project = self.ledger.snapshot()
        self.assertEqual((project["spent_microusd"], project["reserved_microusd"]),
                         (self.prices.cost(50, 10), 0))
        self.assertEqual(len(self.calls), 1)
        replay = self.model()
        self.assertEqual(replay["status"], "allowed")
        self.assertTrue(replay["replayed"])
        self.assertEqual(len(self.calls), 1)

    def test_model_decision_audit_failure_keeps_settlement_and_replays_without_transport(self):
        with self.fail_records("model_decision"):
            result = self.model()
        self.assertEqual((result["status"], result["reason"]), ("held", "model_outcome_unknown"))
        self.assertNotIn("receipt", result)
        self.assertEqual(self.operation_status(self.body["operation_id"]), "settled")
        self.assertEqual(self.ledger.snapshot()["spent_microusd"], self.prices.cost(50, 10))
        self.assertEqual(len(self.calls), 1)
        replay = self.model()
        self.assertEqual(replay["status"], "allowed")
        self.assertTrue(replay["replayed"])
        self.assertEqual(len(self.calls), 1)

    def test_stopped_run_cannot_release_a_settled_model_after_audit_failure(self):
        with self.fail_records("model_finished"):
            self.assertEqual(self.model()["status"], "held")
        self.broker.stop(self.job)
        replay = self.model()
        self.assertEqual(replay["status"], "denied")
        self.assertNotIn("receipt", replay)
        self.assertEqual(len(self.calls), 1)

    def test_model_unknown_audit_failure_keeps_unknown_cost_and_does_not_retry(self):
        self.transport_error = True
        with self.fail_records("model_unknown"):
            result = self.model()
        self.assertEqual((result["status"], result["reason"]), ("held", "model_outcome_unknown"))
        self.assertEqual(self.operation_status(self.body["operation_id"]), "unknown")
        self.assertEqual(self.ledger.snapshot()["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.model()["reason"], "operation_unknown")
        self.assertEqual(len(self.calls), 1)

    def test_tool_start_audit_failure_holds_claim_without_an_effect(self):
        ticket = self.reserve_read()
        with self.fail_records("tool_started", "tool_error"):
            result = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual((result["status"], result["reason"]), ("held", "outcome_unknown"))
        self.assertEqual(self.operation_status("tool-callback"), "unknown")
        self.assertEqual(self.effects_count(), 0)
        self.assertEqual(self.broker.snapshot(self.job, self.token)["reserved_microusd"], 2)
        self.assertNotEqual(self.broker.execute(self.job, self.token, self.run, ticket)["status"], "allowed")
        self.assertEqual(self.effects_count(), 0)

    def test_tool_unknown_write_failure_keeps_claim_without_an_effect(self):
        ticket = self.reserve_read()
        authority = self.broker.authority(self.job)
        with patch.object(authority, "mark_unknown", side_effect=RuntimeError("synthetic state failure")), \
                self.fail_records("tool_started"):
            result = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual((result["status"], result["reason"]), ("held", "outcome_unknown"))
        self.assertEqual(self.operation_status("tool-callback"), "dispatched")
        self.assertEqual(self.broker.snapshot(self.job, self.token)["reserved_microusd"], 2)
        self.assertEqual(self.effects_count(), 0)
        self.assertNotEqual(self.broker.execute(self.job, self.token, self.run, ticket)["status"], "allowed")
        self.assertEqual(self.effects_count(), 0)

    def check_settled_tool_audit_failure(self, event):
        ticket = self.reserve_read()
        with self.fail_records(event, "tool_error"):
            result = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual((result["status"], result["reason"]), ("held", "outcome_unknown"))
        self.assertNotIn("receipt", result)
        self.assertEqual(self.operation_status("tool-callback"), "settled")
        self.assertEqual(self.effects_count(), 1)
        self.assertEqual(self.broker.snapshot(self.job, self.token)["settled_microusd"], 2)
        replay = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual(replay["status"], "allowed")
        self.assertTrue(replay["replayed"])
        self.assertEqual(self.effects_count(), 1)

    def test_tool_finish_audit_failure_keeps_settlement(self):
        self.check_settled_tool_audit_failure("tool_finished")

    def test_tool_release_audit_failure_keeps_settlement(self):
        self.check_settled_tool_audit_failure("result_release")

    def test_tool_replay_audit_failure_withholds_receipt_without_new_effect(self):
        ticket = self.reserve_read()
        self.assertEqual(self.broker.execute(self.job, self.token, self.run, ticket)["status"], "allowed")
        with self.fail_records("execution_replayed"):
            result = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual((result["status"], result["reason"]), ("held", "outcome_unknown"))
        self.assertNotIn("receipt", result)
        self.assertEqual(self.operation_status("tool-callback"), "settled")
        self.assertEqual(self.effects_count(), 1)
        replay = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual(replay["status"], "allowed")
        self.assertTrue(replay["replayed"])
        self.assertEqual(self.effects_count(), 1)

    def test_tool_replay_audit_failure_does_not_override_stop(self):
        ticket = self.reserve_read()
        self.assertEqual(self.broker.execute(self.job, self.token, self.run, ticket)["status"], "allowed")
        self.broker.stop(self.job)
        with self.fail_records("execution_replayed"):
            result = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertNotEqual(result["status"], "allowed")
        self.assertNotIn("receipt", result)
        replay = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual(replay["status"], "denied")
        self.assertNotIn("receipt", replay)
        self.assertEqual(self.effects_count(), 1)

    def test_stopped_run_cannot_release_a_settled_tool_after_audit_failure(self):
        ticket = self.reserve_read()
        with self.fail_records("tool_finished"):
            self.assertEqual(self.broker.execute(self.job, self.token, self.run, ticket)["status"], "held")
        self.broker.stop(self.job)
        replay = self.broker.execute(self.job, self.token, self.run, ticket)
        self.assertEqual(replay["status"], "denied")
        self.assertNotIn("receipt", replay)
        self.assertEqual(self.effects_count(), 1)


if __name__ == "__main__":
    unittest.main()
