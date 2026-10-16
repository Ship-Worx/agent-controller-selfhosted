"""Paid-provider boundary tests use mocked transport and temporary accounting only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from http.server import ThreadingHTTPServer
import os
from pathlib import Path
import tempfile
import sys
import threading
import time
import unittest
from unittest.mock import patch

from controller.engine import Attempt
from controller.live_model import (LiveModelGateway, MAX_PROMPT_BYTES, MODEL_CONTEXT_TOKENS,
                                   MODEL_ID, OpenAIResponsesTransport, PriceCard)
from controller.installation import InstallationConfig
from controller.project_budget import ProjectBudgetLedger
from controller.service import Broker, Handler
from integration.client import ControllerClient
from integration.live_worker import run_live
from integration.process import run_sdk_process


def response(*, usage=True, tokens=(50, 10), output=None):
    value = {"id": "resp_fixture", "model": MODEL_ID, "service_tier": "default", "status": "completed",
             "output": output or [{"type": "message", "content": [{"type": "output_text", "text": "Done."}]}]}
    if usage:
        value["usage"] = {"input_tokens": tokens[0], "output_tokens": tokens[1], "total_tokens": sum(tokens)}
    return value


class Transport:
    def __init__(self):
        self.calls = []
        self.callback = lambda: response()

    def __call__(self, prompt, operation_key):
        self.calls.append((prompt, operation_key))
        return self.callback()


class LiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = ProjectBudgetLedger(
            Path(self.temp.name) / "project.sqlite",
            installation=InstallationConfig("example/agent-controller", "123456789012", "us-east-1", 200_000_000),
        )
        now = int(time.time())
        # Synthetic test tariff and accounting evidence, never real reconciliation.
        self.price = PriceCard(MODEL_ID, 400_000, 1_600_000, MODEL_CONTEXT_TOKENS,
                               now - 1, now + 1000, "https://openai.com/api/pricing/", "test:fixture")
        self.transport = Transport()
        self.gateway = LiveModelGateway(self.price, self.ledger, self.transport)
        self.state = Path(self.temp.name) / "service"
        self.broker = Broker(self.state, "test-admin-" + "x" * 32, live_model=self.gateway)
        self.addCleanup(self.broker.close)
        self.created = self.broker.create({"workflow": "recruiting", "live_model": True,
                                          "budget_microusd": 1_000_000})
        self.job = self.broker.job(self.created["job_id"])
        self.token, self.run = self.created["token"], self.created["run_id"]
        self.body = {"operation_id": "model-test-one", "prompt": "Read the assigned fictional record."}

    def reconcile(self, prior=0, outstanding=0):
        self.ledger.reconcile(prior_spent_microusd=prior, outstanding_reserved_microusd=outstanding,
                              evidence_refs=["test:synthetic-baseline"], as_of="2026-01-01T00:00:00Z")

    def call(self, body=None, broker=None):
        return (broker or self.broker).model(self.job, self.token, self.run, body or self.body)

    def test_unreconciled_project_denies_before_provider(self):
        self.assertEqual(self.call()["reason"], "project_budget_denied")
        self.assertEqual(self.transport.calls, [])
        self.assertIsNone(self.ledger.snapshot()["remaining_microusd"])

    def test_shared_project_cap_includes_prior_and_outstanding(self):
        self.reconcile(prior=199_600_000, outstanding=100_000)
        self.assertEqual(self.call()["reason"], "project_budget_denied")
        self.assertEqual(self.transport.calls, [])

    def test_measured_output_settles_both_ledgers_and_replays_once(self):
        self.reconcile()
        first = self.call()
        self.assertEqual(first["status"], "allowed")
        again = self.call()
        self.assertTrue(again["replayed"])
        self.assertEqual(len(self.transport.calls), 1)
        cost = self.price.cost(50, 10)
        project = self.ledger.snapshot()
        snap = self.broker.snapshot(self.job, self.token)
        self.assertEqual((project["spent_microusd"], project["reserved_microusd"]), (cost, 0))
        self.assertEqual((snap["settled_microusd"], snap["reserved_microusd"]), (cost, 0))
        trace = json.dumps(self.broker.trace(self.job))
        self.assertNotIn(self.token, trace)
        self.assertNotIn(self.body["prompt"], trace)
        self.assertIn("provider_measured", trace)

    def test_missing_usage_is_unknown_while_measured_zero_is_zero(self):
        self.reconcile()
        self.transport.callback = lambda: response(usage=False)
        self.assertEqual(self.call()["reason"], "model_outcome_unknown")
        snap = self.ledger.snapshot()
        self.assertEqual(snap["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertIsNone(next(iter(snap["operations"].values()))["actual_cost_microusd"])
        # A different workflow root has independent per-run state but the same
        # global project ledger. Explicit provider zero is measured, not invented.
        created = self.broker.create({"workflow": "recruiting", "live_model": True,
                                      "budget_microusd": 1_000_000})
        self.transport.callback = lambda: response(tokens=(0, 0))
        result = self.broker.model(self.broker.job(created["job_id"]), created["token"], created["run_id"], self.body)
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["receipt"]["usage"]["total_tokens"], 0)

    def test_unknown_transport_survives_restart_without_retry_or_refund(self):
        self.reconcile()
        self.transport.callback = lambda: (_ for _ in ()).throw(TimeoutError("do-not-log-provider-secrets"))
        self.assertEqual(self.call()["reason"], "model_outcome_unknown")
        self.broker.close()
        restarted = Broker(self.state, "test-admin-" + "x" * 32, live_model=self.gateway)
        self.addCleanup(restarted.close)
        self.assertNotEqual(self.call(broker=restarted)["status"], "allowed")
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.ledger.snapshot()["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertNotIn("do-not-log-provider-secrets", json.dumps(restarted.trace(self.job)))

    def test_crash_after_project_reservation_never_dispatches_on_restart(self):
        self.reconcile()
        authority = self.broker.authority(self.job)
        attempt = Attempt(self.body["operation_id"], "model", "model.respond", MODEL_ID, "model-provider",
                          {"prompt": self.body["prompt"], "pricing_pin": self.price.pin})
        reserved = authority.reserve(self.token, attempt)
        import hashlib
        key = "model:" + hashlib.sha256(reserved.ticket.encode()).hexdigest()
        self.ledger.reserve(key, self.gateway.max_cost_microusd, evidence_refs=["pricing:" + self.price.pin])
        self.broker.close()
        restarted = Broker(self.state, "test-admin-" + "x" * 32, live_model=self.gateway)
        self.addCleanup(restarted.close)
        self.assertNotEqual(self.call(broker=restarted)["status"], "allowed")
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.ledger.snapshot()["reserved_microusd"], self.gateway.max_cost_microusd)

    def test_stop_before_request_denies_provider(self):
        self.reconcile()
        self.broker.stop(self.job)
        self.assertEqual(self.call()["reason"], "root_stopped")
        self.assertEqual(self.transport.calls, [])

    def test_stop_between_project_reservation_and_claim_denies_provider(self):
        self.reconcile()
        original = self.ledger.reserve
        def reserve_and_stop(*args, **kwargs):
            result = original(*args, **kwargs)
            self.broker.stop(self.job)
            return result
        with patch.object(self.ledger, "reserve", side_effect=reserve_and_stop):
            self.assertEqual(self.call()["reason"], "root_stopped")
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.ledger.snapshot()["spent_microusd"], 0)
        self.assertEqual(self.ledger.snapshot()["reserved_microusd"], 0)

    def test_stop_inflight_accounts_usage_but_blocks_output(self):
        self.reconcile()
        entered, finish = threading.Event(), threading.Event()
        def blocked():
            entered.set()
            self.assertTrue(finish.wait(3))
            return response()
        self.transport.callback = blocked
        with ThreadPoolExecutor() as pool:
            pending = pool.submit(self.call)
            self.assertTrue(entered.wait(3))
            self.assertEqual(self.call()["reason"], "already_in_flight")
            self.assertEqual(len(self.transport.calls), 1)
            stopped = self.broker.stop(self.job)
            self.assertTrue(stopped["already_in_flight"])
            self.assertTrue(stopped["uncancellable_model_calls"])
            finish.set()
            result = pending.result(timeout=3)
        self.assertEqual(result["status"], "denied")
        self.assertNotIn("receipt", result)
        self.assertGreater(self.ledger.snapshot()["spent_microusd"], 0)
        self.assertEqual(len(self.transport.calls), 1)

    def test_bounds_forbid_prompt_overflow_or_worker_provider_settings(self):
        self.reconcile()
        for body in ({**self.body, "prompt": "x" * (MAX_PROMPT_BYTES + 1)},
                     {**self.body, "prompt": ""}, {**self.body, "model": "other"},
                     {**self.body, "base_url": "https://attacker.invalid"},
                     {**self.body, "max_cost_microusd": 0},
                     {**self.body, "installation": {"limit_microusd": 900_000_000}},
                     {**self.body, "account_id": "210987654321"}):
            with self.subTest(body_fields=list(body)):
                result = self.gateway.respond(self.broker.authority(self.job), self.token, body)
                self.assertEqual(result["reason"], "invalid_model_input")
        self.assertEqual(self.transport.calls, [])

    def test_expired_pricing_and_deadline_each_deny_before_provider(self):
        self.reconcile()
        with patch.object(self.gateway, "clock", return_value=self.price.expires_at):
            self.assertEqual(self.call()["reason"], "verified_pricing_required")
        authority = self.broker.authority(self.job)
        with patch.object(authority, "clock", return_value=self.created["deadline"] + 1):
            self.assertEqual(self.call()["reason"], "expired")
        self.assertEqual(self.transport.calls, [])

    def test_pricing_expiring_during_project_reservation_denies_before_claim(self):
        self.reconcile()
        original = self.ledger.reserve
        def reserve_then_expire(*args, **kwargs):
            result = original(*args, **kwargs)
            self.gateway.clock = lambda: self.price.expires_at
            return result
        with patch.object(self.ledger, "reserve", side_effect=reserve_then_expire):
            self.assertEqual(self.call()["reason"], "verified_pricing_required")
        self.assertEqual(self.transport.calls, [])
        project = self.ledger.snapshot()
        self.assertEqual((project["spent_microusd"], project["reserved_microusd"]), (0, 0))
        snap = self.broker.snapshot(self.job, self.token)
        self.assertEqual(snap["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertEqual(snap["unknown_operations"], [])

    def test_pricing_expiring_during_claim_or_audit_denies_before_transport(self):
        self.reconcile()
        original = self.broker.record
        def record_then_expire(job, run_id, event, **data):
            original(job, run_id, event, **data)
            if event == "model_started":
                self.gateway.clock = lambda: self.price.expires_at
        with patch.object(self.broker, "record", side_effect=record_then_expire):
            self.assertEqual(self.call()["reason"], "verified_pricing_required")
        self.assertEqual(self.transport.calls, [])
        project = self.ledger.snapshot()
        self.assertEqual((project["spent_microusd"], project["reserved_microusd"]), (0, 0))
        snap = self.broker.snapshot(self.job, self.token)
        self.assertEqual(snap["reserved_microusd"], self.gateway.max_cost_microusd)
        self.assertEqual(len(snap["unknown_operations"]), 1)

    def test_job_budget_denies_before_project_or_provider(self):
        self.reconcile()
        created = self.broker.create({"workflow": "recruiting", "live_model": True, "budget_microusd": 1})
        result = self.broker.model(self.broker.job(created["job_id"]), created["token"], created["run_id"], self.body)
        self.assertEqual(result["reason"], "budget_exhausted")
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.ledger.snapshot()["operations"], {})

    def test_unenabled_workflow_and_child_without_model_scope_cannot_call(self):
        self.reconcile()
        created = self.broker.create({"workflow": "recruiting"})
        result = self.broker.model(self.broker.job(created["job_id"]), created["token"], created["run_id"], self.body)
        self.assertEqual(result["reason"], "live_model_disabled")
        child = self.broker.delegate(self.job, self.token, self.run,
                    {"capabilities": [cap for cap in self.created["capabilities"] if cap["action"] == "record.read"],
                     "context_fields": ["record_id", "task"]})
        result = self.broker.model(self.job, child["token"], child["run_id"], self.body)
        self.assertNotEqual(result["status"], "allowed")
        self.assertEqual(self.transport.calls, [])

    def test_invalid_tool_or_usage_never_becomes_a_receipt(self):
        self.reconcile()
        self.transport.callback = lambda: response(output=[{"type": "web_search_call", "id": "x"}])
        self.assertEqual(self.call()["reason"], "model_outcome_unknown")
        self.assertEqual(self.ledger.snapshot()["reserved_microusd"], self.gateway.max_cost_microusd)

    def test_incomplete_provider_responses_never_release_proposals(self):
        for mutate in (
            lambda value: value.update(status="incomplete"),
            lambda value: value.update(incomplete_details={"reason": "max_output_tokens"}),
            lambda value: value.update(error={"code": "server_error"}),
            lambda value: value["output"][0].update(status="in_progress"),
        ):
            value = response()
            mutate(value)
            with self.assertRaises(ValueError):
                self.gateway._receipt(value)

    def test_changed_price_pin_refuses_restart(self):
        changed = LiveModelGateway(replace(self.price, input_microusd_per_million_tokens=500_000),
                                   self.ledger, self.transport)
        self.broker.close()
        with self.assertRaisesRegex(ValueError, "live_model_configuration_required"):
            Broker(self.state, "test-admin-" + "x" * 32, live_model=changed)

    def test_real_transport_configuration_disables_retries_and_hosted_tools(self):
        with patch("openai.OpenAI") as client:
            receiver = OpenAIResponsesTransport("fixture-controller-key")
            receiver("synthetic prompt", "model:fixture")
            options = client.call_args.kwargs
            self.assertEqual(options["max_retries"], 0)
            self.assertEqual(options["base_url"], "https://api.openai.com/v1")
            request = client.return_value.responses.create.call_args.kwargs
            self.assertEqual(request["model"], MODEL_ID)
            self.assertEqual([tool["type"] for tool in request["tools"]], ["function"])
            self.assertEqual(request["tools"][0]["name"], "protected_action")
            self.assertFalse(request["store"])
            self.assertFalse(request["background"])

    def test_provider_rejects_ambient_authentication_headers(self):
        with patch.dict(os.environ, {"OPENAI_CUSTOM_HEADERS": "Authorization: Bearer fixture-only"}):
            with self.assertRaisesRegex(ValueError, "ambient_provider_headers_forbidden"):
                OpenAIResponsesTransport("fixture-controller-key")

    def test_sdk_worker_rejects_provider_or_operator_credential(self):
        import asyncio
        for name in ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY", "OPENAI_CUSTOM_HEADERS",
                     "OPENAI_AGENTS_TRACING_API_KEY", "CONTROLLER_OPENAI_API_KEY", "CONTROLLER_ADMIN_TOKEN",
                     "CONTROLLER_INSTALLATION_CONFIG", "CONTROLLER_PROJECT_LEDGER", "CONTROLLER_LIVE_CONFIG"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "fixture-only"}), \
                    patch("integration.live_worker.ControllerClient") as client:
                result = asyncio.run(run_live("http://127.0.0.1:1", "worker-token"))
                self.assertEqual(result["reason"], "worker_privileged_credential_present")
                client.assert_not_called()

    def test_separate_sdk_live_worker_uses_controller_model_and_protected_tools(self):
        self.reconcile()
        read = {"operation_id": "live-read", "step": "read", "action": "record.read",
                "resource": "candidate-a", "recipient": "worker", "payload": {}}
        write = {"operation_id": "live-write", "step": "write", "action": "report.write",
                 "resource": "candidate-a", "recipient": "internal", "payload": {"summary": "Fictional Python candidate."}}
        outputs = [response(output=[{"type": "function_call", "name": "protected_action", "call_id": "call_read",
                                     "arguments": json.dumps({"proposal_json": json.dumps(read)})}]),
                   response(output=[{"type": "function_call", "name": "protected_action", "call_id": "call_write",
                                     "arguments": json.dumps({"proposal_json": json.dumps(write)})}]), response()]
        self.transport.callback = lambda: outputs.pop(0)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.broker = self.broker
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Minimal environment demonstrates no provider/operator credentials
            # enter the separate worker process, while exercising the actual SDK.
            env = {"PATH": os.environ.get("PATH", ""), "CONTROLLER_WORKER_TOKEN": self.token}
            result = run_sdk_process([sys.executable, "-m", "integration.live_worker",
                                     "--url", f"http://127.0.0.1:{server.server_port}"],
                                    cwd=Path(__file__).resolve().parents[1], env=env,
                                    ready_file=Path(self.temp.name) / "worker-ready.json", timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value["status"], "completed")
            self.assertEqual(value["usage"]["total_tokens"], 180)
            self.assertEqual(len(self.transport.calls), 3)
            self.assertEqual(self.broker.snapshot(self.job, self.token)["effects_count"], 2)
            self.assertNotIn(self.token, result.stdout + result.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_https_client_preserves_verified_tls_and_disables_redirects(self):
        ControllerClient("https://controller.example.test", "fixture-run-token")
        for endpoint in ("http://controller.example.test", "https://user:pass@example.test",
                         "https://example.test/path", "https://example.test?token=secret"):
            with self.assertRaises(ValueError):
                ControllerClient(endpoint, "fixture-run-token")
        from integration.client import _NoRedirect
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.test"))


if __name__ == "__main__":
    unittest.main()
