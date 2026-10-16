"""Offline release-evidence checks. No AWS CLI or live credentials are used."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "aws_readonly.py"
SPEC = importlib.util.spec_from_file_location("aws_readonly", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

from controller.installation import InstallationConfig
INSTALLATION = InstallationConfig(project_id="synthetic-inventory", account_id="123456789012", region="us-west-2", limit_microusd=200_000_000)

def inventory(*args, **kwargs):
    return MODULE.inventory(*args, installation=INSTALLATION, **kwargs)

def call_aws(*args, **kwargs):
    return MODULE.call_aws(*args, installation=INSTALLATION, **kwargs)

def reconciliation(*args, **kwargs):
    return MODULE.reconciliation(*args, installation=INSTALLATION, **kwargs)


class InventoryTests(unittest.TestCase):
    def fake_cli(self, account=INSTALLATION.account_id, failed_service=None):
        calls = []

        def run(command, **_kwargs):
            calls.append(command)
            if command[1] == "sts":
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "Account": account,
                    "Arn": f"arn:aws:sts::{account}:assumed-role/test/session",
                    "UserId": "synthetic",
                }), "")
            if command[1] == failed_service:
                return subprocess.CompletedProcess(command, 255, "", "private auth-helper diagnostic")
            return subprocess.CompletedProcess(command, 0, "[]", "")

        return calls, run

    def test_wrong_account_prevents_all_inventory_calls(self):
        calls, runner = self.fake_cli(account="111111111111")
        report = inventory("fake-aws", runner=runner)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report["inventory"], {})
        self.assertEqual(report["status"], "blocked_identity_unverified_or_wrong_account")

    def test_region_is_explicit_on_every_request_and_no_cost_calls(self):
        calls, runner = self.fake_cli()
        report = inventory("fake-aws", runner=runner)
        self.assertEqual(len(calls), len(MODULE.QUERIES) + 1)
        for command in calls:
            self.assertEqual(command[command.index("--region") + 1], INSTALLATION.region)
            self.assertNotEqual(command[1], "ce")
        self.assertFalse(report["costs_reconciled"])
        self.assertFalse(report["deployment_allowed"])

    def test_denied_inventory_is_unknown_and_diagnostics_not_copied(self):
        _, runner = self.fake_cli(failed_service="ec2")
        report = inventory("fake-aws", runner=runner)
        self.assertEqual(report["status"], "partial_inventory")
        self.assertEqual(report["inventory"]["instances"]["status"], "unknown")
        self.assertNotIn("private auth-helper diagnostic", json.dumps(report))

    def test_write_and_secret_operations_are_rejected_before_cli(self):
        calls, runner = self.fake_cli()
        for service, operation in (("ec2", "run-instances"), ("iam", "create-access-key"),
                                   ("secretsmanager", "get-secret-value"), ("ce", "get-cost-and-usage")):
            with self.assertRaises(ValueError):
                call_aws("fake-aws", service, operation, runner=runner)
        self.assertEqual(calls, [])

    def test_null_query_output_is_unknown_not_empty_inventory(self):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, "null", "")
        result = call_aws("fake-aws", "ec2", "describe-instances", runner=runner)
        self.assertEqual(result["status"], "unknown")


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.document = json.loads((MODULE_PATH.parent / "reconcile.example.json").read_text())
        self.document.update(project=INSTALLATION.project_id, account_id=INSTALLATION.account_id, region=INSTALLATION.region, total_project_ceiling="200.00", as_of_utc=datetime.now(timezone.utc).isoformat(),
                             project_history_start_date="2026-10-01", reviewed_by="synthetic-test-reviewer")
        self.document["coverage"] = {key: True for key in MODULE.COVERAGE}
        self.document["historical_project_names_and_tags"] = [INSTALLATION.project_id]
        self.document.update({key: "0.00" for key in MODULE.AMOUNTS})
        self.document.update(settled_aws_usd="80.00", settled_openai_usd="20.00",
                             outstanding_reservations_not_in_settled_usd="50.00",
                             proposed_new_package_and_test_upper_bound_usd="30.00")
        evidence = []
        for source in ("aws_billing", "openai_billing", "reservation_ledger", "lifecycle_estimate"):
            path = self.directory / (source + ".txt")
            content = b"SYNTHETIC TEST FIXTURE; NOT REAL COST EVIDENCE"
            path.write_bytes(content)
            evidence.append({"source": source, "path": path.name,
                             "sha256": hashlib.sha256(content).hexdigest()})
        self.document["evidence_files"] = evidence

    def check_document(self):
        return reconciliation(self.document, self.directory)

    def test_complete_arithmetic_counts_prior_cost_and_reservations(self):
        result = self.check_document()
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["remaining_after_proposed_package_usd"], "20.00")
        self.assertFalse(result["paid_testing_allowed"])
        self.assertFalse(result["deployment_allowed"])
        self.assertFalse(result["evidence_authenticity_verified"])

    def test_total_ceiling_is_not_a_new_run_allowance(self):
        self.document["proposed_new_package_and_test_upper_bound_usd"] = "100.00"
        result = self.check_document()
        self.assertIn("project_ceiling_exceeded", result["reasons"])
        self.assertEqual(result["remaining_after_proposed_package_usd"], "-50.00")

    def test_null_unknown_and_unbounded_usage_fail_closed(self):
        self.document["unbilled_or_unknown_upper_bound_not_reserved_usd"] = None
        self.document["coverage"]["billing_lag_and_unknown_usage_bounded"] = False
        result = self.check_document()
        self.assertIn("amount_unknown_or_invalid:unbilled_or_unknown_upper_bound_not_reserved_usd", result["reasons"])
        self.assertIsNone(result["remaining_after_proposed_package_usd"])

    def test_modified_evidence_fails_hash_validation(self):
        (self.directory / "aws_billing.txt").write_text("modified")
        self.assertIn("evidence_file_missing_or_hash_mismatch", self.check_document()["reasons"])

    def test_stale_evidence_and_changed_account_are_blocked(self):
        self.document["as_of_utc"] = "2000-01-01T00:00:00+00:00"
        self.document["account_id"] = "111111111111"
        result = self.check_document()
        self.assertIn("scope_mismatch", result["reasons"])
        self.assertIn("reconciliation_older_than_24h_or_future", result["reasons"])

    def test_negative_nonfinite_and_json_float_are_not_costs(self):
        for invalid in ("-1.00", "NaN", "Infinity", 0.0, None):
            with self.subTest(amount=invalid), self.assertRaises(ValueError):
                MODULE.money(invalid)

    def test_unknown_template_cannot_pass(self):
        document = json.loads((MODULE_PATH.parent / "reconcile.example.json").read_text())
        result = reconciliation(document, self.directory)
        self.assertEqual(result["status"], "blocked_incomplete_reconciliation")
        self.assertFalse(result["paid_testing_allowed"])

    def test_report_permissions_and_no_overwrite(self):
        output = self.directory / "report.json"
        MODULE.write_report(output, {"synthetic": True})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            MODULE.write_report(output, {"synthetic": False})
        self.assertEqual(json.loads(output.read_text()), {"synthetic": True})


if __name__ == "__main__":
    unittest.main()
