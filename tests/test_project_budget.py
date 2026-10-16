"""Project-wide accounting regressions using only local SQLite and fictional costs.

These checks establish durable admission accounting, not provider-side spending
enforcement, billing completeness, operator identity, or database access control.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import json
from pathlib import Path
import select
import subprocess
import sys
import threading

import pytest

from controller.installation import InstallationConfig
from controller.project_budget import BudgetConflict, ProjectBudgetLedger


IDENTITY = {
    "project_id": "example/agent-controller",
    "account_id": "123456789012",
    "region": "us-east-1",
}
INSTALLATION = InstallationConfig(**IDENTITY, limit_microusd=200_000_000)
AS_OF = "2026-10-15T00:00:00+00:00"
BASELINE_EVIDENCE = ("evidence:billing/baseline-2026-10-15",)
ESTIMATE_EVIDENCE = ("evidence:estimate/operation-maximum",)
OUTCOME_EVIDENCE = ("evidence:receipt/observed-cost",)
UNKNOWN_EVIDENCE = ("evidence:incident/provider-outcome-unknown",)


@pytest.fixture
def ledger(tmp_path):
    return ProjectBudgetLedger(tmp_path / "project-budget.sqlite", installation=INSTALLATION)


def reconcile(ledger, spent=0, reserved=0):
    return ledger.reconcile(
        prior_spent_microusd=spent,
        outstanding_reserved_microusd=reserved,
        evidence_refs=BASELINE_EVIDENCE,
        as_of=AS_OF,
    )


def reserve(ledger, operation_id="operation-1", maximum=10_000_000):
    return ledger.reserve(operation_id, maximum, ESTIMATE_EVIDENCE)


def assert_totals(ledger, *, spent, reserved, exposure, remaining):
    snapshot = ledger.snapshot()
    assert snapshot["spent_microusd"] == spent
    assert snapshot["reserved_microusd"] == reserved
    assert snapshot["exposure_microusd"] == exposure
    assert snapshot["remaining_microusd"] == remaining
    return snapshot


def test_unknown_baseline_is_not_reported_as_zero_or_available_budget(ledger):
    snapshot = ledger.snapshot()
    assert INSTALLATION.limit_microusd == 200_000_000
    assert {key: snapshot[key] for key in IDENTITY} == IDENTITY
    assert snapshot["limit_microusd"] == 200_000_000
    assert snapshot["reconciled"] is False
    for key in (
        "prior_spent_microusd", "external_reserved_microusd", "spent_microusd",
        "reserved_microusd", "exposure_microusd", "remaining_microusd",
    ):
        assert snapshot[key] is None
    assert snapshot["operations"] == {}
    assert reserve(ledger)["approved"] is False
    assert ledger.snapshot()["operations"] == {}


def test_prior_external_and_local_costs_share_one_fixed_project_limit(ledger):
    reconcile(ledger, spent=120_000_000, reserved=30_000_000)
    assert reserve(ledger, "first", 20_000_000)["approved"] is True
    assert reserve(ledger, "second", 30_000_000)["approved"] is True
    snapshot = assert_totals(
        ledger, spent=120_000_000, reserved=80_000_000,
        exposure=200_000_000, remaining=0,
    )
    assert snapshot["prior_spent_microusd"] == 120_000_000
    assert snapshot["external_reserved_microusd"] == 30_000_000
    assert reserve(ledger, "one-more-microusd", 1)["approved"] is False
    assert set(ledger.snapshot()["operations"]) == {"first", "second"}


@pytest.mark.parametrize("maximum", [0, -1, True, False, 1.5, "100", None])
def test_reservations_require_a_positive_integer_maximum(ledger, maximum):
    reconcile(ledger)
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        reserve(ledger, maximum=maximum)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("operation_id", ["", " ", "has\nnewline", None, 42, True])
def test_operation_id_must_be_a_nonempty_reference(ledger, operation_id):
    reconcile(ledger)
    with pytest.raises(ValueError):
        reserve(ledger, operation_id=operation_id)
    assert ledger.snapshot()["operations"] == {}


@pytest.mark.parametrize("field", ["prior_spent_microusd", "outstanding_reserved_microusd"])
@pytest.mark.parametrize("invalid", [-1, True, False, 0.5, "0", None])
def test_reconciliation_requires_nonnegative_integer_costs(ledger, field, invalid):
    arguments = {
        "prior_spent_microusd": 0,
        "outstanding_reserved_microusd": 0,
        "evidence_refs": BASELINE_EVIDENCE,
        "as_of": AS_OF,
    }
    arguments[field] = invalid
    with pytest.raises(ValueError):
        ledger.reconcile(**arguments)
    assert ledger.snapshot()["reconciled"] is False


@pytest.mark.parametrize("as_of", [None, "", "yesterday", "2026-10-15", "2026-10-15T00:00:00"])
def test_reconciliation_requires_an_explicit_aware_timestamp(ledger, as_of):
    with pytest.raises(ValueError):
        ledger.reconcile(prior_spent_microusd=0, outstanding_reserved_microusd=0,
                         evidence_refs=BASELINE_EVIDENCE, as_of=as_of)
    assert ledger.snapshot()["reconciled"] is False


@pytest.mark.parametrize("evidence", [[], (), None, "evidence:billing/baseline", [""], [" "], [None]])
def test_reconciliation_requires_evidence_references(ledger, evidence):
    with pytest.raises(ValueError):
        ledger.reconcile(prior_spent_microusd=0, outstanding_reserved_microusd=0,
                         evidence_refs=evidence, as_of=AS_OF)
    assert ledger.snapshot()["reconciled"] is False


def test_future_timestamp_cannot_claim_completed_billing_reconciliation(ledger):
    with pytest.raises(ValueError):
        ledger.reconcile(prior_spent_microusd=0, outstanding_reserved_microusd=0,
                         evidence_refs=BASELINE_EVIDENCE, as_of="9999-01-01T00:00:00+00:00")
    assert ledger.snapshot()["reconciled"] is False


@pytest.mark.parametrize("changed", [
    {"project_id": "other/project"},
    {"account_id": "210987654321"},
    {"region": "us-west-2"},
])
def test_existing_project_identity_cannot_be_changed(tmp_path, changed):
    path = tmp_path / "project-budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=INSTALLATION)
    reconcile(ledger, spent=80_000_000)
    with pytest.raises(BudgetConflict):
        ProjectBudgetLedger(path, installation=replace(INSTALLATION, **changed))
    assert ProjectBudgetLedger(path, installation=INSTALLATION).snapshot() == ledger.snapshot()


def test_duplicate_reservation_does_not_approve_another_execution_or_charge_twice(ledger):
    reconcile(ledger)
    first = reserve(ledger)
    before = ledger.snapshot()
    duplicate = reserve(ledger)
    assert first["approved"] is True
    assert duplicate["approved"] is False
    assert duplicate["reason"] == "already_reserved"
    assert duplicate["operation"] == first["operation"]
    assert ledger.snapshot() == before


@pytest.mark.parametrize("changed", [
    {"max_cost_microusd": 11_000_000},
    {"evidence_refs": ("evidence:estimate/changed-maximum",)},
])
def test_changed_reservation_payload_is_an_idempotency_conflict(ledger, changed):
    reconcile(ledger)
    reserve(ledger)
    before = ledger.snapshot()
    arguments = {
        "operation_id": "operation-1",
        "max_cost_microusd": 10_000_000,
        "evidence_refs": ESTIMATE_EVIDENCE,
    }
    result = ledger.reserve(**(arguments | changed))
    assert result["approved"] is False
    assert result["reason"] == "idempotency_conflict"
    assert ledger.snapshot() == before


def test_unknown_outcome_retains_full_maximum_until_known_settlement(ledger):
    reconcile(ledger, spent=150_000_000, reserved=10_000_000)
    assert reserve(ledger, maximum=40_000_000)["approved"] is True
    ledger.mark_unknown("operation-1", UNKNOWN_EVIDENCE)
    assert_totals(ledger, spent=150_000_000, reserved=50_000_000,
                  exposure=200_000_000, remaining=0)
    duplicate = reserve(ledger, maximum=40_000_000)
    assert duplicate["approved"] is False
    assert duplicate["reason"] == "outcome_unknown"
    assert reserve(ledger, "another", 1)["approved"] is False
    ledger.settle("operation-1", 15_000_000, OUTCOME_EVIDENCE)
    assert_totals(ledger, spent=165_000_000, reserved=10_000_000,
                  exposure=175_000_000, remaining=25_000_000)


def test_known_actual_releases_only_unused_local_reservation(ledger):
    reconcile(ledger, spent=100_000_000, reserved=20_000_000)
    reserve(ledger, "settled", 30_000_000)
    reserve(ledger, "still-pending", 40_000_000)
    ledger.settle("settled", 12_000_000, OUTCOME_EVIDENCE)
    snapshot = assert_totals(ledger, spent=112_000_000, reserved=60_000_000,
                             exposure=172_000_000, remaining=28_000_000)
    assert snapshot["external_reserved_microusd"] == 20_000_000
    assert reserve(ledger, "released-capacity", 28_000_000)["approved"] is True
    assert reserve(ledger, "excess", 1)["approved"] is False


def test_zero_actual_is_a_valid_known_result(ledger):
    reconcile(ledger)
    reserve(ledger)
    ledger.settle("operation-1", 0, OUTCOME_EVIDENCE)
    assert_totals(ledger, spent=0, reserved=0, exposure=0, remaining=200_000_000)


@pytest.mark.parametrize("actual", [-1, True, False, 1.25, "1", None])
def test_invalid_settlement_never_releases_the_reservation(ledger, actual):
    reconcile(ledger)
    reserve(ledger)
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.settle("operation-1", actual, OUTCOME_EVIDENCE)
    assert ledger.snapshot() == before


def test_same_settlement_is_idempotent_and_changed_actual_cannot_refund_history(ledger):
    reconcile(ledger, spent=20_000_000, reserved=5_000_000)
    reserve(ledger)
    ledger.settle("operation-1", 7_000_000, OUTCOME_EVIDENCE)
    before = ledger.snapshot()
    ledger.settle("operation-1", 7_000_000, OUTCOME_EVIDENCE)
    assert ledger.snapshot() == before
    with pytest.raises(BudgetConflict):
        ledger.settle("operation-1", 0, OUTCOME_EVIDENCE)
    assert ledger.snapshot() == before
    duplicate = reserve(ledger)
    assert duplicate["approved"] is False
    assert duplicate["reason"] == "already_settled"


def test_settled_operation_cannot_be_made_unknown_again(ledger):
    reconcile(ledger)
    reserve(ledger)
    ledger.settle("operation-1", 7_000_000, OUTCOME_EVIDENCE)
    before = ledger.snapshot()
    with pytest.raises(BudgetConflict):
        ledger.mark_unknown("operation-1", UNKNOWN_EVIDENCE)
    assert ledger.snapshot() == before


def test_overrun_records_the_real_cost_and_stops_new_work_even_below_project_cap(ledger):
    reconcile(ledger)
    reserve(ledger)
    ledger.settle("operation-1", 11_000_000, OUTCOME_EVIDENCE)
    snapshot = assert_totals(ledger, spent=11_000_000, reserved=0,
                             exposure=11_000_000, remaining=189_000_000)
    assert snapshot["stopped"] is True
    assert reserve(ledger, "next", 1)["approved"] is False
    ledger.settle("operation-1", 11_000_000, OUTCOME_EVIDENCE)
    assert ledger.snapshot() == snapshot
    with pytest.raises(BudgetConflict):
        ledger.settle("operation-1", 10_000_000, OUTCOME_EVIDENCE)


def test_overrun_is_never_capped_or_discarded_to_make_accounting_look_safe(ledger):
    reconcile(ledger, spent=190_000_000)
    reserve(ledger)
    ledger.settle("operation-1", 12_000_000, OUTCOME_EVIDENCE)
    snapshot = ledger.snapshot()
    assert snapshot["spent_microusd"] == 202_000_000
    assert snapshot["exposure_microusd"] == 202_000_000
    assert snapshot["reserved_microusd"] == 0
    assert snapshot["stopped"] is True
    assert reserve(ledger, "next", 1)["approved"] is False


def test_stopped_ledger_still_records_other_actual_costs_without_clearing_stop(ledger):
    reconcile(ledger, spent=30_000_000, reserved=5_000_000)
    reserve(ledger, "overrun", 10_000_000)
    reserve(ledger, "already-in-flight", 20_000_000)
    ledger.settle("overrun", 11_000_000, OUTCOME_EVIDENCE)
    assert ledger.snapshot()["stopped"] is True
    ledger.settle("already-in-flight", 12_000_000, OUTCOME_EVIDENCE)
    before = assert_totals(ledger, spent=53_000_000, reserved=5_000_000,
                           exposure=58_000_000, remaining=142_000_000)
    assert before["stopped"] is True
    reconcile(ledger, spent=30_000_000, reserved=5_000_000)
    assert ledger.snapshot() == before
    assert reserve(ledger, "after-reconciliation-replay", 1)["approved"] is False


@pytest.mark.parametrize("spent,reserved", [(200_000_001, 0), (190_000_000, 20_000_000)])
def test_accurate_over_limit_baseline_is_recorded_and_stopped(ledger, spent, reserved):
    reconcile(ledger, spent=spent, reserved=reserved)
    snapshot = ledger.snapshot()
    assert snapshot["reconciled"] is True
    assert snapshot["stopped"] is True
    assert snapshot["spent_microusd"] == spent
    assert snapshot["reserved_microusd"] == reserved
    assert snapshot["exposure_microusd"] == spent + reserved
    assert reserve(ledger, "next", 1)["approved"] is False


def test_reconciliation_exact_replay_does_not_double_count_later_operations(ledger):
    reconcile(ledger, spent=50_000_000, reserved=20_000_000)
    reserve(ledger)
    ledger.settle("operation-1", 7_000_000, OUTCOME_EVIDENCE)
    before = ledger.snapshot()
    reconcile(ledger, spent=50_000_000, reserved=20_000_000)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("changed", [
    {"prior_spent_microusd": 0},
    {"outstanding_reserved_microusd": 0},
    {"evidence_refs": ("evidence:billing/replacement-baseline",)},
    {"as_of": "2026-10-14T00:00:00+00:00"},
])
def test_reconciliation_cannot_reset_or_replace_the_initial_baseline(ledger, changed):
    reconcile(ledger, spent=150_000_000, reserved=30_000_000)
    reserve(ledger)
    before = ledger.snapshot()
    arguments = {
        "prior_spent_microusd": 150_000_000,
        "outstanding_reserved_microusd": 30_000_000,
        "evidence_refs": BASELINE_EVIDENCE,
        "as_of": AS_OF,
    }
    with pytest.raises(BudgetConflict):
        ledger.reconcile(**(arguments | changed))
    assert ledger.snapshot() == before


def test_reservations_settlements_unknowns_and_stop_survive_restart(tmp_path):
    path = tmp_path / "project-budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=INSTALLATION)
    reconcile(ledger, spent=20_000_000, reserved=5_000_000)
    reserve(ledger, "unknown", 20_000_000)
    ledger.mark_unknown("unknown", UNKNOWN_EVIDENCE)
    reserve(ledger, "overrun", 10_000_000)
    ledger.settle("overrun", 11_000_000, OUTCOME_EVIDENCE)
    before = ledger.snapshot()
    restarted = ProjectBudgetLedger(path, installation=INSTALLATION)
    assert restarted.snapshot() == before
    assert before["stopped"] is True
    assert before["spent_microusd"] == 31_000_000
    assert before["reserved_microusd"] == 25_000_000
    assert reserve(restarted, "new-after-restart", 1)["approved"] is False
    with pytest.raises(BudgetConflict):
        reconcile(restarted)
    assert restarted.snapshot() == before


def test_operator_stop_survives_restart_and_preserves_every_liability(tmp_path):
    path = tmp_path / "project-budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=INSTALLATION)
    reconcile(ledger, spent=50_000_000, reserved=20_000_000)
    reserve(ledger, "pending", 30_000_000)
    reserve(ledger, "settled", 10_000_000)
    ledger.settle("settled", 7_000_000, OUTCOME_EVIDENCE)
    stopped = ledger.stop("incident:unreconciled-external-cost", UNKNOWN_EVIDENCE)
    assert stopped["stopped"] is True
    restarted = ProjectBudgetLedger(path, installation=INSTALLATION)
    assert restarted.snapshot() == stopped
    assert_totals(restarted, spent=57_000_000, reserved=50_000_000,
                  exposure=107_000_000, remaining=93_000_000)
    assert reserve(restarted, "after-operator-stop", 1)["approved"] is False
    reconcile(restarted, spent=50_000_000, reserved=20_000_000)
    assert restarted.snapshot() == stopped


def test_reconciliation_cannot_clear_an_operator_stop_set_before_bootstrap(tmp_path):
    path = tmp_path / "project-budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=INSTALLATION)
    ledger.stop("incident:unknown-prior-cost", UNKNOWN_EVIDENCE)
    restarted = ProjectBudgetLedger(path, installation=INSTALLATION)
    assert restarted.snapshot()["stopped"] is True
    assert restarted.snapshot()["reconciled"] is False
    reconcile(restarted, spent=50_000_000, reserved=20_000_000)
    snapshot = assert_totals(restarted, spent=50_000_000, reserved=20_000_000,
                             exposure=70_000_000, remaining=130_000_000)
    assert snapshot["stopped"] is True
    assert reserve(restarted, "after-stopped-bootstrap", 1)["approved"] is False


def test_concurrent_independent_connections_cannot_oversubscribe_remaining_budget(tmp_path):
    path = tmp_path / "project-budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=INSTALLATION)
    reconcile(ledger, spent=190_000_000, reserved=4_000_000)
    contenders = 8
    barrier = threading.Barrier(contenders)

    def contend(index):
        independent = ProjectBudgetLedger(path, installation=INSTALLATION)
        barrier.wait(timeout=10)
        return reserve(independent, f"concurrent-{index}", 3_000_000)

    with ThreadPoolExecutor(max_workers=contenders) as pool:
        results = list(pool.map(contend, range(contenders)))
    assert sum(result["approved"] for result in results) == 2
    snapshot = assert_totals(ledger, spent=190_000_000, reserved=10_000_000,
                             exposure=200_000_000, remaining=0)
    assert len(snapshot["operations"]) == 2


def test_concurrent_replays_approve_exactly_one_execution(tmp_path):
    path = tmp_path / "project-budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=INSTALLATION)
    reconcile(ledger)
    contenders = 8
    barrier = threading.Barrier(contenders)

    def contend(_index):
        independent = ProjectBudgetLedger(path, installation=INSTALLATION)
        barrier.wait(timeout=10)
        return reserve(independent, "one-logical-operation", 10_000_000)

    with ThreadPoolExecutor(max_workers=contenders) as pool:
        results = list(pool.map(contend, range(contenders)))
    assert sum(result["approved"] for result in results) == 1
    assert [result["reason"] for result in results].count("already_reserved") == contenders - 1
    snapshot = assert_totals(ledger, spent=0, reserved=10_000_000,
                             exposure=10_000_000, remaining=190_000_000)
    assert set(snapshot["operations"]) == {"one-logical-operation"}


def test_separate_processes_share_capacity_and_fresh_process_observes_persisted_state(tmp_path):
    path = tmp_path / "project-budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=INSTALLATION)
    reconcile(ledger, spent=190_000_000, reserved=4_000_000)
    child_script = """
import json
import sys
from controller.project_budget import ProjectBudgetLedger
from controller.installation import InstallationConfig
ledger = ProjectBudgetLedger(sys.argv[1], installation=InstallationConfig(**json.loads(sys.argv[3])))
print("ready", flush=True)
if sys.stdin.readline() != "go\\n":
    raise RuntimeError("Test start barrier was not released")
print(json.dumps(ledger.reserve(sys.argv[2], 3000000, ["evidence:estimate/process-race"])), flush=True)
"""
    processes = []
    try:
        for index in range(6):
            processes.append(subprocess.Popen(
                [sys.executable, "-c", child_script, str(path), f"process-{index}", json.dumps(asdict(INSTALLATION))],
                cwd=Path(__file__).resolve().parents[1], text=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ))
        pending = {process.stdout for process in processes}
        while pending:
            readable, _, _ = select.select(list(pending), [], [], 15)
            assert readable, "A child process did not reach the reservation barrier"
            for stream in readable:
                assert stream.readline() == "ready\n"
                pending.remove(stream)
        for process in processes:
            process.stdin.write("go\n")
            process.stdin.flush()
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stderr
            results.append(json.loads(stdout))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
    assert sum(result["approved"] for result in results) == 2
    snapshot = assert_totals(ledger, spent=190_000_000, reserved=10_000_000,
                             exposure=200_000_000, remaining=0)
    assert len(snapshot["operations"]) == 2
    restarted = subprocess.run(
        [sys.executable, "-c",
         "import json,sys; from controller.project_budget import ProjectBudgetLedger; "
         "from controller.installation import InstallationConfig; "
         "print(json.dumps(ProjectBudgetLedger(sys.argv[1], installation=InstallationConfig(**json.loads(sys.argv[2]))).snapshot()))",
         str(path), json.dumps(asdict(INSTALLATION))],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=15,
    )
    assert restarted.returncode == 0, restarted.stderr
    assert json.loads(restarted.stdout) == snapshot


@pytest.mark.parametrize("secret_reference", [
    "sk-proj-" + "x" * 40,
    "AKIA" + "A" * 16,
    "ghp_" + "a" * 36,
])
@pytest.mark.parametrize("method", ["reconcile", "reserve", "mark_unknown", "settle"])
def test_known_credential_patterns_are_rejected_before_they_enter_evidence(ledger, method, secret_reference):
    if method != "reconcile":
        reconcile(ledger)
    if method in {"mark_unknown", "settle"}:
        reserve(ledger)
    before = ledger.snapshot()
    references = (secret_reference,)
    with pytest.raises(ValueError):
        if method == "reconcile":
            ledger.reconcile(prior_spent_microusd=0, outstanding_reserved_microusd=0,
                             evidence_refs=references, as_of=AS_OF)
        elif method == "reserve":
            ledger.reserve("operation-1", 10_000_000, references)
        elif method == "mark_unknown":
            ledger.mark_unknown("operation-1", references)
        else:
            ledger.settle("operation-1", 5_000_000, references)
    assert ledger.snapshot() == before
