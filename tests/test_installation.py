"""Owner configuration and durable budget identity; no cloud or provider calls."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from controller.installation import (InstallationConfig, InstallationConfigError,
                                     MAX_CONFIG_BYTES, load_installation)
from controller.project_budget import BudgetConflict, ProjectBudgetLedger, main
from controller.service import configured_live_model


OWNER = InstallationConfig("example/personal-controller", "123456789012", "us-east-1", 200_000_000)


def config_file(tmp_path, value=None):
    path = tmp_path / "installation.json"
    path.write_text(json.dumps(OWNER.as_dict() if value is None else value))
    path.chmod(0o600)
    return path


def test_loader_requires_explicit_owner_and_observed_account_match(tmp_path):
    config = load_installation(config_file(tmp_path))
    assert config == OWNER
    config.assert_target("123456789012", "us-east-1")
    for target in (("210987654321", "us-east-1"), ("123456789012", "us-west-2")):
        with pytest.raises(InstallationConfigError, match="installation_target_mismatch"):
            config.assert_target(*target)
    with pytest.raises(FrozenInstanceError):
        config.limit_microusd = 900_000_000


@pytest.mark.parametrize("changed", [
    {"schema_version": True}, {"schema_version": 2}, {"worker_token": "private-canary"},
    {"account_id": "123"}, {"account_id": "000000000000"}, {"account_id": 123456789012},
    {"region": "https://untrusted.invalid"}, {"project_id": "not\na-project"},
    {"project_id": "sk-proj-" + "x" * 40},
    {"limit_microusd": 0}, {"limit_microusd": -1}, {"limit_microusd": True},
    {"limit_microusd": "200000000"}, {"limit_microusd": 1.5}, {"limit_microusd": 2**63},
])
def test_unknown_worker_fields_or_invalid_identity_are_rejected_without_echo(tmp_path, changed):
    with pytest.raises(InstallationConfigError) as error:
        load_installation(config_file(tmp_path, OWNER.as_dict() | changed))
    assert "private-canary" not in str(error.value)
    assert "sk-proj-" not in str(error.value)


def test_missing_and_duplicate_fields_cannot_override_the_owner(tmp_path):
    value = OWNER.as_dict()
    del value["limit_microusd"]
    with pytest.raises(InstallationConfigError):
        load_installation(config_file(tmp_path, value))
    path = config_file(tmp_path)
    path.write_text(path.read_text().removesuffix("}") + ',"limit_microusd":999999999}')
    with pytest.raises(InstallationConfigError):
        load_installation(path)


def test_loader_refuses_relative_symlink_writable_and_nonregular_files(tmp_path):
    path = config_file(tmp_path)
    with pytest.raises(InstallationConfigError, match="absolute_installation"):
        load_installation(Path("installation.json"))
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    with pytest.raises(InstallationConfigError, match="trusted_installation"):
        load_installation(link)
    for mode in (0o620, 0o602, 0o666):
        path.chmod(mode)
        with pytest.raises(InstallationConfigError, match="trusted_installation"):
            load_installation(path)
    with pytest.raises(InstallationConfigError, match="trusted_installation"):
        load_installation(tmp_path)
    pipe = tmp_path / "untrusted-pipe"
    os.mkfifo(pipe)
    with pytest.raises(InstallationConfigError, match="trusted_installation"):
        load_installation(pipe)


def test_foreign_owner_and_oversized_configuration_are_rejected(tmp_path):
    path = config_file(tmp_path)
    metadata = path.stat()
    fake = SimpleNamespace(st_mode=metadata.st_mode, st_size=metadata.st_size,
                           st_uid=os.geteuid() + 12345)
    with patch("controller.installation.os.fstat", return_value=fake):
        with pytest.raises(InstallationConfigError, match="trusted_installation"):
            load_installation(path)
    path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(InstallationConfigError, match="trusted_installation"):
        load_installation(path)


def test_ledger_requires_typed_installation_and_immutable_configured_cap(tmp_path):
    path = tmp_path / "budget.sqlite"
    with pytest.raises(BudgetConflict):
        ProjectBudgetLedger(path, installation=OWNER.as_dict())
    assert not path.exists()
    smaller = replace(OWNER, account_id="210987654321", region="us-west-2", limit_microusd=7)
    ledger = ProjectBudgetLedger.create_new(path, installation=smaller)
    assert ledger.snapshot()["limit_microusd"] == 7
    ledger.reconcile(prior_spent_microusd=2, outstanding_reserved_microusd=3,
                     evidence_refs=["test:synthetic-baseline"], as_of="2026-01-01T00:00:00Z")
    assert ledger.reserve("fits", 2, ["test:synthetic-maximum"])["approved"] is True
    assert ledger.reserve("over", 1, ["test:synthetic-maximum"])["approved"] is False
    before = ledger.snapshot()
    with pytest.raises(BudgetConflict):
        ProjectBudgetLedger.open_existing(path, installation=replace(smaller, limit_microusd=8))
    assert ledger.snapshot() == before


def test_existing_empty_or_missing_ledger_is_never_initialized_by_reopen(tmp_path):
    path = tmp_path / "budget.sqlite"
    with pytest.raises(BudgetConflict):
        ProjectBudgetLedger.open_existing(path, installation=OWNER)
    assert not path.exists()
    path.touch()
    with pytest.raises(BudgetConflict):
        ProjectBudgetLedger(path, installation=OWNER)
    assert path.read_bytes() == b""


def test_bound_ledger_rejects_external_identity_changes_before_new_spending(tmp_path):
    path = tmp_path / "budget.sqlite"
    ledger = ProjectBudgetLedger(path, installation=OWNER)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE project_budget SET limit_microusd=300000000")
    with pytest.raises(BudgetConflict):
        ledger.reserve("blocked", 1, ["test:synthetic-maximum"])


def test_legacy_schema_preserves_cap_prior_costs_holds_and_stop_without_migration(tmp_path):
    path = tmp_path / "legacy-budget.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE project_budget (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                project_id TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
                limit_microusd INTEGER NOT NULL CHECK(limit_microusd=200000000),
                prior_spent INTEGER, external_reserved INTEGER, reconciliation TEXT,
                stopped INTEGER NOT NULL DEFAULT 0, stop_reason TEXT);
            CREATE TABLE project_operations (
                operation_id TEXT PRIMARY KEY, maximum INTEGER NOT NULL CHECK(maximum>0),
                status TEXT NOT NULL, actual INTEGER, reserve_evidence TEXT NOT NULL,
                outcome_evidence TEXT, created_at TEXT NOT NULL);
            CREATE TABLE project_budget_trace (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                event TEXT NOT NULL, operation_id TEXT, details TEXT NOT NULL);
        """)
        connection.execute("INSERT INTO project_budget VALUES(1,?,?,?,?,?,?,?,1,?)",
                           (*OWNER.identity, 1_234_567, 4_000_000, json.dumps({"source": "test:legacy"}), "test:legacy-stop"))
        connection.execute("INSERT INTO project_operations VALUES(?,?,?,?,?,?,?)",
                           ("synthetic-pending", 2000000, "unknown", None, '["test:legacy-hold"]',
                            '["test:unknown-outcome"]', "2026-01-01T00:00:00Z"))
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE name='project_budget'").fetchone()[0]
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    ledger = ProjectBudgetLedger.open_existing(path, installation=OWNER)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    snapshot = ledger.snapshot()
    assert snapshot["limit_microusd"] == 200_000_000
    assert snapshot["spent_microusd"] == 1_234_567
    assert snapshot["reserved_microusd"] == 6_000_000
    assert snapshot["stopped"] is True
    assert snapshot["stop_reason"] == "test:legacy-stop"
    assert snapshot["operations"]["synthetic-pending"]["status"] == "unknown"
    assert ledger.reserve("no-reset", 1, ["test:synthetic-maximum"])["approved"] is False
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT sql FROM sqlite_master WHERE name='project_budget'").fetchone()[0] == schema
    with pytest.raises(BudgetConflict):
        ProjectBudgetLedger.open_existing(path, installation=replace(OWNER, limit_microusd=300_000_000))
    assert ledger.snapshot() == snapshot


def test_cli_init_requires_new_path_and_does_not_invent_reconciliation(tmp_path, capsys):
    path = tmp_path / "budget.sqlite"
    args = ["init", "--installation", str(config_file(tmp_path)), "--ledger", str(path)]
    assert main(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "initialized_unreconciled"
    assert output["reconciled"] is False
    assert output["remaining_microusd"] is None
    assert output["operations"] == {}
    assert path.stat().st_mode & 0o077 == 0
    before = path.read_bytes()
    with pytest.raises(BudgetConflict):
        main(args)
    assert path.read_bytes() == before


def test_live_startup_requires_operator_config_matching_existing_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROLLER_LIVE_CONFIG", "/synthetic/unused-price-card.json")
    monkeypatch.delenv("CONTROLLER_INSTALLATION_CONFIG", raising=False)
    with pytest.raises(ValueError, match="trusted_installation"):
        configured_live_model()
    installation_path = config_file(tmp_path)
    monkeypatch.setenv("CONTROLLER_INSTALLATION_CONFIG", str(installation_path))
    path = tmp_path / "budget.sqlite"
    monkeypatch.setenv("CONTROLLER_PROJECT_LEDGER", str(path))
    with pytest.raises(ValueError, match="existing_project_ledger"):
        configured_live_model()
    assert not path.exists()
    ledger = ProjectBudgetLedger(path, installation=OWNER)
    ledger.stop("test:stopped", ["test:unknown-billing"])
    with patch("controller.live_model.LiveModelGateway.from_environment", return_value="synthetic-gateway") as factory:
        assert configured_live_model() == "synthetic-gateway"
        assert factory.call_args.args[0].snapshot()["stopped"] is True
        installation_path.write_text(json.dumps(replace(OWNER, account_id="210987654321").as_dict()))
        with pytest.raises(BudgetConflict):
            configured_live_model()
        assert factory.call_count == 1


def test_synthetic_mode_needs_no_owner_or_paid_configuration(monkeypatch):
    monkeypatch.delenv("CONTROLLER_LIVE_CONFIG", raising=False)
    monkeypatch.setenv("CONTROLLER_INSTALLATION_CONFIG", "/untrusted/not-read")
    assert configured_live_model() is None
