"""The production preflight must reject before bootstrap, recovery or serving."""
import fcntl
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from controller.service import Broker, main, state_startup_check
from deploy.state_guard import StateGuardError


ADMIN = "synthetic-guarded-startup-admin-token"


@pytest.fixture(autouse=True)
def preserve_umask():
    previous = os.umask(0o077)
    os.umask(previous)
    try:
        yield
    finally:
        os.umask(previous)


def contents(directory):
    return {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


def policy_file(tmp_path, state):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "mountpoint": str(tmp_path), "state_dir": str(state),
        "volume_id": "vol-0123456789abcdef0",
        "filesystem_uuid": "12345678-1234-1234-1234-123456789abc",
        "uid": os.getuid(), "gid": os.getgid(),
    }))
    return path


def test_rejected_guard_holds_lease_and_does_not_recover_or_change_state(tmp_path):
    state = tmp_path / "state"
    with Broker(state, ADMIN) as broker:
        broker.create({"workflow": "recruiting"})
    before = contents(state)
    called = []

    def reject(lease):
        called.append(lease.fileno())
        with (state / ".broker.lock").open("r+b") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert contents(state) == before
        raise StateGuardError("synthetic_recovery_required")

    with pytest.raises(StateGuardError, match="^synthetic_recovery_required$"):
        Broker(state, ADMIN, startup_check=reject)
    assert len(called) == 1
    assert contents(state) == before
    # The rejected constructor releases ownership, without relying on GC.
    with (state / ".broker.lock").open("r+b") as contender:
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize("existing_directory", [False, True])
def test_guarded_startup_never_creates_a_directory_or_lock(tmp_path, existing_directory):
    state = tmp_path / "state"
    if existing_directory:
        state.mkdir()
    called = []
    with pytest.raises(FileNotFoundError):
        Broker(state, ADMIN, startup_check=lambda lease: called.append(lease))
    assert state.exists() == existing_directory
    assert not (state / ".broker.lock").exists()
    assert called == []


def test_guarded_startup_does_not_follow_lock_symlink(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    other = tmp_path / "other"
    other.write_bytes(b"untouched")
    (state / ".broker.lock").symlink_to(other)
    with pytest.raises(OSError):
        Broker(state, ADMIN, startup_check=lambda lease: pytest.fail("symlink admitted"))
    assert other.read_bytes() == b"untouched"
    assert not (state / "broker.sqlite").exists()


def test_policy_must_match_the_exact_state_argument(tmp_path, monkeypatch):
    path = policy_file(tmp_path, tmp_path / "state")
    monkeypatch.setattr("deploy.state_guard.verify_mount", lambda policy: pytest.fail("wrong path observed"))
    with pytest.raises(StateGuardError, match="^state_policy_path_mismatch$"):
        state_startup_check(path, tmp_path / "different")


def test_live_setup_runs_after_guard_before_existing_job_recovery(tmp_path):
    state = tmp_path / "state"
    # Inert configuration only: this object has no provider transport.
    gateway = SimpleNamespace(prices=SimpleNamespace(pin="synthetic-price-pin"),
                              max_cost_microusd=100)
    with Broker(state, ADMIN, live_model=gateway) as broker:
        created = broker.create({"workflow": "recruiting", "live_model": True})
        epoch = broker.job(created["job_id"])["epoch"]
    before = contents(state)
    stages = []

    def guard(lease):
        stages.append("guard")
        assert lease.fileno() >= 0
        assert contents(state) == before

    def setup():
        assert stages == ["guard"]
        assert contents(state) == before
        stages.append("model_setup")
        return gateway

    with Broker(state, ADMIN, startup_check=guard, live_model_factory=setup) as broker:
        assert stages == ["guard", "model_setup"]
        assert broker.live_model is gateway
        assert broker.job(created["job_id"])["epoch"] > epoch
        assert broker.snapshot(broker.job(created["job_id"]), created["token"])["effects_count"] == 0


def test_failed_live_setup_releases_lease_without_recovery(tmp_path):
    state = tmp_path / "state"
    with Broker(state, ADMIN) as broker:
        broker.create({"workflow": "recruiting"})
    before = contents(state)

    def fail():
        raise ValueError("synthetic_model_setup_failure")

    with pytest.raises(ValueError, match="^synthetic_model_setup_failure$"):
        Broker(state, ADMIN, startup_check=lambda lease: None, live_model_factory=fail)
    assert contents(state) == before
    with (state / ".broker.lock").open("r+b") as contender:
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize("failure_stage", ["mount", "existing_state"])
def test_cli_rejection_precedes_live_ledger_and_listener(tmp_path, monkeypatch, failure_stage):
    state = tmp_path / "state"
    if failure_stage == "existing_state":
        with Broker(state, ADMIN):
            pass
    before = contents(state) if state.exists() else {}
    path = policy_file(tmp_path, state)
    ready = tmp_path / "ready.json"
    stages = []

    def observe(policy):
        stages.append("mount")
        if failure_stage == "mount":
            raise StateGuardError("synthetic_mount_rejected")

    def inspect(policy, *, lease):
        stages.append("existing_state")
        assert lease.fileno() >= 0
        raise StateGuardError("synthetic_existing_state_rejected")

    monkeypatch.setattr("deploy.state_guard.verify_mount", observe)
    monkeypatch.setattr("deploy.state_guard.verify_existing_state", inspect)
    monkeypatch.setattr("controller.project_budget.ProjectBudgetLedger",
                        lambda *a, **k: pytest.fail("ledger opened before state guard"))
    monkeypatch.setattr("controller.service.ThreadingHTTPServer",
                        lambda *a, **k: pytest.fail("listener opened before state guard"))
    monkeypatch.setenv("CONTROLLER_LIVE_CONFIG", "synthetic-unread-config")
    monkeypatch.setenv("CONTROLLER_PROJECT_LEDGER", str(path))
    monkeypatch.setenv("CONTROLLER_ADMIN_TOKEN", ADMIN)
    monkeypatch.setattr(sys, "argv", ["controller.service", "--state-dir", str(state),
                                    "--ready-file", str(ready), "--state-policy", str(path)])
    with pytest.raises(StateGuardError, match="^synthetic_.*_rejected$"):
        main()
    assert stages == (["mount"] if failure_stage == "mount" else ["mount", "existing_state"])
    assert not ready.exists()
    assert (contents(state) if state.exists() else {}) == before
    assert state.exists() == (failure_stage == "existing_state")
