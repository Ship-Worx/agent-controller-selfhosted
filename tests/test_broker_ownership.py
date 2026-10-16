"""Only one live Broker may own a state directory, including during shutdown."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from controller.durable import DurableError
from controller.engine import Attempt
from controller.service import Broker


REPOSITORY = Path(__file__).resolve().parents[1]
ADMIN_TOKEN = "synthetic-ownership-test-admin-credential"


def read(operation="ownership-read"):
    return Attempt(operation, "read", "record.read", "candidate-a", "worker", {})


def database_bytes(directory):
    return {path.relative_to(directory): path.read_bytes()
            for path in directory.rglob("*.sqlite")}


def subprocess_environment():
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["OPENAI_AGENTS_DISABLE_TRACING"] = "1"
    return environment


@pytest.fixture
def owner(tmp_path):
    broker = Broker(tmp_path, ADMIN_TOKEN)
    try:
        yield broker
    finally:
        # Keep the regression's pre-fix failure focused on concurrent ownership.
        close = getattr(broker, "close", None)
        if close is not None:
            close()


@pytest.mark.parametrize("existing_job", [False, True], ids=["empty", "existing"])
@pytest.mark.parametrize("second_process", [False, True], ids=["same-process", "subprocess"])
def test_rejected_owner_changes_no_database_bytes(owner, tmp_path, existing_job, second_process):
    if existing_job:
        created = owner.create({"workflow": "recruiting"})
        job = owner.job(created["job_id"])
        reserved = owner.authorize(job, created["token"], created["run_id"], read())
        assert reserved["status"] == "reserved"
    before = database_bytes(tmp_path)
    if second_process:
        contender = subprocess.run(
            [sys.executable, "-B", "-c", """
import sys
from controller.service import Broker
try:
    broker = Broker(sys.argv[1], sys.argv[2])
except RuntimeError as error:
    print(str(error))
    raise SystemExit(23)
else:
    close = getattr(broker, 'close', None)
    if close is not None:
        close()
    raise SystemExit(24)
""", str(tmp_path), ADMIN_TOKEN],
            cwd=REPOSITORY, env=subprocess_environment(), capture_output=True,
            text=True, timeout=10,
        )
        assert (contender.returncode, contender.stdout.strip(), contender.stderr) == (
            23, "state_directory_in_use", "")
    else:
        with pytest.raises(RuntimeError, match="^state_directory_in_use$"):
            Broker(tmp_path, ADMIN_TOKEN)
    assert database_bytes(tmp_path) == before
    if not existing_job:
        created = owner.create({"workflow": "recruiting"})
        job = owner.job(created["job_id"])
        reserved = owner.authorize(job, created["token"], created["run_id"], read())
        assert reserved["status"] == "reserved"
    result = owner.execute(job, created["token"], created["run_id"], reserved["ticket"])
    assert result["status"] == "allowed"
    assert owner.snapshot(job, created["token"])["effects_count"] == 1
    fresh = owner.authorize(job, created["token"], created["run_id"], read("after-rejection"))
    assert fresh["status"] == "reserved"


def test_close_releases_ownership_and_fences_old_tickets_and_broker(owner, tmp_path):
    created = owner.create({"workflow": "recruiting"})
    job = owner.job(created["job_id"])
    authority = owner.authority(job)
    reserved = owner.authorize(job, created["token"], created["run_id"], read())
    owner.close()
    owner.close()
    before = database_bytes(tmp_path)
    with pytest.raises(DurableError, match="^broker_closed$"):
        owner.create({"workflow": "recruiting"})
    assert database_bytes(tmp_path) == before
    with Broker(tmp_path, ADMIN_TOKEN) as replacement:
        with pytest.raises(DurableError, match="^broker_closed$"):
            owner.authorize(job, created["token"], created["run_id"], read("stale-broker"))
        assert authority.reserve(created["token"], read("stale-authority")).reason == "controller_fenced"
        result = replacement.execute(job, created["token"], created["run_id"], reserved["ticket"])
        assert (result["status"], result["reason"]) == ("denied", "ticket_fenced")
        assert replacement.snapshot(job, created["token"])["effects_count"] == 0
        fresh = replacement.authorize(job, created["token"], created["run_id"], read("replacement"))
        assert fresh["status"] == "reserved"
        assert replacement.execute(job, created["token"], created["run_id"], fresh["ticket"])["status"] == "allowed"
    with pytest.raises(DurableError, match="^broker_closed$"):
        replacement.create({"workflow": "recruiting"})
    with Broker(tmp_path, ADMIN_TOKEN):
        pass


def test_constructor_failure_releases_ownership(owner, tmp_path, monkeypatch):
    owner.create({"workflow": "recruiting"})
    owner.close()

    def fail_recovery(self, job):
        raise ValueError("synthetic_recovery_failure")

    with monkeypatch.context() as patch:
        patch.setattr(Broker, "authority", fail_recovery)
        # Keep the exception traceback alive: cleanup must not depend on GC.
        with pytest.raises(ValueError, match="^synthetic_recovery_failure$") as failure:
            Broker(tmp_path, ADMIN_TOKEN)
    assert failure.value is not None
    with Broker(tmp_path, ADMIN_TOKEN) as replacement:
        with replacement.connect() as connection:
            assert connection.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1


@pytest.mark.parametrize("crash", [False, True], ids=["normal-exit", "killed"])
def test_process_exit_releases_ownership(tmp_path, crash):
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", """
import sys
from controller.service import Broker
broker = Broker(sys.argv[1], sys.argv[2])
broker.create({'workflow': 'recruiting'})
print('ready', flush=True)
sys.stdin.readline()
""", str(tmp_path), ADMIN_TOKEN],
        cwd=REPOSITORY, env=subprocess_environment(), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        # Bounded wait also surfaces startup failures without an indefinite read.
        import selectors
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=10), "owner process did not become ready"
        assert process.stdout.readline().strip() == "ready"
        with pytest.raises(RuntimeError, match="^state_directory_in_use$"):
            Broker(tmp_path, ADMIN_TOKEN)
        if crash:
            process.kill()
        else:
            process.stdin.write("exit\n")
            process.stdin.flush()
        _stdout, stderr = process.communicate(timeout=10)
        assert stderr == ""
        assert process.returncode < 0 if crash else process.returncode == 0
        with Broker(tmp_path, ADMIN_TOKEN) as replacement:
            with replacement.connect() as connection:
                assert connection.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def test_close_holds_ownership_until_running_operation_finishes(owner, tmp_path, monkeypatch):
    created = owner.create({"workflow": "recruiting"})
    job = owner.job(created["job_id"])
    reserved = owner.authorize(job, created["token"], created["run_id"], read())
    started, finish = threading.Event(), threading.Event()
    record = owner.record

    def pause_dispatch(job, run_id, event, **data):
        record(job, run_id, event, **data)
        if event == "tool_started":
            started.set()
            assert finish.wait(10), "test did not release pending dispatch"

    monkeypatch.setattr(owner, "record", pause_dispatch)
    with ThreadPoolExecutor(max_workers=2) as pool:
        execution = pool.submit(owner.execute, job, created["token"], created["run_id"], reserved["ticket"])
        try:
            assert started.wait(5), "dispatch did not start"
            closing = pool.submit(owner.close)
            with pytest.raises(TimeoutError):
                closing.result(timeout=0.1)
            deadline = time.monotonic() + 5
            while True:
                try:
                    owner.authenticate(ADMIN_TOKEN)
                except DurableError as error:
                    assert str(error) == "broker_closed"
                    break
                assert time.monotonic() < deadline, "close did not reject new operations"
                time.sleep(0.01)
            before = database_bytes(tmp_path)
            with pytest.raises(DurableError, match="^broker_closed$"):
                owner.create({"workflow": "recruiting"})
            assert database_bytes(tmp_path) == before
            with pytest.raises(RuntimeError, match="^state_directory_in_use$"):
                Broker(tmp_path, ADMIN_TOKEN)
        finally:
            finish.set()
        assert execution.result(timeout=5)["status"] == "allowed"
        closing.result(timeout=5)
    with Broker(tmp_path, ADMIN_TOKEN) as replacement:
        assert replacement.snapshot(job, created["token"])["effects_count"] == 1
