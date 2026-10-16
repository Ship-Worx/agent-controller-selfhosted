"""SDK process startup and execution budgets using only stdlib fake workers."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

import pytest

from integration.process import run_sdk_process, signal_ready


REPOSITORY = Path(__file__).resolve().parents[1]
PRELUDE = """
import json
import os
from pathlib import Path
import sys
import time
from integration.process import signal_ready
ready = Path(sys.argv[sys.argv.index('--ready-file') + 1])
Path(sys.argv[1]).write_text(str(os.getpid()))
"""


@pytest.fixture
def worker(tmp_path):
    ready = tmp_path / "ready.json"
    pid_file = tmp_path / "worker.pid"
    event = threading.Event()

    def run(source, *, timeout=2, startup_timeout=5):
        return run_sdk_process(
            [sys.executable, "-B", "-c", PRELUDE + source, str(pid_file)],
            cwd=REPOSITORY, env={"PYTHONDONTWRITEBYTECODE": "1"},
            ready_file=ready, timeout=timeout, startup_timeout=startup_timeout,
            ready_event=event,
        )

    return run, ready, pid_file, event


def assert_reaped(pid_file):
    pid = int(pid_file.read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    # Clean up a broken implementation's child before reporting the failure.
    try:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    except (ProcessLookupError, ChildProcessError):
        pass
    pytest.fail("SDK process helper returned without reaping its child")


def test_startup_delay_does_not_consume_execution_budget(worker):
    run, ready, pid_file, event = worker
    result = run("""
time.sleep(1.25)
signal_ready(ready)
print(json.dumps({'status': 'completed'}))
""", timeout=1)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"status": "completed"}
    assert result.stderr == ""
    assert event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_startup_timeout_reaps_child_and_removes_marker(worker):
    run, ready, pid_file, event = worker
    with pytest.raises(TimeoutError, match="^worker_start_timeout$"):
        run("time.sleep(30)\n", startup_timeout=2)
    assert not event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_execution_timeout_reaps_ready_child_and_removes_marker(worker):
    run, ready, pid_file, event = worker
    with pytest.raises(subprocess.TimeoutExpired):
        run("signal_ready(ready)\ntime.sleep(30)\n", timeout=0.15)
    assert event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_stale_marker_is_removed_before_child_starts(worker):
    run, ready, pid_file, event = worker
    ready.write_text(json.dumps({"pid": os.getpid()}))
    result = run("""
assert not ready.exists(), 'stale readiness marker survived launch'
print(json.dumps({'status': 'blocked', 'reason': 'worker_identity_required'}))
raise SystemExit(2)
""")
    assert result.returncode == 2
    assert json.loads(result.stdout)["reason"] == "worker_identity_required"
    assert result.stderr == ""
    assert not event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_wrong_pid_cannot_bypass_startup_timeout(worker):
    run, ready, pid_file, event = worker
    with pytest.raises(TimeoutError, match="^worker_start_timeout$"):
        run("ready.write_text(json.dumps({'pid': os.getpid() + 1}))\ntime.sleep(30)\n",
            timeout=0.15, startup_timeout=2)
    assert not event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_early_safe_exit_preserves_result_without_signaling_ready(worker):
    run, ready, pid_file, event = worker
    result = run("""
print(json.dumps({'status': 'error', 'reason': 'invalid_worker_input'}))
raise SystemExit(2)
""")
    assert isinstance(result, subprocess.CompletedProcess)
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"status": "error", "reason": "invalid_worker_input"}
    assert result.stderr == ""
    assert not event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_ready_then_immediate_exit_preserves_readiness_and_output(worker):
    run, ready, pid_file, event = worker
    result = run("signal_ready(ready)\nprint('finished', flush=True)\n")
    assert result.returncode == 0
    assert result.stdout == "finished\n"
    assert result.stderr == ""
    assert event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_large_startup_output_cannot_block_readiness(worker):
    run, ready, pid_file, event = worker
    result = run("""
sys.stdout.write('o' * 1048576)
sys.stdout.flush()
sys.stderr.write('e' * 1048576)
sys.stderr.flush()
signal_ready(ready)
""")
    assert result.returncode == 0
    assert result.stdout == "o" * 1048576
    assert result.stderr == "e" * 1048576
    assert event.is_set()
    assert not ready.exists()
    assert_reaped(pid_file)


def test_signal_ready_contains_only_process_identity(tmp_path):
    ready = tmp_path / "ready.json"
    signal_ready(None)
    assert list(tmp_path.iterdir()) == []
    signal_ready(ready)
    assert json.loads(ready.read_text()) == {"pid": os.getpid()}
