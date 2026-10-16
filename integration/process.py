"""Local SDK process startup accounting; readiness never grants authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


SDK_STARTUP_TIMEOUT = 60


def signal_ready(path):
    if path is not None:
        Path(path).write_text(json.dumps({"pid": os.getpid()}))


def run_sdk_process(command, *, cwd, env, ready_file, timeout=15,
                    startup_timeout=SDK_STARTUP_TIMEOUT, ready_event=None):
    """Bound cold import separately from execution, preserving safe early exits.

    The caller owns a fresh run directory. A PID-matched marker is a local
    scheduling hint, not evidence of controller authorization or useful work.
    Neither timer changes the controller's absolute job expiry.
    """
    ready_file = Path(ready_file)
    ready_file.unlink(missing_ok=True)
    command = [*command, "--ready-file", str(ready_file)]
    # Drain output into temporary files during startup, so a traceback or SDK
    # diagnostic cannot fill an unread pipe and prevent the ready signal.
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout, \
            tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, text=True)
        try:
            deadline = time.monotonic() + startup_timeout
            while True:
                try:
                    ready = json.loads(ready_file.read_text())
                except (OSError, ValueError):
                    ready = None
                if type(ready) is dict and ready.get("pid") == process.pid:
                    if ready_event is not None:
                        ready_event.set()
                    process.wait(timeout=timeout)
                    break
                if process.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("worker_start_timeout")
                time.sleep(.02)
            stdout.seek(0)
            stderr.seek(0)
            return subprocess.CompletedProcess(command, process.returncode,
                                               stdout.read(), stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            ready_file.unlink(missing_ok=True)
