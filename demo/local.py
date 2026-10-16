"""Launch separate local processes with distinct protocol credentials."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

from integration.client import ControllerClient
from integration.process import SDK_STARTUP_TIMEOUT, run_sdk_process

PROJECT = Path(__file__).resolve().parents[1]


def process_environment() -> dict[str, str]:
    """Do not pass supervisor/provider/cloud credentials to subprocess workers."""
    return {**{name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL", "TMPDIR")
               if name in os.environ},
            "PYTHONUNBUFFERED": "1", "OPENAI_AGENTS_DISABLE_TRACING": "1"}


class LocalController:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.state = directory / "state"
        self.ready = directory / "ready.json"
        self.admin_token = secrets.token_urlsafe(32)
        self.process = None
        self.log = None

    def start(self):
        if self.process is not None:
            raise RuntimeError("controller_already_running")
        self.ready.unlink(missing_ok=True)
        self.log = (self.directory / "controller.log").open("a")
        env = {**process_environment(), "CONTROLLER_ADMIN_TOKEN": self.admin_token}
        self.process = subprocess.Popen(
            [sys.executable, "-m", "controller.service", "--state-dir", str(self.state),
             "--port", "0", "--ready-file", str(self.ready)],
            cwd=PROJECT, env=env, stdout=self.log, stderr=self.log,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.stop()
                raise RuntimeError("controller_start_failed; inspect controller.log")
            if self.ready.exists():
                try:
                    ready = json.loads(self.ready.read_text())
                    if ready["pid"] == self.process.pid:
                        self.url = ready["url"]
                        self.admin = ControllerClient(self.url, self.admin_token)
                        return self
                except (ValueError, KeyError):
                    pass
            time.sleep(.02)
        self.stop()
        raise RuntimeError("controller_start_timeout")

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def restart(self):
        self.stop()
        return self.start()

    def create(self, workflow="recruiting", **options):
        job = self.admin.request("/jobs", {"workflow": workflow, **options})
        if "token" not in job:
            raise RuntimeError("job_admission_failed")
        return job

    def worker_client(self, job):
        return ControllerClient(self.url, job["token"])

    def run_worker(self, job, plan, *, memory="", timeout=15,
                   startup_timeout=SDK_STARTUP_TIMEOUT, ready_event=None):
        run_dir = self.directory / ("worker-" + secrets.token_hex(8))
        run_dir.mkdir()
        plan_path, memory_path = run_dir / "plan.json", run_dir / "memory.txt"
        plan_path.write_text(json.dumps(plan))
        memory_path.write_text(memory)
        env = {**process_environment(), "CONTROLLER_WORKER_TOKEN": job["token"]}
        result = run_sdk_process(
            [sys.executable, "-m", "integration.worker", "--url", self.url,
             "--plan", str(plan_path), "--memory", str(memory_path)],
            cwd=PROJECT, env=env, ready_file=run_dir / "ready.json", timeout=timeout,
            startup_timeout=startup_timeout, ready_event=ready_event,
        )
        try:
            output = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("worker_failed_without_safe_result") from None
        output["exit_code"] = result.returncode
        return output

    def __enter__(self):
        return self.start()

    def __exit__(self, *_args):
        self.stop()


def proposal(job, action, operation_id, **changes):
    cap = next(cap for cap in job["capabilities"] if cap["action"] == action)
    payload = {"summary": "Synthetic internal summary"} if action == "report.write" else {}
    return {"operation_id": operation_id, **cap, "payload": payload, **changes}
