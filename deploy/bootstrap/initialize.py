"""Explicit one-time synthetic state initialization; never part of restart."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from controller.service import Broker
from deploy.state_guard import (StatePolicy, observe_linux_mount, verify_mount,
                                verify_existing_state, _check_lease)
from deploy.bootstrap.bundle import APP, ETC, MOUNT, STATE, BootstrapError, strict_json


def initialize_synthetic(policy, *, observe=observe_linux_mount, broker_type=Broker):
    """Only a verified, precreated empty directory may acquire fresh authority.

    A failure deliberately leaves all partial files intact. It is never a reset
    or automatic recovery operation. The temporary administrator is synthetic.
    """
    if (os.geteuid(), os.getegid()) != (policy.uid, policy.gid) or policy.uid == 0:
        raise BootstrapError("state_owner_identity_required")
    observed = verify_mount(policy, observe=observe)
    if any(policy.state_dir.iterdir()):
        raise BootstrapError("empty_state_directory_required")
    prior_umask = os.umask(0o077)
    try:
        # O_EXCL arbitrates simultaneous initializers without creating a new
        # lock inode for an existing owner. A crash here makes retries refuse.
        directory = os.open(policy.state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                lock = os.open(".broker.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600, dir_fd=directory)
            except FileExistsError:
                raise BootstrapError("empty_state_directory_required") from None
            os.close(lock)
            os.fsync(directory)
        finally:
            os.close(directory)

        def fresh_check(lease):
            current = verify_mount(policy, observe=observe)
            if current != observed or {path.name for path in policy.state_dir.iterdir()} != {".broker.lock"}:
                raise BootstrapError("fresh_state_changed")
            _check_lease(policy, current, lease)

        with broker_type(policy.state_dir, "synthetic-bootstrap-never-an-operator-token",
                         startup_check=fresh_check) as broker:
            created = broker.create({"workflow": "recruiting", "budget_microusd": 0,
                                     "runtime_seconds": 1})
            broker.stop(broker.job(created["job_id"]))
            report = verify_existing_state(policy, lease=broker._owner_file, observe=observe)
            return {"status": "synthetic_state_initialized", "seed_job_stopped": True,
                    "jobs": report.jobs, "databases": report.databases,
                    "volume_id": policy.volume_id, "filesystem_uuid": policy.filesystem_uuid,
                    "rollback_protection": report.rollback_protection,
                    "project_budget_created": False}
    finally:
        os.umask(prior_umask)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--initialize-empty-synthetic-state", action="store_true", required=True)
    args = parser.parse_args()
    try:
        from deploy.bootstrap.launch import protected_file
        if Path(__file__).resolve().parents[2] != APP or Path(args.policy) != ETC / "state-policy.json":
            raise BootstrapError("reviewed_installed_policy_required")
        fields = strict_json(protected_file(Path(args.policy), limit=16384))
        if set(fields) != {"mountpoint", "state_dir", "volume_id", "filesystem_uuid", "uid", "gid"}:
            raise BootstrapError("exact_state_policy_required")
        if fields["mountpoint"] != str(MOUNT) or fields["state_dir"] != str(STATE):
            raise BootstrapError("fixed_state_identity_required")
        print(json.dumps(initialize_synthetic(StatePolicy(**fields)), sort_keys=True))
        return 0
    except Exception as exc:
        # Foreign errors (including SQLite) may contain paths or data.
        reason = str(exc) if isinstance(exc, BootstrapError) else "state_initialization_blocked"
        print(json.dumps({"status": "blocked", "reason": reason}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
