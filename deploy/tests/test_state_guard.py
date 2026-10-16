"""Offline state-volume preflight; fake mount observations and private fixtures."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import subprocess

import pytest

from controller.service import Broker
from deploy.state_guard import (MountObservation, StateGuardError, StatePolicy,
                                observe_linux_mount, verify_existing_state, verify_mount)


VOLUME = "vol-0123456789abcdef0"
UUID = "12345678-1234-1234-1234-123456789abc"


@pytest.fixture
def state(tmp_path):
    mount = tmp_path / "volume"
    mount.mkdir(mode=0o700)
    broker = Broker(mount / "controller", "synthetic-state-guard-admin-credential")
    created = broker.create({"workflow": "recruiting"})
    for path in broker.state_dir.iterdir():
        path.chmod(0o600)
    info = mount.stat()
    policy = StatePolicy(mount, broker.state_dir, VOLUME, UUID, os.getuid(), os.getgid())
    observed = MountObservation(mount, "/dev/nvme1n1", UUID, VOLUME, "ext4", "/", ("rw",),
                                os.major(info.st_dev), os.minor(info.st_dev))
    try:
        yield policy, observed, broker, created
    finally:
        broker.close()


def check(state, **changes):
    policy, observed, broker, _created = state
    return verify_existing_state(policy, lease=broker._owner_file,
                                 observe=lambda _path: replace(observed, **changes))


def disk_bytes(directory):
    return {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}


def test_complete_state_is_read_only_and_does_not_claim_rollback_protection(state):
    policy, _observed, broker, created = state
    before = disk_bytes(policy.state_dir)
    epoch = broker.authority(broker.job(created["job_id"])).epoch
    report = check(state)
    assert (report.jobs, report.databases, report.check) == (1, 3, "existing_state_complete")
    assert report.rollback_protection == "external_recovery_proof_required"
    assert disk_bytes(policy.state_dir) == before
    assert broker.authority(broker.job(created["job_id"])).epoch == epoch


def test_missing_mount_does_not_touch_or_create_fallback_directory(tmp_path):
    fallback = tmp_path / "unmounted"
    policy = StatePolicy(fallback, fallback / "controller", VOLUME, UUID, os.getuid(), os.getgid())

    def absent(_path):
        raise StateGuardError("mount_metadata_unavailable")

    with pytest.raises(StateGuardError, match="mount_metadata_unavailable"):
        verify_mount(policy, observe=absent)
    assert not fallback.exists()


@pytest.mark.parametrize("changes", [
    {"volume_id": "vol-aaaaaaaa"}, {"filesystem_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
    {"filesystem_type": "overlay"}, {"filesystem_root": "/copied-state"},
    {"options": ("ro",)}, {"source": "tmpfs"}, {"mountpoint": Path("/wrong")},
])
def test_wrong_mount_identity_fails_before_database_access(state, changes):
    before = disk_bytes(state[0].state_dir)
    with pytest.raises(StateGuardError, match="unexpected_state_mount"):
        check(state, **changes)
    assert disk_bytes(state[0].state_dir) == before


def test_mount_device_must_match_state_files(state):
    with pytest.raises(StateGuardError, match="state_device_mismatch"):
        check(state, minor=state[1].minor + 1)


@pytest.mark.parametrize("kind", ["missing-broker", "empty-broker", "missing-authority", "missing-fence"])
def test_missing_or_empty_database_cannot_bootstrap(state, kind):
    policy, _observed, _broker, created = state
    names = {"missing-broker": "broker.sqlite", "empty-broker": "broker.sqlite",
             "missing-authority": created["job_id"] + ".sqlite",
             "missing-fence": created["job_id"] + ".sqlite.fence.sqlite"}
    target = policy.state_dir / names[kind]
    if kind == "empty-broker":
        target.write_bytes(b"")
    else:
        target.unlink()
    before = disk_bytes(policy.state_dir)
    with pytest.raises(StateGuardError, match="existing_state_(missing|empty)"):
        check(state)
    assert disk_bytes(policy.state_dir) == before


@pytest.mark.parametrize("target", ["directory", "database", "lock"])
def test_group_or_world_access_is_rejected(state, target):
    policy = state[0]
    path = {"directory": policy.state_dir, "database": policy.state_dir / "broker.sqlite",
            "lock": policy.state_dir / ".broker.lock"}[target]
    path.chmod(0o755 if target == "directory" else 0o640)
    with pytest.raises(StateGuardError, match="unsafe_state_permissions"):
        check(state)


def test_wrong_owner_is_rejected(state):
    policy, observed, broker, _ = state
    with pytest.raises(StateGuardError, match="unsafe_state_permissions"):
        verify_existing_state(replace(policy, uid=policy.uid + 1), lease=broker._owner_file,
                              observe=lambda _path: observed)


def test_database_symlink_cannot_escape_guard(state, tmp_path):
    policy = state[0]
    database = policy.state_dir / "broker.sqlite"
    outside = tmp_path / "outside.sqlite"
    database.rename(outside)
    database.symlink_to(outside)
    with pytest.raises(StateGuardError, match="unsafe_state_permissions"):
        check(state)


def test_existing_unlocked_descriptor_is_not_a_writer_lease(state):
    policy, observed, broker, _ = state
    broker.close()
    with (policy.state_dir / ".broker.lock").open("rb") as unlocked:
        with pytest.raises(StateGuardError, match="state_lease_required"):
            verify_existing_state(policy, lease=unlocked, observe=lambda _path: observed)


def test_unlocked_descriptor_cannot_borrow_same_process_broker_lease(state):
    policy, observed, broker, _ = state
    before = disk_bytes(policy.state_dir)
    with (policy.state_dir / ".broker.lock").open("rb") as unrelated:
        with pytest.raises(StateGuardError, match="state_lease_required"):
            verify_existing_state(policy, lease=unrelated, observe=lambda _path: observed)
        assert verify_existing_state(policy, lease=broker._owner_file,
                                     observe=lambda _path: observed).jobs == 1
    assert disk_bytes(policy.state_dir) == before


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_pending_journal_requires_explicit_recovery(state, suffix):
    journal = state[0].state_dir / ("broker.sqlite" + suffix)
    journal.write_bytes(b"synthetic pending state")
    before = disk_bytes(state[0].state_dir)
    with pytest.raises(StateGuardError, match="state_recovery_required"):
        check(state)
    assert disk_bytes(state[0].state_dir) == before


def test_anchor_mismatch_is_rejected_without_repair(state):
    policy, _observed, _broker, created = state
    with sqlite3.connect(policy.state_dir / (created["job_id"] + ".sqlite.fence.sqlite")) as conn:
        conn.execute("UPDATE anchor SET revision=revision+1")
    before = disk_bytes(policy.state_dir)
    with pytest.raises(StateGuardError, match="state_anchor_mismatch"):
        check(state)
    assert disk_bytes(policy.state_dir) == before


def test_orphan_database_and_empty_registry_fail_closed(state):
    policy = state[0]
    orphan = policy.state_dir / "orphan.sqlite"
    orphan.write_bytes(b"not registered")
    with pytest.raises(StateGuardError, match="state_registry_incomplete"):
        check(state)
    orphan.unlink()
    with sqlite3.connect(policy.state_dir / "broker.sqlite") as conn:
        conn.execute("DELETE FROM jobs")
    with pytest.raises(StateGuardError, match="existing_state_empty_or_unbounded"):
        check(state)


def test_corrupt_database_and_missing_schema_are_rejected(state):
    database = state[0].state_dir / "broker.sqlite"
    before = database.read_bytes()
    database.write_bytes(b"not a SQLite database")
    with pytest.raises(StateGuardError, match="state_database_invalid"):
        check(state)
    database.write_bytes(before)
    with sqlite3.connect(database) as conn:
        conn.execute("DROP TABLE sessions")
    with pytest.raises(StateGuardError, match="state_schema_incomplete"):
        check(state)


def test_wal_database_header_is_rejected_without_sidecar_files(state):
    database = state[0].state_dir / "broker.sqlite"
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    finally:
        connection.close()
    assert not database.with_name(database.name + "-wal").exists()
    with pytest.raises(StateGuardError, match="unsafe_state_journal_mode"):
        check(state)


def test_consistent_whole_volume_rollback_requires_external_evidence(state):
    policy, _observed, broker, created = state
    old_volume = disk_bytes(policy.state_dir)
    broker.stop(broker.job(created["job_id"]))
    assert disk_bytes(policy.state_dir) != old_volume
    # Synthetic rollback of every local database. This deliberately demonstrates
    # the limit: local consistency cannot authenticate current Stop/budget truth.
    for name, content in old_volume.items():
        (policy.state_dir / name).write_bytes(content)
    report = check(state)
    assert report.check == "existing_state_complete"
    assert report.rollback_protection == "external_recovery_proof_required"


def test_changed_mount_during_validation_fails_closed(state):
    policy, observed, broker, _ = state
    calls = 0

    def observe(_path):
        nonlocal calls
        calls += 1
        return observed if calls == 1 else replace(observed, source="/dev/nvme2n1")

    with pytest.raises(StateGuardError, match="state_mount_changed"):
        verify_existing_state(policy, lease=broker._owner_file, observe=observe)


@pytest.mark.parametrize("changes", [
    {"mountpoint": Path("/")}, {"state_dir": Path("/outside/controller")},
    {"volume_id": None}, {"uid": True}, {"mountpoint": Path("relative")},
])
def test_invalid_policy_cannot_select_root_or_untrusted_paths(state, changes):
    with pytest.raises(StateGuardError, match="invalid_state_policy"):
        replace(state[0], **changes)


def metadata_fixture(mountpoint):
    mounted = {"target": str(mountpoint), "source": "/dev/nvme1n1p1", "fstype": "ext4",
               "fsroot": "/", "options": "rw,nosuid,nodev", "uuid": UUID, "maj:min": "259:3"}
    disk = {"path": "/dev/nvme1n1", "type": "disk", "maj:min": "259:2", "serial": VOLUME.replace("-", "")}
    filesystem = {"path": "/dev/nvme1n1p1", "type": "part", "maj:min": "259:3", "uuid": UUID,
                  "children": [disk]}
    return mounted, filesystem


def test_linux_observer_uses_only_exact_read_only_mount_and_block_metadata(tmp_path):
    mounted, filesystem = metadata_fixture(tmp_path)
    calls = []

    def runner(command, **options):
        calls.append(command)
        assert options == {"capture_output": True, "text": True, "timeout": 5, "check": False}
        document = {"filesystems": [mounted]} if command[0] == "findmnt" else {"blockdevices": [filesystem]}
        return subprocess.CompletedProcess(command, 0, json.dumps(document), "")

    observation = observe_linux_mount(tmp_path, runner=runner)
    assert (observation.volume_id, observation.filesystem_uuid, observation.major, observation.minor) == (
        VOLUME, UUID, 259, 3)
    assert calls[0][:4] == ["findmnt", "--json", "--mountpoint", str(tmp_path)]
    assert calls[1][0] == "lsblk"
    assert calls[1][-1] == "/dev/nvme1n1p1"


def test_missing_mount_metadata_never_queries_block_devices(tmp_path):
    calls = []

    def runner(command, **_options):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, "", "private metadata error")

    with pytest.raises(StateGuardError, match="^mount_metadata_unavailable$"):
        observe_linux_mount(tmp_path, runner=runner)
    assert len(calls) == 1


@pytest.mark.parametrize("alter", ["missing-serial", "uuid-mismatch", "multiple-disks"])
def test_ambiguous_block_identity_is_rejected(tmp_path, alter):
    mounted, filesystem = metadata_fixture(tmp_path)
    if alter == "missing-serial":
        filesystem["children"][0]["serial"] = None
    elif alter == "uuid-mismatch":
        filesystem["uuid"] = "another-filesystem"
    else:
        filesystem["children"].append(dict(filesystem["children"][0]))

    def runner(command, **_options):
        document = {"filesystems": [mounted]} if command[0] == "findmnt" else {"blockdevices": [filesystem]}
        return subprocess.CompletedProcess(command, 0, json.dumps(document), "")

    with pytest.raises(StateGuardError, match="mount_identity_unavailable"):
        observe_linux_mount(tmp_path, runner=runner)
