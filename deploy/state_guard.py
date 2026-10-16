"""Read-only preflight for an existing, quiesced controller state volume.

This checks local mount identity and state completeness, not the freshness of a
whole-volume restore. Recovery still requires independent external evidence.
No database, directory, lock file, filesystem, or recovery manifest is created.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import time


class StateGuardError(RuntimeError):
    """A safe, credential-free startup rejection code."""


@dataclass(frozen=True)
class StatePolicy:
    mountpoint: Path
    state_dir: Path
    volume_id: str
    filesystem_uuid: str
    uid: int
    gid: int

    def __post_init__(self):
        for name in ("mountpoint", "state_dir"):
            try:
                value = Path(getattr(self, name))
            except (TypeError, ValueError):
                raise StateGuardError("invalid_state_policy") from None
            if not value.is_absolute() or ".." in value.parts:
                raise StateGuardError("invalid_state_policy")
            object.__setattr__(self, name, value)
        if (self.mountpoint == Path("/") or not self.state_dir.is_relative_to(self.mountpoint)
                or not isinstance(self.volume_id, str) or not isinstance(self.filesystem_uuid, str)
                or not re.fullmatch(r"vol-(?:[0-9a-f]{8}|[0-9a-f]{17})", self.volume_id)
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", self.filesystem_uuid)
                or any(type(value) is not int or value < 0 for value in (self.uid, self.gid))):
            raise StateGuardError("invalid_state_policy")


@dataclass(frozen=True)
class MountObservation:
    mountpoint: Path
    source: str
    filesystem_uuid: str
    volume_id: str
    filesystem_type: str
    filesystem_root: str
    options: tuple[str, ...]
    major: int
    minor: int


@dataclass(frozen=True)
class StateReport:
    jobs: int
    databases: int
    check: str = "existing_state_complete"
    rollback_protection: str = "external_recovery_proof_required"


def _metadata(command, runner):
    try:
        result = runner(command, capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0 or len(result.stdout) > 1_048_576:
            raise StateGuardError("mount_metadata_unavailable")
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise StateGuardError("mount_metadata_unavailable") from None


def observe_linux_mount(mountpoint, *, runner=subprocess.run):
    """Observe one exact Linux mount and its disk serial; never query AWS.

    Supports a directly mounted ext4/XFS EBS disk or one partition on that disk.
    Missing/ambiguous serials, stacked devices, and subdirectory binds fail closed.
    """
    document = _metadata(["findmnt", "--json", "--mountpoint", str(mountpoint),
                          "--output", "TARGET,SOURCE,FSTYPE,FSROOT,OPTIONS,UUID,MAJ:MIN"], runner)
    try:
        mounts = document["filesystems"]
        if len(mounts) != 1:
            raise ValueError
        mounted = mounts[0]
        source = mounted["source"]
        if (mounted["target"] != str(mountpoint) or not source.startswith("/dev/")
                or "[" in source or mounted.get("children")):
            raise ValueError
        major, minor = (int(value) for value in mounted["maj:min"].split(":"))
        blocks = _metadata(["lsblk", "--json", "--inverse", "--paths", "--tree",
                            "--output", "NAME,PATH,TYPE,MAJ:MIN,SERIAL,UUID", source], runner)["blockdevices"]
        if len(blocks) != 1:
            raise ValueError
        filesystem = blocks[0]
        if filesystem["maj:min"] != mounted["maj:min"] or filesystem["uuid"] != mounted["uuid"]:
            raise ValueError
        disk = filesystem
        if disk["type"] == "part":
            if len(disk.get("children", [])) != 1:
                raise ValueError
            disk = disk["children"][0]
        if disk["type"] != "disk" or disk.get("children"):
            raise ValueError
        serial = disk["serial"]
        if not isinstance(serial, str) or not re.fullmatch(r"vol-?(?:[0-9a-f]{8}|[0-9a-f]{17})", serial):
            raise ValueError
        volume_id = "vol-" + serial.removeprefix("vol").removeprefix("-")
        return MountObservation(Path(mounted["target"]), source, mounted["uuid"], volume_id,
                                mounted["fstype"], mounted["fsroot"],
                                tuple(mounted["options"].split(",")), major, minor)
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        raise StateGuardError("mount_identity_unavailable") from None


def verify_mount(policy: StatePolicy, *, observe=observe_linux_mount):
    """Must precede Broker construction; a missing mount never touches fallback state."""
    observed = observe(policy.mountpoint)
    if (not isinstance(observed, MountObservation) or observed.mountpoint != policy.mountpoint
            or observed.volume_id != policy.volume_id
            or observed.filesystem_uuid != policy.filesystem_uuid
            or observed.filesystem_type not in {"ext4", "xfs"}
            or observed.filesystem_root != "/" or "rw" not in observed.options
            or "ro" in observed.options or not observed.source.startswith("/dev/")
            or type(observed.major) is not int or type(observed.minor) is not int
            or observed.major < 0 or observed.minor < 0):
        raise StateGuardError("unexpected_state_mount")
    _check_directory_chain(policy, observed)
    return observed


def _secure_stat(path, policy, observed, *, directory=False, nonempty=False):
    try:
        info = path.lstat()
    except OSError:
        raise StateGuardError("existing_state_missing") from None
    expected_mode = 0o700 if directory else 0o600
    right_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not right_type or stat.S_IMODE(info.st_mode) != expected_mode
            or (info.st_uid, info.st_gid) != (policy.uid, policy.gid)
            or (not directory and info.st_nlink != 1)):
        raise StateGuardError("unsafe_state_permissions")
    if (os.major(info.st_dev), os.minor(info.st_dev)) != (observed.major, observed.minor):
        raise StateGuardError("state_device_mismatch")
    if nonempty and info.st_size == 0:
        raise StateGuardError("existing_state_empty")
    return info


def _check_directory_chain(policy, observed):
    # Reject symlink aliases even above the mountpoint. Only directories inside
    # the dedicated mount must have the controller's exact private owner/mode.
    for parent in reversed(policy.mountpoint.parents):
        if parent.is_symlink():
            raise StateGuardError("state_path_alias")
    current = policy.mountpoint
    _secure_stat(current, policy, observed, directory=True)
    for part in policy.state_dir.relative_to(policy.mountpoint).parts:
        current /= part
        _secure_stat(current, policy, observed, directory=True)


def _check_lease(policy, observed, lease):
    path = policy.state_dir / ".broker.lock"
    info = _secure_stat(path, policy, observed)
    try:
        descriptor = lease.fileno()
        held = os.fstat(descriptor)
        if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
            raise StateGuardError("state_lease_required")
        # A process-wide /proc/locks match can belong to another open-file
        # description. The supplied descriptor itself must carry this flock;
        # an unrelated open of the same inode does not retain the writer lease.
        identity = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}"
        details = [line.split() for line in Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines()]
        if ([parts[1] for parts in details if len(parts) == 2 and parts[0] == "ino:"] != [str(info.st_ino)]
                or not any(len(parts) == 9 and parts[0] == "lock:"
                           and parts[2:6] == ["FLOCK", "ADVISORY", "WRITE", str(os.getpid())]
                           and parts[6:] == [identity, "0", "EOF"] for parts in details)):
            raise StateGuardError("state_lease_required")
        probe = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            fcntl.flock(probe, fcntl.LOCK_UN)
        finally:
            os.close(probe)
    except (OSError, ValueError, AttributeError):
        raise StateGuardError("state_lease_required") from None
    raise StateGuardError("state_lease_required")


BROKER_SCHEMA = {
    "jobs": "job_id workflow budget runtime epoch root_token root_id final_outcome live_enabled pricing_pin",
    "sessions": "token_hash job_id run_id", "effects": "ticket job_id operation_id action receipt cost",
    "trace": "event_id job_id run_id at event data",
}
AUTHORITY_SCHEMA = {
    "meta": "singleton authority_id schema_version epoch revision config_pin",
    "roots": "root_id stopped budget_microusd call_limit children",
    "runs": "run_id root_id parent_id token binding capabilities context deadline depth generation ancestry",
    "tokens": "token run_id", "approvals": "approval_id fingerprint lineage epoch consumed",
    "operations": "ticket root_id run_id operation_id fingerprint attempt status max_cost actual_cost receipt epoch lineage approval_id",
    "audit": "event_id root_id run_id ticket event at",
}
FENCE_SCHEMA = {"anchor": "singleton authority_id epoch revision"}


@contextmanager
def _database(path, policy, observed, schema):
    _secure_stat(path, policy, observed, nonempty=True)
    conn = None
    try:
        with path.open("rb") as database_file:
            header = database_file.read(100)
        if header[:16] != b"SQLite format 3\x00":
            raise StateGuardError("state_database_invalid")
        # Immutable readers can report DELETE even for a WAL-format file. Check
        # the on-disk read/write format bytes, before opening without recovery.
        if header[18:20] != b"\x01\x01":
            raise StateGuardError("unsafe_state_journal_mode")
        conn = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=1)
        conn.row_factory = sqlite3.Row
        deadline = time.monotonic() + 5
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        conn.execute("PRAGMA query_only=ON")
        if [row[0] for row in conn.execute("PRAGMA quick_check")] != ["ok"]:
            raise StateGuardError("state_database_invalid")
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not set(schema) <= tables:
            raise StateGuardError("state_schema_incomplete")
        for table, columns in schema.items():
            if not set(columns.split()) <= {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}:
                raise StateGuardError("state_schema_incomplete")
        yield conn
    except (sqlite3.Error, OSError):
        raise StateGuardError("state_database_invalid") from None
    finally:
        if conn is not None:
            conn.close()


def _check_journals(directory):
    try:
        if any(path.name.endswith(("-journal", "-wal", "-shm")) for path in directory.iterdir()):
            raise StateGuardError("state_recovery_required")
    except OSError:
        raise StateGuardError("existing_state_missing") from None


def verify_existing_state(policy: StatePolicy, *, lease, observe=observe_linux_mount):
    """Validate quiesced state under the caller's existing Broker ownership lock.

    The caller must keep that lock through initialization and serving. Do not
    use this result as a standalone check followed by an unlocked startup.
    """
    observed = verify_mount(policy, observe=observe)
    _check_lease(policy, observed, lease)
    _check_journals(policy.state_dir)
    with _database(policy.state_dir / "broker.sqlite", policy, observed, BROKER_SCHEMA) as conn:
        jobs = conn.execute("SELECT job_id,epoch,root_id FROM jobs LIMIT 10001").fetchall()
    if not jobs or len(jobs) > 10000:
        raise StateGuardError("existing_state_empty_or_unbounded")
    expected = {"broker.sqlite"}
    for job in jobs:
        job_id = job["job_id"]
        if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise StateGuardError("state_registry_invalid")
        authority_name, fence_name = job_id + ".sqlite", job_id + ".sqlite.fence.sqlite"
        expected.update((authority_name, fence_name))
        with _database(policy.state_dir / authority_name, policy, observed, AUTHORITY_SCHEMA) as conn:
            metadata = conn.execute("SELECT * FROM meta").fetchall()
            if len(metadata) != 1:
                raise StateGuardError("state_anchor_mismatch")
            meta = metadata[0]
            if (meta["singleton"] != 1 or meta["schema_version"] != 1
                    or not isinstance(meta["authority_id"], str)
                    or not re.fullmatch(r"[0-9a-f]{32}", meta["authority_id"])
                    or not isinstance(meta["config_pin"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", meta["config_pin"])
                    or type(meta["epoch"]) is not int or meta["epoch"] < 1
                    or type(meta["revision"]) is not int or meta["revision"] < 0
                    or meta["epoch"] != job["epoch"]
                    or not conn.execute("SELECT 1 FROM roots WHERE root_id=?", (job["root_id"],)).fetchone()
                    or not conn.execute("SELECT 1 FROM runs WHERE run_id=? AND root_id=? AND parent_id IS NULL",
                                        (job["root_id"], job["root_id"])).fetchone()):
                raise StateGuardError("state_anchor_mismatch")
        with _database(policy.state_dir / fence_name, policy, observed, FENCE_SCHEMA) as conn:
            anchors = conn.execute("SELECT * FROM anchor").fetchall()
            if (len(anchors) != 1 or anchors[0]["singleton"] != 1
                    or any(anchors[0][key] != meta[key] for key in ("authority_id", "epoch", "revision"))):
                raise StateGuardError("state_anchor_mismatch")
    if {path.name for path in policy.state_dir.glob("*.sqlite")} != expected:
        raise StateGuardError("state_registry_incomplete")
    _check_journals(policy.state_dir)
    if verify_mount(policy, observe=observe) != observed:
        raise StateGuardError("state_mount_changed")
    _check_lease(policy, observed, lease)
    return StateReport(len(jobs), len(expected))
