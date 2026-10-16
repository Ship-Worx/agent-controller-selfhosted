"""Operator-owned installation identity; never accept it from worker requests.

This configuration chooses the owner of a new installation, not permission to
spend. Its persistent ledger still needs verified historical reconciliation.
Filesystem and process isolation keep this authority away from workers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import stat


MAX_CONFIG_BYTES = 8192
MAX_MICROUSD = 2**63 - 1
_FIELDS = {"schema_version", "project_id", "account_id", "region", "limit_microusd"}
_PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,127}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2,8}(?:-[a-z0-9]+)+-[0-9]+\Z")
_CREDENTIAL = re.compile(r"sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{12,}|ASIA[A-Z0-9]{12,}|"
                         r"gh[pousr]_[A-Za-z0-9_]{12,}|aws_secret_access_key|-----BEGIN", re.I)


class InstallationConfigError(ValueError):
    """Configuration is absent, untrusted or invalid; never echo its contents."""


@dataclass(frozen=True)
class InstallationConfig:
    project_id: str
    account_id: str
    region: str
    limit_microusd: int

    def __post_init__(self):
        if (type(self.project_id) is not str or not _PROJECT.fullmatch(self.project_id)
                or _CREDENTIAL.search(self.project_id)
                or type(self.account_id) is not str or not _ACCOUNT.fullmatch(self.account_id)
                or self.account_id == "000000000000"
                or type(self.region) is not str or not _REGION.fullmatch(self.region)
                or type(self.limit_microusd) is not int
                or not 0 < self.limit_microusd <= MAX_MICROUSD):
            raise InstallationConfigError("invalid_installation_identity")

    @classmethod
    def from_mapping(cls, value):
        if (type(value) is not dict or set(value) != _FIELDS
                or type(value["schema_version"]) is not int or value["schema_version"] != 1):
            raise InstallationConfigError("exact_installation_fields_required")
        return cls(**{key: value[key] for key in _FIELDS - {"schema_version"}})

    def as_dict(self):
        return {"schema_version": 1, **asdict(self)}

    @property
    def identity(self):
        return self.project_id, self.account_id, self.region, self.limit_microusd

    def assert_target(self, account_id, region):
        """Compare an independently observed target before operator cloud actions."""
        if (account_id, region) != (self.account_id, self.region):
            raise InstallationConfigError("installation_target_mismatch")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InstallationConfigError("duplicate_installation_field")
        value[key] = item
    return value


def load_installation(path: str | Path) -> InstallationConfig:
    """Load a bounded, regular operator/root-owned file without following links.

    The parent directory and caller identity must also be operator-controlled.
    No environment value or invocation field can substitute an account or cap.
    """
    path = Path(path)
    if not path.is_absolute():
        raise InstallationConfigError("absolute_installation_config_required")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise InstallationConfigError("trusted_installation_config_required") from None
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(before.st_mode) & 0o022
                or not 0 < before.st_size <= MAX_CONFIG_BYTES):
            raise InstallationConfigError("trusted_installation_config_required")
        raw = b""
        while len(raw) <= MAX_CONFIG_BYTES:
            chunk = os.read(descriptor, MAX_CONFIG_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
        if (len(raw) > MAX_CONFIG_BYTES or len(raw) != before.st_size
                or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise InstallationConfigError("installation_config_changed_or_oversized")
    finally:
        os.close(descriptor)
    try:
        return InstallationConfig.from_mapping(json.loads(raw, object_pairs_hook=_unique))
    except (ValueError, TypeError, UnicodeError):
        raise InstallationConfigError("invalid_installation_config") from None
