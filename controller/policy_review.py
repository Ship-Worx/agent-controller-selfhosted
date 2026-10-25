"""Offline review records for trusted workflow contracts; grants no authority.

Snapshots describe compiled operator-owned policy. Stored JSON is never loaded
as executable policy, used to authorize a job, or used to repair a state pin.
Hashes establish internal consistency, not signer identity or policy approval.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from controller.durable import _digest, _plain
from controller.engine import Capability, Contract, Limits
from workflows.definitions import PRICES, WORKFLOWS


MAX_BYTES = 262_144
MAX_REVIEWS = 256
_HASH = re.compile(r"[0-9a-f]{64}")
_OUTER = {"schema_version", "kind", "configuration", "config_pin", "policy_pin", "review_id"}
_CONFIG = {"contract", "prices", "budget_microusd", "validation_policy"}
_CONTRACT = {
    "workflow_id", "version", "purpose", "capabilities", "required_context", "limits",
    "exact_approval_actions", "allowed_principals", "payload_fields", "handoff_actions",
    "delegable_context_fields", "step_dependencies", "validation_policy",
}
_VALIDATOR = {
    "mode", "policy_id", "policy_version", "definition_sha256", "fixture_sha256", "pricing_pin",
}


class PolicyReviewError(ValueError):
    """Safe review failure code, with no contents from the input file."""


def _require(condition, reason="invalid_policy_snapshot"):
    if not condition:
        raise PolicyReviewError(reason)


def _fields(value, expected):
    _require(type(value) is dict and set(value) == expected)


def _name(value):
    _require(type(value) is str and 1 <= len(value) <= 512)


def _hash(value):
    _require(type(value) is str and _HASH.fullmatch(value) is not None)


def _names(value):
    _require(type(value) is list and len(value) <= 128)
    for item in value:
        _name(item)
    _require(len(value) == len(set(value)))


def _name_map(value):
    _require(type(value) is dict and len(value) <= 128)
    for key, items in value.items():
        _name(key)
        _names(items)


def _review_id(snapshot):
    return _digest({key: value for key, value in snapshot.items() if key != "review_id"})


def validate_snapshot(snapshot):
    """Validate data and its hashes without importing code named by the record."""
    _fields(snapshot, _OUTER)
    _require(type(snapshot["schema_version"]) is int and snapshot["schema_version"] == 1)
    _require(snapshot["kind"] == "policy_review_only")
    for key in ("config_pin", "policy_pin", "review_id"):
        _hash(snapshot[key])
    config = snapshot["configuration"]
    _fields(config, _CONFIG)
    _require(type(config["budget_microusd"]) is int and 0 <= config["budget_microusd"] <= 1_000_000)
    prices = config["prices"]
    _require(type(prices) is dict and 1 <= len(prices) <= 128)
    for action, price in prices.items():
        _name(action)
        _require(type(price) is int and 0 <= price <= 1_000_000_000_000)
    contract = config["contract"]
    _fields(contract, _CONTRACT)
    for key in ("workflow_id", "version", "purpose", "validation_policy"):
        _name(contract[key])
    for key in ("exact_approval_actions", "handoff_actions", "delegable_context_fields"):
        _names(contract[key])
    for key in ("required_context", "payload_fields", "step_dependencies"):
        _name_map(contract[key])
    _require(type(contract["capabilities"]) is list and 1 <= len(contract["capabilities"]) <= 128)
    capabilities = []
    for cap in contract["capabilities"]:
        _fields(cap, {"step", "action", "resource", "recipient"})
        for value in cap.values():
            _name(value)
        capabilities.append(Capability(**cap))
    principals = contract["allowed_principals"]
    _require(type(principals) is list and len(principals) <= 128)
    for principal in principals:
        _require(type(principal) is list and len(principal) == 2)
        for value in principal:
            _name(value)
    limits = contract["limits"]
    _fields(limits, {"budget_calls", "input_bytes", "runtime_seconds", "max_children", "max_depth"})
    _require(type(limits["runtime_seconds"]) in (int, float) and 0 < limits["runtime_seconds"] <= 3600)
    try:
        restored = Contract(**{**contract, "capabilities": frozenset(capabilities),
                              "allowed_principals": frozenset(tuple(p) for p in principals),
                              "limits": Limits(**limits)})
        _require(_plain(restored) == contract)
    except (TypeError, ValueError):
        raise PolicyReviewError("invalid_policy_snapshot") from None
    actions = {cap.action for cap in capabilities}
    steps = {cap.step for cap in capabilities}
    _require(actions <= prices.keys() and actions <= contract["payload_fields"].keys())
    _require(steps <= contract["required_context"].keys() and steps <= contract["step_dependencies"].keys())
    _require(set(contract["exact_approval_actions"]) <= actions)
    for dependencies in contract["step_dependencies"].values():
        _require(set(dependencies) <= steps)
    visited, visiting = set(), set()

    def visit(step):
        _require(step not in visiting)
        if step not in visited:
            visiting.add(step)
            for dependency in contract["step_dependencies"].get(step, []):
                visit(dependency)
            visiting.remove(step)
            visited.add(step)

    for step in steps:
        visit(step)
    validator = config["validation_policy"]
    _fields(validator, _VALIDATOR)
    _require(validator["mode"] == "reviewed" and validator["policy_id"] == contract["validation_policy"])
    for key in ("policy_id", "policy_version"):
        _name(validator[key])
    for key in ("definition_sha256", "fixture_sha256"):
        _hash(validator[key])
    if validator["pricing_pin"] is not None:
        _hash(validator["pricing_pin"])
    _require(snapshot["policy_pin"] == _digest(validator), "policy_pin_mismatch")
    _require(snapshot["config_pin"] == _digest(config), "configuration_pin_mismatch")
    _require(snapshot["review_id"] == _review_id(snapshot), "review_id_mismatch")
    return snapshot


def inspect_policy(workflow, *, runtime_seconds=60, budget_microusd=30):
    """Describe the current trusted synthetic contract without opening any DB.

    Runtime is normalized exactly as Broker.create normalizes SQLite REAL input.
    The configuration hash uses the existing durable authority serialization.
    Live provider policy additionally needs private pricing and is excluded.
    """
    _require(type(workflow) is str and workflow in WORKFLOWS, "unknown_workflow")
    _require(type(runtime_seconds) in (int, float) and 0 < runtime_seconds <= 3600,
             "invalid_runtime")
    _require(type(budget_microusd) is int and 0 <= budget_microusd <= 1_000_000,
             "invalid_budget")
    definition = WORKFLOWS[workflow]
    contract = definition.contract(float(runtime_seconds))
    validator = definition.validator(contract)
    validator.check(contract)
    config = _plain({"contract": contract, "prices": dict(PRICES),
                     "budget_microusd": budget_microusd, "validation_policy": validator.policy})
    snapshot = {"schema_version": 1, "kind": "policy_review_only", "configuration": config,
                "config_pin": _digest(config), "policy_pin": validator.policy_pin}
    snapshot["review_id"] = _review_id(snapshot)
    return validate_snapshot(snapshot)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "invalid_policy_json")
        result[key] = value
    return result


def _nonfinite(_value):
    raise PolicyReviewError("invalid_policy_json")


def read_snapshot(path):
    """Bounded regular-file read; never create, recover or update state files."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_BYTES, "invalid_policy_file")
            raw = stream.read(MAX_BYTES + 1)
        _require(len(raw) <= MAX_BYTES, "policy_file_too_large")
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_nonfinite)
        return validate_snapshot(value)
    except PolicyReviewError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        raise PolicyReviewError("invalid_policy_file") from None


def compare_policies(before, after):
    """Describe changes; matching visible permissions do not prove equivalence."""
    before, after = validate_snapshot(before), validate_snapshot(after)
    old, new = before["configuration"], after["configuration"]
    old_caps = {_digest(cap): cap for cap in old["contract"]["capabilities"]}
    new_caps = {_digest(cap): cap for cap in new["contract"]["capabilities"]}
    changes = []

    def compare(left, right, prefix):
        if type(left) is dict and type(right) is dict:
            for key in sorted(left.keys() | right.keys()):
                if prefix == "contract" and key == "capabilities":
                    continue
                compare(left.get(key), right.get(key), prefix + "." + key if prefix else key)
        elif left != right:
            changes.append({"field": prefix, "before": left, "after": right})

    compare(old, new, "")
    return {"kind": "policy_comparison_only", "before_review_id": before["review_id"],
            "after_review_id": after["review_id"],
            "same_configuration_pin": before["config_pin"] == after["config_pin"],
            "permissions_added": [new_caps[key] for key in sorted(new_caps.keys() - old_caps.keys())],
            "permissions_removed": [old_caps[key] for key in sorted(old_caps.keys() - new_caps.keys())],
            "changes": changes, "semantic_equivalence": "not_established",
            "recovery_requirement": "matching_trusted_configuration_and_existing_state_checks"}


def _archive_directory(path, *, create=False):
    path = Path(os.path.abspath(path))
    try:
        # Reject aliases before creating a directory or opening an archive file.
        for entry in (*reversed(path.parents), path):
            if entry.is_symlink():
                raise PolicyReviewError("unsafe_policy_archive")
        if create:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                 and info.st_uid == os.geteuid(), "unsafe_policy_archive")
        return path
    except OSError:
        raise PolicyReviewError("unsafe_policy_archive") from None


def _archive_entries(directory):
    entries = []
    try:
        for path in directory.iterdir():
            _require(len(entries) < MAX_REVIEWS, "policy_archive_full")
            _require(re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is not None,
                     "invalid_policy_archive_entry")
            info = path.lstat()
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600,
                     "unsafe_policy_archive_entry")
            snapshot = read_snapshot(path)
            _require(path.stem == snapshot["review_id"], "archive_revision_mismatch")
            entries.append((path, info, snapshot))
        return entries
    except OSError:
        raise PolicyReviewError("invalid_policy_archive") from None


def capture_policy(archive, snapshot):
    """Save an immutable review record, without activation or approval semantics."""
    snapshot = validate_snapshot(snapshot)
    directory = _archive_directory(archive, create=True)
    entries = _archive_entries(directory)
    target = directory / (snapshot["review_id"] + ".json")
    for path, _info, existing in entries:
        if path == target:
            _require(existing == snapshot, "archive_revision_mismatch")
            return target
    _require(len(entries) < MAX_REVIEWS, "policy_archive_full")
    raw = (json.dumps(snapshot, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    _require(len(raw) <= MAX_BYTES, "policy_file_too_large")
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return target
    except OSError:
        raise PolicyReviewError("policy_capture_failed") from None


def policy_history(archive):
    entries = _archive_entries(_archive_directory(archive))
    return {"kind": "policy_review_history_only", "reviews": [
        {"review_id": snapshot["review_id"], "workflow": snapshot["configuration"]["contract"]["workflow_id"],
         "contract_version": snapshot["configuration"]["contract"]["version"],
         "policy_version": snapshot["configuration"]["validation_policy"]["policy_version"],
         "config_pin": snapshot["config_pin"],
         "archive_file_modified_at_utc": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat()}
        for _path, info, snapshot in sorted(entries, key=lambda entry: (entry[1].st_mtime_ns, entry[0].name))],
        "activation": "not_performed", "provenance": "local_review_records_not_signed_approvals"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "capture"):
        sub = commands.add_parser(command)
        sub.add_argument("--workflow", required=True, choices=sorted(WORKFLOWS))
        sub.add_argument("--runtime-seconds", type=float, default=60)
        sub.add_argument("--budget-microusd", type=int, default=30)
        if command == "capture":
            sub.add_argument("--archive", type=Path, required=True)
    sub = commands.add_parser("history")
    sub.add_argument("--archive", type=Path, required=True)
    sub = commands.add_parser("compare")
    sub.add_argument("--before", type=Path, required=True)
    sub.add_argument("--after", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in {"inspect", "capture"}:
            snapshot = inspect_policy(args.workflow, runtime_seconds=args.runtime_seconds,
                                      budget_microusd=args.budget_microusd)
            if args.command == "capture":
                path = capture_policy(args.archive, snapshot)
                value = {"kind": "policy_review_saved", "path": str(path),
                         "review_id": snapshot["review_id"], "config_pin": snapshot["config_pin"],
                         "activation": "not_performed"}
            else:
                value = snapshot
        elif args.command == "history":
            value = policy_history(args.archive)
        else:
            value = compare_policies(read_snapshot(args.before), read_snapshot(args.after))
    except (PolicyReviewError, ValueError, TypeError, RecursionError, OverflowError):
        print(json.dumps({"status": "rejected", "reason": "policy_review_failed"}))
        return 2
    print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
