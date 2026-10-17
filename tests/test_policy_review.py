"""Offline policy review never turns recorded policy data into authority."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import stat

import pytest

from controller import policy_review as review
from controller.durable import DurableAuthority, _digest
from controller.engine import Attempt
from controller.service import Broker


def reseal(snapshot):
    """Model a caller able to rewrite every self-consistency hash."""
    snapshot["policy_pin"] = _digest(snapshot["configuration"]["validation_policy"])
    snapshot["config_pin"] = _digest(snapshot["configuration"])
    snapshot["review_id"] = _digest({key: value for key, value in snapshot.items()
                                   if key != "review_id"})
    return snapshot


@pytest.fixture
def snapshot():
    return review.inspect_policy("recruiting")


@pytest.mark.parametrize("workflow,budget,runtime", [
    ("recruiting", 30, 60), ("document-processing", 0, 0.5),
    ("recruiting", 1_000_000, 3600),
])
def test_snapshot_pin_matches_actual_admitted_authority(tmp_path, workflow, budget, runtime):
    inspected = review.inspect_policy(workflow, budget_microusd=budget, runtime_seconds=runtime)
    with Broker(tmp_path / "state", "synthetic-admin-" + "x" * 32) as broker:
        admitted = broker.create({"workflow": workflow, "budget_microusd": budget,
                                  "runtime_seconds": runtime})
        actual = broker.authority(broker.job(admitted["job_id"]))
        assert inspected["config_pin"] == actual.config_pin
        assert inspected["policy_pin"] == actual.validator.policy_pin
    assert inspected == review.inspect_policy(workflow, budget_microusd=budget,
                                               runtime_seconds=runtime)


def test_inspect_is_read_only_and_excludes_fixture_and_ambient_credentials(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("policy inspection attempted a state write, broker startup or network access")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-private-provider-canary")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-private-aws-canary")
    monkeypatch.setattr(Broker, "__init__", forbidden)
    monkeypatch.setattr(DurableAuthority, "__init__", forbidden)
    monkeypatch.setattr(review.os, "open", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    inspected = review.inspect_policy("recruiting")
    encoded = json.dumps(inspected)
    assert list(tmp_path.iterdir()) == []
    assert "Fictional Ada" not in encoded
    assert "synthetic-private-provider-canary" not in encoded
    assert "synthetic-private-aws-canary" not in encoded
    assert inspected["kind"] == "policy_review_only"
    assert "record" not in inspected["configuration"]


def test_source_only_change_remains_visible_without_claiming_semantic_equivalence(snapshot):
    changed = deepcopy(snapshot)
    changed["configuration"]["validation_policy"]["definition_sha256"] = "9" * 64
    reseal(changed)
    result = review.compare_policies(snapshot, changed)
    assert not result["same_configuration_pin"]
    assert result["permissions_added"] == result["permissions_removed"] == []
    assert [change["field"] for change in result["changes"]] == [
        "validation_policy.definition_sha256"]
    assert result["semantic_equivalence"] == "not_established"
    assert result["recovery_requirement"] == "matching_trusted_configuration_and_existing_state_checks"


def test_comparison_reports_exact_resource_recipient_and_other_security_changes(snapshot):
    changed = deepcopy(snapshot)
    config = changed["configuration"]
    contract = config["contract"]
    before_cap = deepcopy(contract["capabilities"][0])
    contract["capabilities"][0].update(resource="different-object", recipient="different-receiver")
    after_cap = deepcopy(contract["capabilities"][0])
    contract["limits"]["max_children"] = 1
    contract["exact_approval_actions"] = ["report.write"]
    contract["step_dependencies"]["write"] = ["read", "slow"]
    contract["required_context"]["read"] = ["record_id"]
    config["budget_microusd"] = 20
    config["prices"]["record.read"] = 3
    config["validation_policy"]["fixture_sha256"] = "8" * 64
    reseal(changed)
    result = review.compare_policies(snapshot, changed)
    assert result["permissions_removed"] == [before_cap]
    assert result["permissions_added"] == [after_cap]
    fields = {change["field"] for change in result["changes"]}
    assert fields == {"contract.limits.max_children", "contract.exact_approval_actions",
                      "contract.step_dependencies.write", "contract.required_context.read",
                      "budget_microusd", "prices.record.read", "validation_policy.fixture_sha256"}


@pytest.mark.parametrize("change", [
    lambda s: s.update(schema_version=True),
    lambda s: s.update(activation="approved"),
    lambda s: s["configuration"].update(import_path="untrusted.module:authorize"),
    lambda s: s["configuration"]["contract"].update(callback="untrusted.py"),
    lambda s: s["configuration"].update(budget_microusd=True),
    lambda s: s["configuration"]["prices"].update({"record.read": True}),
    lambda s: s["configuration"]["contract"]["limits"].update(runtime_seconds=True),
    lambda s: s["configuration"]["contract"]["limits"].update(max_children=True),
    lambda s: s["configuration"]["contract"]["capabilities"][0].update(resource=0),
    lambda s: s["configuration"]["contract"]["step_dependencies"].update(write=["missing"]),
    lambda s: s["configuration"]["contract"]["step_dependencies"].update(read=["write"]),
    lambda s: s["configuration"]["validation_policy"].update(mode="synthetic_test"),
    lambda s: s["configuration"]["validation_policy"].update(definition_sha256="not-a-digest"),
])
def test_resealed_malformed_records_cannot_be_treated_as_valid_policy(snapshot, change):
    change(snapshot)
    reseal(snapshot)
    with pytest.raises(review.PolicyReviewError):
        review.validate_snapshot(snapshot)


@pytest.mark.parametrize("field", ["config_pin", "policy_pin", "review_id"])
def test_independently_forged_hash_is_rejected(snapshot, field):
    snapshot[field] = "0" * 64
    with pytest.raises(review.PolicyReviewError):
        review.validate_snapshot(snapshot)


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":1}',
    b'{"configuration":{"prices":{"read":1,"read":2}}}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
    b'\xff', b'[]', b'null', b'"plain string"',
    b'[' * 1500 + b']' * 1500,
])
def test_untrusted_json_input_fails_with_safe_error(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with pytest.raises(review.PolicyReviewError) as failure:
        review.read_snapshot(path)
    assert str(failure.value) in {"invalid_policy_json", "invalid_policy_file", "invalid_policy_snapshot"}


def test_oversized_symlink_and_fifo_reads_are_rejected_without_blocking(tmp_path):
    oversized = tmp_path / "large.json"
    oversized.write_bytes(b" " * (review.MAX_BYTES + 1))
    linked = tmp_path / "link.json"
    linked.symlink_to(oversized)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    for path in (oversized, linked, fifo):
        with pytest.raises(review.PolicyReviewError):
            review.read_snapshot(path)


def test_private_capture_is_idempotent_and_history_grants_no_authority(tmp_path, snapshot):
    archive = tmp_path / "reviews"
    path = review.capture_policy(archive, snapshot)
    contents, modified = path.read_bytes(), path.stat().st_mtime_ns
    assert stat.S_IMODE(archive.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.name == snapshot["review_id"] + ".json"
    assert review.read_snapshot(path) == snapshot
    assert review.capture_policy(archive, snapshot) == path
    assert (path.read_bytes(), path.stat().st_mtime_ns) == (contents, modified)
    history = review.policy_history(archive)
    assert history["activation"] == "not_performed"
    assert history["provenance"] == "local_review_records_not_signed_approvals"
    assert history["reviews"][0]["config_pin"] == snapshot["config_pin"]
    assert "Fictional Ada" not in json.dumps(history)
    assert not list(tmp_path.rglob("*.sqlite"))


def test_fully_resealed_review_record_cannot_expand_a_real_job_permission(tmp_path, snapshot):
    # A review file can be self-consistent without having trusted provenance.
    # Saving it must never register its advertised permission with the broker.
    changed = deepcopy(snapshot)
    changed["configuration"]["contract"]["capabilities"][0]["resource"] = "outside-scope"
    reseal(changed)
    review.capture_policy(tmp_path / "reviews", changed)
    assert review.policy_history(tmp_path / "reviews")["activation"] == "not_performed"
    with Broker(tmp_path / "state", "synthetic-admin-" + "x" * 32) as broker:
        created = broker.create({"workflow": "recruiting"})
        job = broker.job(created["job_id"])
        assert broker.authority(job).config_pin == snapshot["config_pin"]
        assert broker.authority(job).config_pin != changed["config_pin"]
        result = broker.authorize(job, created["token"], created["run_id"],
                                  Attempt("outside-read", "read", "record.read", "outside-scope",
                                          "worker", {}))
        assert result["status"] == "denied"
        assert broker.snapshot(job, created["token"])["effects_count"] == 0


def test_capture_refuses_corrupt_record_instead_of_overwriting_it(tmp_path, snapshot):
    archive = tmp_path / "reviews"
    path = review.capture_policy(archive, snapshot)
    path.write_text('{"private_canary":"must-stay-private"}')
    before = path.read_bytes()
    with pytest.raises(review.PolicyReviewError):
        review.capture_policy(archive, snapshot)
    assert path.read_bytes() == before


def test_capture_under_restrictive_umask_remains_readable_and_private(tmp_path, snapshot):
    archive = tmp_path / "reviews"
    archive.mkdir(mode=0o700)
    previous = os.umask(0o777)
    try:
        path = review.capture_policy(archive, snapshot)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert review.read_snapshot(path) == snapshot
    assert len(review.policy_history(archive)["reviews"]) == 1


@pytest.mark.parametrize("kind", ["directory_symlink", "parent_symlink", "entry_symlink",
                                   "entry_hardlink", "entry_world_readable", "archive_world_readable",
                                   "wrong_filename", "unknown_entry"])
def test_archive_rejects_aliases_insecure_files_and_unrecognized_entries(tmp_path, snapshot, kind):
    archive = tmp_path / "reviews"
    path = review.capture_policy(archive, snapshot)
    candidate = archive
    if kind == "directory_symlink":
        candidate = tmp_path / "alias"
        candidate.symlink_to(archive, target_is_directory=True)
    elif kind == "parent_symlink":
        parent = tmp_path / "parent-alias"
        parent.symlink_to(tmp_path, target_is_directory=True)
        candidate = parent / "reviews"
    elif kind == "entry_symlink":
        outside = tmp_path / "outside.json"
        path.rename(outside)
        path.symlink_to(outside)
    elif kind == "entry_hardlink":
        os.link(path, tmp_path / "outside.json")
    elif kind == "entry_world_readable":
        path.chmod(0o644)
    elif kind == "archive_world_readable":
        archive.chmod(0o755)
    elif kind == "wrong_filename":
        path.rename(archive / ("0" * 64 + ".json"))
    else:
        (archive / "readme.txt").write_text("not a policy review")
    with pytest.raises(review.PolicyReviewError):
        review.policy_history(candidate)
    with pytest.raises(review.PolicyReviewError):
        review.capture_policy(candidate, snapshot)


def test_archive_limit_rejects_new_revision_without_losing_saved_history(tmp_path, snapshot, monkeypatch):
    archive = tmp_path / "reviews"
    saved = review.capture_policy(archive, snapshot)
    monkeypatch.setattr(review, "MAX_REVIEWS", 1)
    changed = review.inspect_policy("recruiting", budget_microusd=31)
    with pytest.raises(review.PolicyReviewError, match="^policy_archive_full$"):
        review.capture_policy(archive, changed)
    assert review.read_snapshot(saved) == snapshot
    assert len(review.policy_history(archive)["reviews"]) == 1


def test_cli_inspect_capture_history_compare_and_private_failure(tmp_path, capsys):
    archive = tmp_path / "reviews"
    assert review.main(["inspect", "--workflow", "recruiting"]) == 0
    inspected = json.loads(capsys.readouterr().out)
    saved = []
    for budget in (30, 31):
        assert review.main(["capture", "--workflow", "recruiting", "--archive", str(archive),
                            "--budget-microusd", str(budget)]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["activation"] == "not_performed"
        saved.append(result["path"])
    assert review.read_snapshot(saved[0]) == inspected
    assert review.main(["history", "--archive", str(archive)]) == 0
    assert len(json.loads(capsys.readouterr().out)["reviews"]) == 2
    assert review.main(["compare", "--before", saved[0], "--after", saved[1]]) == 0
    comparison = json.loads(capsys.readouterr().out)
    assert comparison["changes"] == [{"field": "budget_microusd", "before": 30, "after": 31}]
    broken = tmp_path / "broken.json"
    broken.write_text('{"canary":"private-input-must-not-echo"}')
    assert review.main(["compare", "--before", str(broken), "--after", saved[1]]) == 2
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": "rejected", "reason": "policy_review_failed"}
    assert "private-input-must-not-echo" not in output.out + output.err
