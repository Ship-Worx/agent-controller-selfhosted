"""Offline evidence for the fixed STS receiver; no AWS request is performed.

The fake adapter is an independent dispatch journal. Assertions distinguish an
issued reservation, an authorized dispatch, a measured result, and an unknown
outcome rather than accepting an agent's success message as execution proof.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading

import pytest

from controller.aws_identity import (AWSIdentityController, IdentityConfig, MAX_BRIDGE_BYTES,
                                     build_contract, private_directory, read_private_json,
                                     write_private_json)
from controller.engine import Attempt, Binding


ACCOUNT = "123456789012"
REGION = "us-east-1"
PRINCIPAL = "arn:aws:sts::123456789012:assumed-role/OfflineRole/session"
PRINCIPAL_HASH = hashlib.sha256(PRINCIPAL.encode()).hexdigest()
REQUEST_ID_HASH = hashlib.sha256(b"fictional-aws-request-id").hexdigest()
CONFIG = IdentityConfig(ACCOUNT, REGION, PRINCIPAL_HASH)


class RecordingAdapter:
    def __init__(self):
        self.calls = []
        self.change = lambda value: value

    def __call__(self, request):
        # Detach the test's evidence from any caller mutation after dispatch.
        self.calls.append(json.loads(json.dumps(request)))
        receipt = {
            "schema_version": 1,
            "request_nonce": request["request_nonce"],
            "source": "aws_mcp",
            "api_call_status": "success",
            "account_matches": True,
            "principal_sha256": PRINCIPAL_HASH,
            "request_id_sha256": None,
            "http_status": None,
        }
        return self.change(receipt)


@pytest.fixture
def receiver(tmp_path):
    adapter = RecordingAdapter()
    controller = AWSIdentityController(tmp_path / "controller", CONFIG, adapter)
    try:
        yield controller, adapter
    finally:
        controller.close()


def audit_count(controller, event):
    with sqlite3.connect(controller.authority.path) as connection:
        return connection.execute("SELECT count(*) FROM audit WHERE event=?", (event,)).fetchone()[0]


def plain(value):
    from collections.abc import Mapping
    if isinstance(value, Mapping):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [plain(item) for item in value]
    return value


def test_trusted_contract_names_only_one_fixed_read_only_aws_operation():
    contract = build_contract(CONFIG)
    assert {(cap.step, cap.action, cap.resource, cap.recipient) for cap in contract.capabilities} == {
        ("identity", "sts.GetCallerIdentity", "aws-account:" + ACCOUNT, "worker")
    }
    assert tuple(contract.payload_fields["sts.GetCallerIdentity"]) == ()
    assert contract.validation_policy
    assert contract.limits.max_children == 0


def test_allowed_request_dispatches_once_and_returns_only_sanitized_evidence(receiver):
    controller, adapter = receiver
    result = controller.act(controller.token, controller.proposal())
    assert result["status"] == "allowed", result
    assert len(adapter.calls) == 1
    request = adapter.calls[0]
    assert set(request) == {"schema_version", "service", "operation", "region", "params",
                            "request_nonce", "run_id_hash", "operation_id_hash", "config_pin"}
    assert (request["schema_version"], request["service"], request["operation"],
            request["region"], request["params"]) == (1, "sts", "GetCallerIdentity", REGION, {})
    assert len(request["request_nonce"]) == 32
    assert request["run_id_hash"] == hashlib.sha256(controller.snapshot().run_id.encode()).hexdigest()
    assert request["operation_id_hash"] == hashlib.sha256(b"identity-allowed").hexdigest()
    assert request["config_pin"] == controller.authority.config_pin
    assert result["receipt"]["principal_sha256"] == PRINCIPAL_HASH
    assert result["receipt"]["source"] == "aws_mcp"
    assert result["receipt"]["api_call_status"] == "success"
    assert result["receipt"]["request_id_sha256"] is None
    assert result["receipt"]["http_status"] is None
    encoded = json.dumps(plain(result))
    for private in (PRINCIPAL, ACCOUNT, controller.token, "fictional-aws-request-id"):
        assert private not in encoded
    assert audit_count(controller, "dispatch_authorized") == 1
    assert audit_count(controller, "settled") == 1
    snapshot = controller.snapshot()
    assert (snapshot.calls_used, snapshot.unknown_operations) == (1, ())


@pytest.mark.parametrize("changes", [
    {"resource": "aws-account:210987654321"},
    {"action": "s3.ListBuckets"},
    {"action": "iam.CreateUser"},
    {"recipient": "external-destination"},
    {"step": "other-step"},
    {"payload": {"region": "eu-west-1"}},
    {"payload": {"endpoint_url": "https://attacker.invalid"}},
    {"payload": {"RoleArn": "arn:aws:iam::210987654321:role/OtherRole"}},
])
def test_out_of_contract_request_never_reaches_aws_adapter(receiver, changes):
    controller, adapter = receiver
    result = controller.act(controller.token, controller.proposal(**changes))
    assert result["status"] == "denied", result
    assert adapter.calls == []
    assert audit_count(controller, "dispatch_authorized") == 0
    assert "receipt" not in result


@pytest.mark.parametrize("extra", [
    {"region": "eu-west-1"},
    {"endpoint_url": "https://attacker.invalid"},
    {"adapter": "attacker_callback"},
    {"expected_account": "210987654321"},
    {"expected_principal_sha256": "a" * 64},
])
def test_worker_cannot_supply_trusted_receiver_configuration(receiver, extra):
    controller, adapter = receiver
    result = controller.act(controller.token, {**controller.proposal(), **extra})
    assert result["status"] == "denied", result
    assert adapter.calls == []


def test_reservation_alone_is_not_an_aws_dispatch(receiver):
    controller, adapter = receiver
    reserved = controller.reserve(controller.token, controller.proposal())
    assert reserved.status == "reserved"
    assert reserved.ticket
    assert adapter.calls == []
    assert audit_count(controller, "dispatch_authorized") == 0
    assert controller.snapshot().calls_used == 1


def test_stop_after_reservation_blocks_dispatch(receiver):
    controller, adapter = receiver
    reserved = controller.reserve(controller.token, controller.proposal())
    controller.stop()
    result = controller.execute(controller.token, reserved.ticket)
    assert (result.status, result.reason) == ("denied", "root_stopped")
    assert adapter.calls == []
    assert audit_count(controller, "dispatch_authorized") == 0
    assert controller.snapshot().stopped


def test_unknown_token_or_ticket_cannot_dispatch(receiver):
    controller, adapter = receiver
    reserved = controller.reserve(controller.token, controller.proposal())
    for token, ticket in (("not-a-controller-token", reserved.ticket),
                          (controller.token, "not-an-issued-ticket")):
        result = controller.execute(token, ticket)
        assert result.status == "denied", result
    assert adapter.calls == []
    assert audit_count(controller, "dispatch_authorized") == 0


def test_ticket_from_another_admitted_run_cannot_select_its_authority(receiver):
    controller, adapter = receiver
    other_token = controller.authority.admit(
        Binding("aws-demo", "operator", "other-session", "other-worker"), dict(controller.context))
    attempt = Attempt(**controller.proposal(operation_id="other-run"))
    other = controller.authority.reserve(other_token, attempt)
    assert other.status == "reserved", other
    result = controller.execute(controller.token, other.ticket)
    assert result.status == "denied", result
    assert adapter.calls == []
    assert audit_count(controller, "dispatch_authorized") == 0


def test_duplicate_operation_reuses_evidence_without_a_second_aws_call(receiver):
    controller, adapter = receiver
    proposal = controller.proposal()
    first = controller.act(controller.token, proposal)
    second = controller.act(controller.token, proposal)
    assert first["status"] == second["status"] == "allowed"
    assert second["replayed"]
    assert first["receipt"] == second["receipt"]
    assert len(adapter.calls) == 1
    assert audit_count(controller, "dispatch_authorized") == 1
    assert controller.snapshot().calls_used == 1


def test_reusing_operation_id_with_different_payload_cannot_make_another_call(receiver):
    controller, adapter = receiver
    assert controller.act(controller.token, controller.proposal())["status"] == "allowed"
    changed = controller.act(controller.token, controller.proposal(payload={"region": "eu-west-1"}))
    assert changed["status"] == "denied"
    assert len(adapter.calls) == 1
    assert audit_count(controller, "dispatch_authorized") == 1


@pytest.mark.parametrize("change", [
    lambda value: {**value, "account_matches": False},
    lambda value: {**value, "account_matches": 1},
    lambda value: {**value, "principal_sha256": "a" * 64},
    lambda value: {**value, "request_nonce": "0" * 32},
    lambda value: {**value, "request_id_sha256": "not-a-digest"},
    lambda value: {**value, "http_status": 403},
    lambda value: {**value, "http_status": True},
    lambda value: {**value, "source": "agent_claim"},
    lambda value: {**value, "api_call_status": "error"},
    lambda value: {**value, "schema_version": True},
    lambda value: {**value, "raw_response": {"Arn": PRINCIPAL, "Account": ACCOUNT}},
    lambda value: {key: item for key, item in value.items() if key != "http_status"},
    lambda value: None,
])
def test_unconfirmed_adapter_response_is_held_unknown_and_never_retried(receiver, change):
    controller, adapter = receiver
    adapter.change = change
    proposal = controller.proposal()
    first = controller.act(controller.token, proposal)
    assert first["status"] == "held", first
    assert "receipt" not in first
    snapshot = controller.snapshot()
    assert snapshot.unknown_operations == (proposal["operation_id"],)
    assert snapshot.calls_used == 1
    assert audit_count(controller, "settled") == 0
    assert controller.act(controller.token, proposal)["status"] != "allowed"
    assert controller.act(controller.token, controller.proposal(operation_id="new-operation"))["status"] != "allowed"
    assert len(adapter.calls) == 1
    assert audit_count(controller, "dispatch_authorized") == 1
    assert PRINCIPAL not in json.dumps(plain(first))


def test_adapter_exception_keeps_unknown_state_without_exposing_exception_contents(receiver):
    controller, adapter = receiver
    secret = "secret-value-and-provider-response-must-not-escape"
    def fail(_receipt):
        raise TimeoutError(secret)
    adapter.change = fail
    result = controller.act(controller.token, controller.proposal())
    assert result["status"] == "held", result
    assert secret not in json.dumps(result)
    assert "receipt" not in result
    assert controller.snapshot().unknown_operations == ("identity-allowed",)
    assert controller.act(controller.token, controller.proposal())["status"] != "allowed"
    assert len(adapter.calls) == 1


def test_old_issued_ticket_is_fenced_after_controller_restart(receiver, tmp_path):
    controller, adapter = receiver
    token = controller.token
    reserved = controller.reserve(token, controller.proposal())
    assert reserved.status == "reserved"
    controller.close()
    restarted = AWSIdentityController(tmp_path / "controller", CONFIG, adapter)
    try:
        assert restarted.execute(token, reserved.ticket).status == "denied"
        assert restarted.execute(restarted.token, reserved.ticket).status == "denied"
        assert adapter.calls == []
        assert audit_count(restarted, "dispatch_authorized") == 0
    finally:
        restarted.close()


def test_unknown_outcome_survives_restart_and_cannot_call_adapter_again(receiver, tmp_path):
    controller, adapter = receiver
    adapter.change = lambda value: {**value, "account_matches": False}
    token = controller.token
    reserved = controller.reserve(token, controller.proposal())
    assert controller.execute(token, reserved.ticket).status == "held"
    controller.close()
    restarted = AWSIdentityController(tmp_path / "controller", CONFIG, adapter)
    try:
        assert restarted.execute(token, reserved.ticket).status != "allowed"
        assert restarted.execute(restarted.token, reserved.ticket).status != "allowed"
        assert len(adapter.calls) == 1
        old = restarted.authority.snapshot(token)
        assert old.unknown_operations == ("identity-allowed",)
        assert audit_count(restarted, "dispatch_authorized") == 1
    finally:
        restarted.close()


def test_stop_during_existing_dispatch_blocks_receipt_and_future_dispatch(receiver):
    controller, adapter = receiver
    entered, finish = threading.Event(), threading.Event()
    def delayed(receipt):
        entered.set()
        assert finish.wait(3)
        return receipt
    adapter.change = delayed
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(controller.act, controller.token, controller.proposal())
        assert entered.wait(3)
        controller.stop()
        finish.set()
        result = pending.result(timeout=3)
    assert result["status"] == "denied", result
    assert "receipt" not in result
    assert len(adapter.calls) == 1
    assert audit_count(controller, "settled") == 1
    assert controller.act(controller.token, controller.proposal(operation_id="after-stop"))["status"] == "denied"
    assert len(adapter.calls) == 1


@pytest.mark.parametrize("change", [
    {"expected_account": "123"},
    {"expected_account": "12345678901x"},
    {"expected_account": 123456789012},
    {"region": "https://attacker.invalid"},
    {"region": "us-east-1/other"},
    {"expected_principal_sha256": "not-a-digest"},
    {"expected_principal_sha256": "A" * 64},
])
def test_invalid_trusted_configuration_cannot_construct_receiver(tmp_path, change):
    values = {"expected_account": ACCOUNT, "region": REGION,
              "expected_principal_sha256": PRINCIPAL_HASH, **change}
    adapter = RecordingAdapter()
    with pytest.raises((ValueError, TypeError)):
        config = IdentityConfig(**values)
        AWSIdentityController(tmp_path / "invalid", config, adapter)
    assert adapter.calls == []


def test_trace_correlates_authorized_dispatch_with_controller_binding(receiver):
    controller, adapter = receiver
    proposal = controller.proposal()
    result = controller.act(controller.token, proposal)
    assert result["status"] == "allowed"
    context = result["trace_context"]
    operation_hash = hashlib.sha256(proposal["operation_id"].encode()).hexdigest()
    operation_events = [event for event in controller.events
                        if event.get("operation_id_hash") == operation_hash]
    assert [event["event"] for event in operation_events] == [
        "action_proposed", "decision", "tool_started", "tool_finished", "result_release"
    ]
    for event in operation_events:
        assert event["source"] == "controller"
        for key, value in context.items():
            assert event[key] == value
    encoded = json.dumps(controller.events)
    for private in (ACCOUNT, PRINCIPAL, controller.token, proposal["operation_id"],
                    adapter.calls[0]["request_nonce"]):
        assert private not in encoded


def test_denial_records_a_decision_without_a_tool_started_event(receiver):
    controller, adapter = receiver
    proposal = controller.proposal(resource="aws-account:210987654321")
    assert controller.act(controller.token, proposal)["status"] == "denied"
    operation_hash = hashlib.sha256(proposal["operation_id"].encode()).hexdigest()
    events = [event for event in controller.events if event.get("operation_id_hash") == operation_hash]
    assert [event["event"] for event in events] == ["action_proposed", "decision"]
    assert events[-1]["status"] == "denied"
    assert adapter.calls == []


def test_bridge_files_are_private_create_once_and_do_not_overwrite(tmp_path):
    directory = private_directory(tmp_path / "bridge")
    path = directory / "request.json"
    write_private_json(path, {"request_nonce": "a" * 32})
    assert path.stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700
    assert read_private_json(path) == {"request_nonce": "a" * 32}
    with pytest.raises(FileExistsError):
        write_private_json(path, {"request_nonce": "b" * 32})
    assert read_private_json(path) == {"request_nonce": "a" * 32}


def test_bridge_file_size_limit_prevents_publishing_or_parsing_large_data(tmp_path):
    directory = private_directory(tmp_path / "bridge")
    path = directory / "request.json"
    with pytest.raises(ValueError):
        write_private_json(path, {"oversize": "x" * MAX_BRIDGE_BYTES})
    assert not path.exists()
    path.write_bytes(b'"' + b"x" * MAX_BRIDGE_BYTES + b'"')
    path.chmod(0o600)
    with pytest.raises(ValueError):
        read_private_json(path)


@pytest.mark.parametrize("data", [b'{"request_nonce":"first","request_nonce":"second"}',
                                  b'{"http_status":NaN}', b'{"http_status":Infinity}'])
def test_bridge_parser_refuses_ambiguous_or_nonfinite_json(tmp_path, data):
    path = tmp_path / "receipt.json"
    path.write_bytes(data)
    path.chmod(0o600)
    with pytest.raises(ValueError):
        read_private_json(path)


def test_bridge_parser_and_publisher_refuse_symlink_targets(tmp_path):
    original = tmp_path / "original.json"
    write_private_json(original, {"unchanged": True})
    link = tmp_path / "receipt.json"
    link.symlink_to(original)
    with pytest.raises(OSError):
        read_private_json(link)
    with pytest.raises(OSError):
        write_private_json(link, {"unchanged": False})
    assert read_private_json(original) == {"unchanged": True}


def test_bridge_parser_refuses_shared_permissions_and_hardlinks(tmp_path):
    path = tmp_path / "receipt.json"
    write_private_json(path, {"fixture": True})
    path.chmod(0o644)
    with pytest.raises(ValueError):
        read_private_json(path)
    path.chmod(0o600)
    os.link(path, tmp_path / "linked.json")
    with pytest.raises(ValueError):
        read_private_json(path)


def test_bridge_directory_refuses_existing_shared_or_symlinked_directory(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    with pytest.raises(ValueError):
        private_directory(shared)
    private = private_directory(tmp_path / "private")
    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError):
        private_directory(alias)


def test_observed_http_metadata_can_be_preserved_without_fabricating_missing_values(receiver):
    controller, adapter = receiver
    adapter.change = lambda value: {**value, "http_status": 200, "request_id_sha256": REQUEST_ID_HASH}
    result = controller.act(controller.token, controller.proposal())
    assert result["status"] == "allowed"
    assert result["receipt"]["http_status"] == 200
    assert result["receipt"]["request_id_sha256"] == REQUEST_ID_HASH
    assert len(adapter.calls) == 1


def test_sdk_agent_receives_no_operator_cloud_or_provider_credentials(tmp_path, monkeypatch):
    from demo import aws_identity
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
                "OPENAI_API_KEY", "CONTROLLER_OPENAI_API_KEY", "BRAINTRUST_API_KEY",
                "OPENAI_AGENTS_TRACING_API_KEY", "CONTROLLER_ADMIN_TOKEN"):
        monkeypatch.setenv(key, "fictional-parent-only-credential")
    actual_process = aws_identity.run_sdk_process
    environments = []
    def observe_environment(*args, **kwargs):
        environments.append(dict(kwargs["env"]))
        return actual_process(*args, **kwargs)
    monkeypatch.setattr(aws_identity, "run_sdk_process", observe_environment)
    adapter = RecordingAdapter()
    report = aws_identity.demonstrate(tmp_path / "bridge", CONFIG, tmp_path / "report", adapter=adapter)
    assert len(environments) == 1
    assert set(environments[0]) <= {"PATH", "LANG", "LC_ALL", "TMPDIR", "PYTHONUNBUFFERED",
                                    "OPENAI_AGENTS_DISABLE_TRACING", "CONTROLLER_WORKER_TOKEN"}
    assert "fictional-parent-only-credential" not in json.dumps(environments[0])
    assert environments[0]["OPENAI_AGENTS_DISABLE_TRACING"] == "1"
    assert all(item["passed"] for item in report["checks"])
    assert report["adapter_requests"] == len(adapter.calls) == 1
    traces = report["observability"]
    assert traces["agent_trace"]["source"] == "agent_sdk"
    assert traces["agent_trace"]["trust"] == "agent_reported_diagnostic"
    assert {event["source"] for event in traces["controller_trace"]["events"]} == {"controller"}
    assert traces["agent_trace"]["run_id_hash"] == adapter.calls[0]["run_id_hash"]
    controller_events = traces["controller_trace"]["events"]
    assert sum(event["event"] == "tool_started" for event in controller_events) == 1
    denied = [event for event in controller_events if event.get("reason") == "outside_scope"]
    assert len(denied) == 1
    assert not any(event["event"] == "tool_started"
                   and event.get("operation_id_hash") == denied[0]["operation_id_hash"]
                   for event in controller_events)
    encoded = json.dumps(report)
    for private in (ACCOUNT, PRINCIPAL, "fictional-parent-only-credential",
                    environments[0]["CONTROLLER_WORKER_TOKEN"], adapter.calls[0]["request_nonce"]):
        assert private not in encoded


def test_actual_sdk_demo_report_exports_both_sources_and_passes_advisory_checks(tmp_path):
    from demo.aws_identity import demonstrate
    from integration.trace_export import build_export
    adapter = RecordingAdapter()
    report = demonstrate(tmp_path / "bridge", CONFIG, tmp_path / "report", adapter=adapter)
    assert report["evidence_source"] == "injected_test_adapter"
    exported = build_export(report, "12345678-1234-5678-9234-567812345678")
    assert len(exported["evaluations"]) == 4
    assert set(exported["evaluations"].values()) == {"pass"}
    assert exported["summary"]["agent_complete"]
    assert exported["summary"]["controller_complete"]
    assert exported["summary"]["input_authenticity_verified"] is False
    assert exported["summary"]["effect_absence_proven"] is False
    assert exported["summary"]["cross_source_clock_ordered"] is False
    rows = exported["events"]
    assert {row["metadata"]["source"] for row in rows} == {"collector", "agent_sdk", "controller"}
    for source, trust in (("agent_sdk", "agent_reported_diagnostic"),
                          ("controller", "controller_journal_projection")):
        source_rows = [row for row in rows if row["metadata"]["source"] == source]
        assert source_rows
        assert {row["metadata"]["trust"] for row in source_rows} == {trust}
    assert all("input" not in row and "output" not in row and "metrics" not in row for row in rows)
    encoded = json.dumps(exported)
    for private in (ACCOUNT, PRINCIPAL, "identity-allowed", "identity-outside-scope",
                    adapter.calls[0]["request_nonce"], REQUEST_ID_HASH):
        assert private not in encoded
    assert len(adapter.calls) == 1


def test_bridge_parser_refuses_fifo_without_waiting_for_a_writer(tmp_path):
    fifo = tmp_path / "receipt.json"
    os.mkfifo(fifo, 0o600)
    result = subprocess.run(
        [sys.executable, "-c", "from controller.aws_identity import read_private_json; "
         "import sys; read_private_json(sys.argv[1])", str(fifo)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3)
    assert result.returncode != 0
    assert "unsafe_bridge_file" in result.stderr
