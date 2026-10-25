"""Offline projection checks use fictional metadata and perform no network I/O."""
from copy import deepcopy
import json
import subprocess
import sys
import uuid

import pytest

from integration.trace_export import ExportError, MAX_EXPORT_BYTES, build_export


PROJECT = "12345678-1234-5678-9234-567812345678"
RUN, ALLOWED, DENIED = "0" * 64, "a" * 64, "b" * 64


def trace_report():
    bindings = {"run_id_hash": RUN, "config_pin": "c" * 64, "policy_pin": "d" * 64,
                "authority_epoch": 2, "controller_instance_id": "e" * 32}
    agent = {"schema_version": 1, "source": "agent_sdk", "trust": "agent_reported_diagnostic",
             "invocation_id": "f" * 32, "model_mode": "scripted", **bindings,
             "truncated": False, "dropped_events": 0, "unavailable": False,
             "events": [
                 {"seq": 1, "elapsed_ms": 0, "event": "agent_started"},
                 {"seq": 2, "elapsed_ms": 10, "event": "action_proposed", "operation_id_hash": ALLOWED},
                 {"seq": 3, "elapsed_ms": 20, "event": "action_result", "operation_id_hash": ALLOWED,
                  "status": "allowed", "reason": "result_released"},
                 {"seq": 4, "elapsed_ms": 30, "event": "action_proposed", "operation_id_hash": DENIED},
                 {"seq": 5, "elapsed_ms": 40, "event": "action_result", "operation_id_hash": DENIED,
                  "status": "denied", "reason": "outside_scope"},
                 {"seq": 6, "elapsed_ms": 41, "event": "run_finished", "status": "denied"},
             ]}
    controller = []
    for index, (name, operation, codes) in enumerate([
        ("action_proposed", ALLOWED, {}),
        ("decision", ALLOWED, {"status": "reserved", "reason": "reserved"}),
        ("tool_started", ALLOWED, {}),
        ("tool_finished", ALLOWED, {"reason": "settled"}),
        ("result_release", ALLOWED, {"status": "allowed", "reason": "result_released"}),
        ("action_proposed", DENIED, {}),
        ("decision", DENIED, {"status": "denied", "reason": "outside_scope"}),
    ], 1):
        controller.append({"source": "controller", "event_id": index, "at": 1000 - index,
                           "event": name, "operation_id_hash": operation, **bindings, **codes})
    return {"observability": {"schema_version": 1, "agent_trace": agent,
                              "controller_trace": {"source": "controller", "events": controller}}}


def source_rows(output, source):
    return [row for row in output["events"] if row["metadata"]["source"] == source]


def test_audit_unavailable_protocol_reason_survives_export():
    report = trace_report()
    report["observability"]["agent_trace"]["events"][4]["reason"] = "audit_unavailable"
    report["observability"]["controller_trace"]["events"][6]["reason"] = "audit_unavailable"
    output = build_export(report, PROJECT)
    for source in ("agent_sdk", "controller"):
        assert any(row["metadata"].get("reason") == "audit_unavailable"
                   for row in source_rows(output, source))


def test_complete_curated_paths_are_correlated_without_claiming_authenticity_or_effect_absence():
    output = build_export(trace_report(), PROJECT)
    assert set(output["evaluations"].values()) == {"pass"}
    assert output["summary"]["run_count"] == 1
    assert output["summary"]["operation_count"] == 2
    assert output["summary"]["row_count"] == 16
    assert output["summary"]["agent_complete"] and output["summary"]["controller_complete"]
    assert output["summary"]["input_authenticity_verified"] is False
    assert output["summary"]["effect_absence_proven"] is False
    assert output["summary"]["cross_source_clock_ordered"] is False
    assert len(json.dumps(output).encode()) < MAX_EXPORT_BYTES
    assert all("input" not in row and "output" not in row and "metrics" not in row for row in output["events"])


def test_row_tree_is_collector_owned_deterministic_and_project_bound():
    report = trace_report()
    output = build_export(report, PROJECT)
    assert output == build_export(deepcopy(report), PROJECT)
    ids = {row["id"] for row in output["events"]}
    assert len(ids) == len(output["events"])
    for row in output["events"]:
        assert str(uuid.UUID(row["id"])) == row["id"] == row["span_id"]
        assert row["root_span_id"] in ids
        assert all(parent in ids for parent in row["span_parents"])
        assert row["_is_merge"] is False
    report["observability"]["agent_trace"]["events"][0].update(
        id="private-id", span_id="private-span", root_span_id="private-root", project_id="private-project")
    assert build_export(report, PROJECT) == output
    changed = build_export(report, "22345678-1234-5678-9234-567812345678")
    assert not ids.intersection(row["id"] for row in changed["events"])
    report["observability"]["agent_trace"]["truncated"] = True
    partial = build_export(report, PROJECT)
    assert not ids.intersection(row["id"] for row in partial["events"])


def test_every_extra_field_is_ignored_without_changing_projection_or_ids():
    report = trace_report()
    expected = build_export(report, PROJECT)
    secret = "unreviewed_secret_canary"
    for value in (report, report["observability"], report["observability"]["agent_trace"],
                  report["observability"]["controller_trace"],
                  *report["observability"]["agent_trace"]["events"],
                  *report["observability"]["controller_trace"]["events"]):
        value.update(prompt=secret, result=secret, error={secret: secret}, token=secret,
                     scores={secret: 1}, span_parents=[secret], usage={"source": secret})
    report["checks"] = [{"passed": True, "check": secret}]
    report["scope"] = {"purpose": secret}
    actual = build_export(report, PROJECT)
    assert actual == expected
    assert secret not in json.dumps(actual)


@pytest.mark.parametrize("source,field", [("agent_trace", "event"), ("agent_trace", "status"),
                                         ("agent_trace", "reason"), ("controller_trace", "event"),
                                         ("controller_trace", "status"), ("controller_trace", "reason")])
def test_unknown_codes_are_rejected_with_fixed_error_and_no_sensitive_content(source, field):
    report = trace_report()
    secret = "secret_looks_like_a_lexically_valid_code"
    report["observability"][source]["events"][0][field] = secret
    with pytest.raises(ExportError) as failure:
        build_export(report, PROJECT)
    assert str(failure.value) in {"invalid_trace_event", "invalid_trace_code"}
    assert secret not in str(failure.value)


@pytest.mark.parametrize("field,value", [("seq", True), ("seq", -1), ("seq", 2**53),
                                        ("elapsed_ms", -1), ("elapsed_ms", float("inf")),
                                        ("elapsed_ms", float("nan")), ("elapsed_ms", True)])
def test_invalid_agent_numbers_are_rejected(field, value):
    report = trace_report()
    report["observability"]["agent_trace"]["events"][0][field] = value
    with pytest.raises(ExportError):
        build_export(report, PROJECT)


@pytest.mark.parametrize("field,value", [("event_id", True), ("event_id", -1), ("at", True),
                                        ("at", -1), ("at", float("nan")), ("at", float("inf")),
                                        ("authority_epoch", True), ("authority_epoch", -1),
                                        ("config_pin", "secret"), ("operation_id_hash", "secret")])
def test_invalid_controller_numbers_and_bindings_are_rejected(field, value):
    report = trace_report()
    report["observability"]["controller_trace"]["events"][0][field] = value
    with pytest.raises(ExportError):
        build_export(report, PROJECT)


@pytest.mark.parametrize("stream,key", [("agent_trace", "seq"), ("controller_trace", "event_id")])
def test_duplicate_or_reordered_source_sequence_is_rejected(stream, key):
    report = trace_report()
    events = report["observability"][stream]["events"]
    events[1][key] = events[0][key]
    with pytest.raises(ExportError, match="invalid_source_order"):
        build_export(report, PROJECT)


def test_clocks_are_preserved_as_source_metadata_without_sorting_journal_wall_time():
    output = build_export(trace_report(), PROJECT)
    controller = [row["metadata"] for row in source_rows(output, "controller")]
    assert [event["event_id"] for event in controller] == list(range(1, 8))
    assert [event["at"] for event in controller] == list(range(999, 992, -1))
    agent = [row["metadata"] for row in source_rows(output, "agent_sdk")]
    assert [event["seq"] for event in agent] == list(range(1, 7))
    assert "at" not in agent[0]


@pytest.mark.parametrize("missing", ["agent_trace", "controller_trace", "both"])
def test_missing_sources_are_inconclusive_even_if_report_claims_checks_passed(missing):
    report = trace_report()
    if missing == "both":
        report["observability"] = {"schema_version": 1}
    else:
        del report["observability"][missing]
    report["checks"] = [{"check": "all_security", "passed": True}]
    assert set(build_export(report, PROJECT)["evaluations"].values()) == {"inconclusive"}


@pytest.mark.parametrize("field,value", [("truncated", True), ("unavailable", True), ("dropped_events", 1)])
def test_incomplete_stream_cannot_pass_evaluations(field, value):
    report = trace_report()
    report["observability"]["agent_trace"][field] = value
    output = build_export(report, PROJECT)
    assert not output["summary"]["agent_complete"]
    assert set(output["evaluations"].values()) == {"inconclusive"}


def test_same_operation_hash_in_different_runs_produces_separate_unconfirmed_trees():
    report = trace_report()
    report["observability"]["agent_trace"]["run_id_hash"] = "1" * 64
    output = build_export(report, PROJECT)
    assert output["summary"]["run_count"] == 2
    assert output["summary"]["operation_count"] == 4
    assert set(output["evaluations"].values()) == {"inconclusive"}
    agent_roots = {row["root_span_id"] for row in source_rows(output, "agent_sdk")}
    controller_roots = {row["root_span_id"] for row in source_rows(output, "controller")}
    assert not agent_roots.intersection(controller_roots)


def test_agent_success_disagreeing_with_controller_denial_fails_consistency():
    report = trace_report()
    report["observability"]["agent_trace"]["events"][4]["status"] = "allowed"
    evaluations = build_export(report, PROJECT)["evaluations"]
    assert evaluations["trace_correlation"] == "fail"
    assert evaluations["allowed_path_observed"] == "fail"
    assert evaluations["denied_dispatch_consistency"] == "fail"


def test_denied_operation_with_recorded_dispatch_fails_but_never_claims_external_effect():
    report = trace_report()
    events = report["observability"]["controller_trace"]["events"]
    extra = {**events[-1], "event_id": 8, "event": "tool_started"}
    extra.pop("status")
    extra.pop("reason")
    events.append(extra)
    output = build_export(report, PROJECT)
    assert output["evaluations"]["denied_dispatch_consistency"] == "fail"
    assert output["summary"]["effect_absence_proven"] is False


def test_missing_allowed_execution_evidence_is_inconclusive_and_duplicate_dispatch_fails():
    report = trace_report()
    events = report["observability"]["controller_trace"]["events"]
    del events[2]
    assert build_export(report, PROJECT)["evaluations"]["allowed_path_observed"] == "inconclusive"
    report = trace_report()
    events = report["observability"]["controller_trace"]["events"]
    events.insert(3, {**events[2], "event_id": 4})
    for index, event in enumerate(events, 1):
        event["event_id"] = index
    assert build_export(report, PROJECT)["evaluations"]["allowed_path_observed"] == "fail"


def test_agent_latest_binding_is_compared_with_latest_controller_context_not_earlier_epoch():
    report = trace_report()
    events = report["observability"]["controller_trace"]["events"]
    events[0]["authority_epoch"] = 1
    events[0]["controller_instance_id"] = "1" * 32
    output = build_export(report, PROJECT)
    assert output["evaluations"]["policy_binding_consistency"] == "pass"
    controller_rows = source_rows(output, "controller")
    assert controller_rows[0]["metadata"]["authority_epoch"] == 1
    for row in source_rows(output, "agent_sdk"):
        assert "authority_epoch" not in row["metadata"]
        assert row["metadata"]["binding_scope"] == "latest_observed_at_report_end"
        assert row["metadata"]["latest_observed_binding"]["authority_epoch"] == 2


def test_binding_mismatch_and_missing_binding_make_all_checks_inconclusive():
    report = trace_report()
    report["observability"]["agent_trace"]["policy_pin"] = "2" * 64
    assert set(build_export(report, PROJECT)["evaluations"].values()) == {"inconclusive"}
    del report["observability"]["agent_trace"]["policy_pin"]
    assert build_export(report, PROJECT)["evaluations"]["policy_binding_consistency"] == "inconclusive"


def test_limits_reject_oversized_sources_and_row_fanout_without_truncation():
    report = trace_report()
    report["observability"]["agent_trace"]["events"] *= 11
    with pytest.raises(ExportError, match="invalid_trace_events"):
        build_export(report, PROJECT)
    report = {"observability": {"schema_version": 1, "controller_trace": {"source": "controller", "events": []}}}
    events = report["observability"]["controller_trace"]["events"]
    for seq in range(1, 257):
        events.append({"source": "controller", "event_id": seq, "at": 0, "event": "action_proposed",
                       "run_id_hash": f"{seq:064x}", "operation_id_hash": f"{seq:064x}"})
    with pytest.raises(ExportError, match="export_row_limit"):
        build_export(report, PROJECT)


@pytest.mark.parametrize("project", [None, True, "https://private.invalid", "a" * 32, "{12345678-1234-5678-9234-567812345678}"])
def test_invalid_project_destination_is_rejected_without_value_in_error(project):
    with pytest.raises(ExportError, match="^invalid_project_id$"):
        build_export(trace_report(), project)


def test_projection_import_has_no_agent_sdk_or_network_dependency():
    result = subprocess.run([sys.executable, "-S", "-c", "import sys; import integration.trace_export; "
                             "assert 'agents' not in sys.modules; assert 'urllib.request' not in sys.modules"],
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("binding,value", [("authority_epoch", 3), ("controller_instance_id", "3" * 32),
                                          ("config_pin", "4" * 64)])
def test_inter_source_binding_mismatch_cannot_pass_any_evaluation(binding, value):
    report = trace_report()
    report["observability"]["agent_trace"][binding] = value
    assert set(build_export(report, PROJECT)["evaluations"].values()) == {"inconclusive"}


def test_controller_internal_policy_conflict_fails_without_claiming_external_effect():
    report = trace_report()
    report["observability"]["controller_trace"]["events"][0]["policy_pin"] = "4" * 64
    output = build_export(report, PROJECT)
    assert output["evaluations"]["policy_binding_consistency"] == "fail"
    assert output["summary"]["effect_absence_proven"] is False


def test_missing_operation_binding_cannot_be_ignored_in_correlation_check():
    report = trace_report()
    report["observability"]["agent_trace"]["events"].append(
        {"seq": 7, "elapsed_ms": 50, "event": "action_result", "status": "allowed"})
    assert build_export(report, PROJECT)["evaluations"]["trace_correlation"] == "inconclusive"


def test_result_before_proposal_fails_source_consistency():
    report = trace_report()
    events = report["observability"]["agent_trace"]["events"]
    events[1]["event"], events[2]["event"] = "action_result", "action_proposed"
    events[1]["status"] = "allowed"
    evaluations = build_export(report, PROJECT)["evaluations"]
    assert evaluations["trace_correlation"] == "fail"
    assert evaluations["allowed_path_observed"] == "fail"


def test_controller_denial_before_its_proposal_fails_semantic_source_order():
    report = trace_report()
    events = report["observability"]["controller_trace"]["events"]
    events[-2], events[-1] = events[-1], events[-2]
    for index, event in enumerate(events, 1):
        event["event_id"] = index
    evaluations = build_export(report, PROJECT)["evaluations"]
    assert evaluations["trace_correlation"] == "fail"
    assert evaluations["denied_dispatch_consistency"] == "fail"


@pytest.mark.parametrize("source,index,evaluation", [
    ("agent_trace", 1, "allowed_path_observed"),
    ("agent_trace", 2, "allowed_path_observed"),
    ("agent_trace", 3, "denied_dispatch_consistency"),
    ("agent_trace", 4, "denied_dispatch_consistency"),
    ("controller_trace", 0, "allowed_path_observed"),
    ("controller_trace", 1, "allowed_path_observed"),
    ("controller_trace", 4, "allowed_path_observed"),
    ("controller_trace", 5, "denied_dispatch_consistency"),
    ("controller_trace", 6, "denied_dispatch_consistency"),
])
def test_duplicate_curated_action_boundaries_fail_consistency(source, index, evaluation):
    report = trace_report()
    events = report["observability"][source]["events"]
    events.insert(index + 1, deepcopy(events[index]))
    sequence = "seq" if source == "agent_trace" else "event_id"
    for number, event in enumerate(events, 1):
        event[sequence] = number
    evaluations = build_export(report, PROJECT)["evaluations"]
    assert evaluations["trace_correlation"] == "fail"
    assert evaluations[evaluation] == "fail"


def test_roots_label_checks_as_report_snapshot_scope():
    report = trace_report()
    report["observability"]["agent_trace"]["run_id_hash"] = "1" * 64
    roots = [row for row in build_export(report, PROJECT)["events"] if not row["span_parents"]]
    assert len(roots) == 2
    assert all(row["metadata"]["evaluation_scope"] == "report_snapshot" for row in roots)
