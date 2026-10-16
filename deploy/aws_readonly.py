#!/usr/bin/env python3
"""Collect AWS resource metadata or check local cost evidence; never deploy.

AWS CLI v2 and an already configured, authorized identity are prerequisites for
inventory. The local reconcile command has no AWS/network dependency. Neither
command grants deployment or paid-test approval, nor updates runtime budgets.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from controller.installation import InstallationConfig, load_installation
from deploy.self_host import require_commercial_installation
COVERAGE = (
    "aws_all_project_regions_and_accounts_reviewed",
    "untagged_deleted_and_shared_resources_reviewed",
    "openai_all_project_organizations_and_keys_reviewed",
    "prior_project_spend_and_reservations_reviewed",
    "billing_lag_and_unknown_usage_bounded",
    "shared_costs_tax_and_fees_allocated",
)
AMOUNTS = (
    "settled_aws_usd",
    "settled_openai_usd",
    "settled_other_project_usd",
    "outstanding_reservations_not_in_settled_usd",
    "unbilled_or_unknown_upper_bound_not_reserved_usd",
    "remaining_existing_resource_lifecycle_upper_bound_usd",
    "proposed_new_package_and_test_upper_bound_usd",
)

# Fixed operations only; intentionally no generic AWS command passthrough and
# no GetSecretValue, SSM parameter reads, instance user data or Lambda env reads.
QUERIES = (
    ("instances", "ec2", "describe-instances", [],
     "Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,State:State.Name,AZ:Placement.AvailabilityZone,Subnet:SubnetId,Vpc:VpcId,Launched:LaunchTime}"),
    ("volumes", "ec2", "describe-volumes", [],
     "Volumes[].{Id:VolumeId,Size:Size,Type:VolumeType,Encrypted:Encrypted,State:State,AZ:AvailabilityZone,Attachments:Attachments}"),
    ("snapshots", "ec2", "describe-snapshots", ["--owner-ids", "self"],
     "Snapshots[].{Id:SnapshotId,VolumeId:VolumeId,Size:VolumeSize,State:State,Started:StartTime}"),
    ("public_addresses", "ec2", "describe-addresses", [],
     "Addresses[].{AllocationId:AllocationId,InstanceId:InstanceId,NetworkInterfaceId:NetworkInterfaceId}"),
    ("nat_gateways", "ec2", "describe-nat-gateways", [],
     "NatGateways[].{Id:NatGatewayId,State:State,Vpc:VpcId,Subnet:SubnetId}"),
    ("vpc_endpoints", "ec2", "describe-vpc-endpoints", [],
     "VpcEndpoints[].{Id:VpcEndpointId,Type:VpcEndpointType,Vpc:VpcId,State:State,Service:ServiceName}"),
    ("load_balancers", "elbv2", "describe-load-balancers", [],
     "LoadBalancers[].{Arn:LoadBalancerArn,Type:Type,Scheme:Scheme,Vpc:VpcId,Created:CreatedTime}"),
    ("ecr_repositories", "ecr", "describe-repositories", [],
     "repositories[].{Arn:repositoryArn,Created:createdAt}"),
    ("agentcore_runtimes", "bedrock-agentcore-control", "list-agent-runtimes", [],
     "agentRuntimes[].{Arn:agentRuntimeArn,Id:agentRuntimeId,Status:status,Updated:lastUpdatedAt}"),
    ("log_groups", "logs", "describe-log-groups", [],
     "logGroups[].{Arn:arn,RetentionDays:retentionInDays,StoredBytes:storedBytes}"),
    ("stacks", "cloudformation", "list-stacks", [],
     "StackSummaries[].{Id:StackId,Status:StackStatus,Created:CreationTime,Deleted:DeletionTime}"),
    ("tagged_resources", "resourcegroupstaggingapi", "get-resources", [],
     "ResourceTagMappingList[].{Arn:ResourceARN,Project:Tags[?Key=='Project'].Value}"),
)
ALLOWED = {("sts", "get-caller-identity")} | {(q[1], q[2]) for q in QUERIES}


def now():
    return datetime.now(timezone.utc).isoformat()


def call_aws(executable, service, operation, arguments=(), query=None, *, installation: InstallationConfig, runner=subprocess.run):
    if (service, operation) not in ALLOWED:
        raise ValueError("operation_not_in_read_only_allowlist")
    require_commercial_installation(installation)
    command = [executable, service, operation, "--region", installation.region, "--output", "json",
               "--no-cli-pager", "--cli-connect-timeout", "10", "--cli-read-timeout", "30"]
    command.extend(arguments)
    if query:
        command.extend(["--query", query])
    environment = os.environ.copy()
    environment.update(AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off")
    try:
        result = runner(command, capture_output=True, text=True, timeout=120,
                        check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unknown", "reason": "aws_cli_unavailable_or_timeout"}
    if result.returncode:
        # Do not copy stderr, which may expose local auth-helper diagnostics.
        return {"status": "unknown", "reason": "aws_cli_failed",
                "exit_code": result.returncode}
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        return {"status": "unknown", "reason": "invalid_cli_response"}
    if not isinstance(payload, (list, dict)):
        return {"status": "unknown", "reason": "missing_response_shape"}
    return {"status": "observed", "collected_at_utc": now(), "data": payload}


def inventory(executable, *, installation: InstallationConfig, runner=subprocess.run):
    require_commercial_installation(installation)
    report = {"schema_version": 1, "project": installation.project_id,
              "expected_account_id": installation.account_id, "explicit_request_region": installation.region,
              "collected_at_utc": now(), "source": "aws_cli_v2",
              "resource_scope": "partial_service_inventory_in_" + installation.region + "_only",
              "costs_reconciled": False, "paid_testing_allowed": False,
              "deployment_allowed": False, "inventory": {}}
    identity = call_aws(executable, "sts", "get-caller-identity", installation=installation, runner=runner)
    report["identity"] = identity
    data = identity.get("data", {})
    arn = data.get("Arn", "") if isinstance(data, dict) else ""
    valid = (identity["status"] == "observed" and isinstance(data, dict)
             and data.get("Account") == installation.account_id
             and isinstance(arn, str) and arn.startswith((f"arn:aws:sts::{installation.account_id}:", f"arn:aws:iam::{installation.account_id}:")))
    if not valid:
        report["status"] = "blocked_identity_unverified_or_wrong_account"
        return report
    for label, service, operation, arguments, query in QUERIES:
        report["inventory"][label] = call_aws(
            executable, service, operation, arguments, query, installation=installation, runner=runner)
    report["status"] = ("partial_inventory" if any(
        item["status"] != "observed" for item in report["inventory"].values())
        else "inventory_collected_cost_reconciliation_still_required")
    return report


def money(value):
    # Strings avoid JSON floating-point rounding. Unknown/null never means zero.
    if not isinstance(value, str) or not re.fullmatch(r"\d+(?:\.\d{1,9})?", value):
        raise ValueError("amount_must_be_nonnegative_decimal_string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("invalid_amount") from exc
    if not result.is_finite():
        raise ValueError("invalid_amount")
    return result


def reconciliation(document, base_path, *, installation: InstallationConfig):
    require_commercial_installation(installation)
    ceiling = Decimal(installation.limit_microusd) / 1_000_000
    report = {"schema_version": 1, "checked_at_utc": now(),
              "status": "blocked_incomplete_reconciliation", "reasons": [],
              "total_project_ceiling_usd": str(ceiling),
              "remaining_after_proposed_package_usd": None,
              "paid_testing_allowed": False, "deployment_allowed": False,
              "evidence_authenticity_verified": False}
    reasons = report["reasons"]
    if not isinstance(document, dict):
        reasons.append("reconciliation_must_be_object")
        return report
    if (document.get("schema_version") != 1 or document.get("project") != installation.project_id
            or document.get("account_id") != installation.account_id or document.get("region") != installation.region
            or document.get("currency") != "USD"):
        reasons.append("scope_mismatch")
    try:
        if money(document.get("total_project_ceiling")) != ceiling:
            reasons.append("total_project_ceiling_mismatch")
    except ValueError:
        reasons.append("total_project_ceiling_missing")
    coverage = document.get("coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}
    reasons.extend("coverage_missing:" + key for key in COVERAGE if coverage.get(key) is not True)
    try:
        timestamp = datetime.fromisoformat(document.get("as_of_utc"))
        if timestamp.tzinfo is None or timestamp.utcoffset().total_seconds() != 0:
            raise ValueError
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        if not 0 <= age <= 86400:
            reasons.append("reconciliation_older_than_24h_or_future")
        if date.fromisoformat(document.get("project_history_start_date")) > timestamp.date():
            reasons.append("project_history_start_is_future")
    except (TypeError, ValueError, OverflowError):
        reasons.append("valid_utc_timestamp_and_history_start_required")
    if not isinstance(document.get("reviewed_by"), str) or not document["reviewed_by"].strip():
        reasons.append("named_reviewer_required")
    history = document.get("historical_project_names_and_tags")
    if not isinstance(history, list) or not history or not all(isinstance(v, str) and v for v in history):
        reasons.append("historical_project_names_required")
    amounts = {}
    for key in AMOUNTS:
        try:
            amounts[key] = money(document.get(key))
        except ValueError:
            reasons.append("amount_unknown_or_invalid:" + key)
    evidence = document.get("evidence_files")
    if not isinstance(evidence, list) or not evidence:
        reasons.append("authoritative_evidence_files_required")
    else:
        sources = set()
        for item in evidence:
            try:
                if not isinstance(item, dict) or item.get("source") not in {
                    "aws_billing", "openai_billing", "reservation_ledger", "lifecycle_estimate"
                }:
                    raise ValueError
                path = Path(item["path"])
                if not path.is_absolute():
                    path = base_path / path
                expected_hash = item["sha256"]
                if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
                    raise ValueError
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                    raise ValueError
                sources.add(item["source"])
            except (KeyError, TypeError, ValueError, OSError):
                reasons.append("evidence_file_missing_or_hash_mismatch")
        reasons.extend("evidence_source_missing:" + source for source in
                       sorted({"aws_billing", "openai_billing", "reservation_ledger", "lifecycle_estimate"} - sources))
    if len(amounts) == len(AMOUNTS):
        total = sum(amounts.values(), Decimal("0"))
        report["total_accounted_upper_bound_usd"] = str(total)
        report["remaining_after_proposed_package_usd"] = str(ceiling - total)
        if total > ceiling:
            reasons.append("project_ceiling_exceeded")
    if not reasons:
        report["status"] = "local_evidence_completeness_and_budget_arithmetic_passed"
        report["review_required"] = "Verify export provenance, attribution, bounds and unchanged usage; this is not authorization."
    return report


def write_report(destination, report):
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite an earlier identity or billing checkpoint.
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("inventory", help="Read STS and selected resource metadata; no billing queries")
    collect.add_argument("--installation", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    reconcile = commands.add_parser("reconcile", help="Check local exported evidence and budget arithmetic")
    reconcile.add_argument("--installation", type=Path, required=True)
    reconcile.add_argument("--input", type=Path, required=True)
    reconcile.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        installation = load_installation(args.installation)
        # Check overwrite before any calls, while write_report also protects races.
        if args.output.exists():
            raise FileExistsError
        if args.command == "inventory":
            executable = shutil.which("aws")
            if not executable:
                print(json.dumps({"status": "blocked", "reason": "preconfigured_aws_cli_v2_required"}))
                return 2
            report = inventory(executable, installation=installation)
        else:
            report = reconciliation(json.loads(args.input.read_text()), args.input.resolve().parent,
                                    installation=installation)
        write_report(args.output, report)
    except (OSError, ValueError):
        print(json.dumps({"status": "blocked", "reason": "invalid_input_or_output_already_exists"}))
        return 2
    print(json.dumps({"status": report["status"], "report": str(args.output)}))
    if args.command == "inventory":
        return 0 if report["status"] == "inventory_collected_cost_reconciliation_still_required" else 2
    return 0 if not report["reasons"] else 2


if __name__ == "__main__":
    sys.exit(main())
