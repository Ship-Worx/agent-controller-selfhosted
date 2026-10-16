"""Render reviewed policy fragments from metadata outputs only; never call AWS.

This is deliberately not a CloudFormation interpreter, IAM simulator, deployer,
or proof that a supplied identifier exists or belongs to this project.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from controller.installation import InstallationConfig, load_installation
from deploy.self_host import installation_document


PACKAGE = Path(__file__).resolve().parent / "templates" / "iam-resolved-proposal"
MARKER = re.compile(r"__[A-Z0-9_]+__")
VARIABLE = re.compile(r"\$\{([^}]+)\}")


class PolicyInputError(ValueError):
    """An input cannot be safely resolved by this limited offline renderer."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyInputError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(), object_pairs_hook=_unique_pairs)


def _validate_bindings(bindings: dict, contract: dict) -> dict:
    if not isinstance(bindings, dict):
        raise PolicyInputError("bindings must be an object of metadata output strings")
    patterns = contract["binding_patterns"]
    for key, value in bindings.items():
        if key not in patterns:
            raise PolicyInputError(f"unknown output binding: {key}")
        if not isinstance(value, str) or re.fullmatch(patterns[key], value) is None:
            # Do not echo supplied values: accidental secret input stays private.
            raise PolicyInputError(f"invalid output binding: {key}")
    runtime_ids = []
    for key in ("AgentRuntimeArn", "SelectedEndpointArn", "WorkerPlatformLogGroupArn"):
        if key in bindings:
            runtime_ids.append(re.search(r"agent_controller_pilot-[A-Za-z0-9]{10}", bindings[key])[0])
    if len(set(runtime_ids)) > 1:
        raise PolicyInputError("runtime, endpoint and log group refer to different runtime IDs")
    groups = [bindings[key] for key in (
        "ControllerSecurityGroup", "WorkerSecurityGroup",
        "ControllerEndpointSecurityGroup", "WorkerEndpointSecurityGroup",
    ) if key in bindings]
    if len(groups) != len(set(groups)):
        raise PolicyInputError("controller, worker and endpoint security groups must be distinct")
    endpoints = [bindings[key] for key in contract.get("cleanup_endpoint_bindings", []) if key in bindings]
    if len(endpoints) != len(set(endpoints)):
        raise PolicyInputError("the seven endpoint output bindings must be distinct")
    return dict(contract["constant_bindings"], **bindings)


def render_documents(bindings: dict, names: list[str] | None = None, *,
                     installation: InstallationConfig, operator_arn=None, package: Path = PACKAGE) -> dict:
    """Resolve only requested allowlisted documents; require every used output.

    Supplying a syntactically valid ARN is not proof of ownership. The human
    deployment review must check provenance before these drafts are applied.
    """
    def configured(name):
        try:
            return installation_document(package / name, installation, operator_arn=operator_arn)
        except (ValueError, TypeError):
            raise PolicyInputError("invalid trusted installation or required operator input") from None
    contract = configured("binding-contract.json")
    values = _validate_bindings(bindings, contract)
    selected = contract["documents"] if names is None else names
    if not selected or len(selected) != len(set(selected)):
        raise PolicyInputError("select one or more distinct document names")
    for name in selected:
        if name not in contract["documents"] or Path(name).name != name:
            raise PolicyInputError("document is not in the reviewed package allowlist")

    def lookup(name):
        if name not in values:
            raise PolicyInputError(f"missing required output binding: {name}")
        return values[name]

    def render(value):
        if isinstance(value, list):
            return [render(item) for item in value]
        if isinstance(value, dict):
            if "Ref" in value:
                if set(value) != {"Ref"} or not isinstance(value["Ref"], str):
                    raise PolicyInputError("invalid Ref expression")
                return lookup(value["Ref"])
            if "Fn::GetAtt" in value:
                attr = value["Fn::GetAtt"]
                if set(value) != {"Fn::GetAtt"} or not isinstance(attr, list) or len(attr) != 2 or not all(isinstance(x, str) for x in attr):
                    raise PolicyInputError("invalid GetAtt expression")
                return lookup(".".join(attr))
            if "Fn::Sub" in value:
                if set(value) != {"Fn::Sub"} or not isinstance(value["Fn::Sub"], str):
                    raise PolicyInputError("only string Fn::Sub expressions are supported")
                return render(VARIABLE.sub(lambda match: lookup(match[1]), value["Fn::Sub"]))
            if any(key.startswith("Fn::") for key in value):
                raise PolicyInputError("unsupported CloudFormation intrinsic")
            return {key: render(item) for key, item in value.items()}
        if isinstance(value, str):
            def marker(match):
                key = contract["markers"].get(match[0])
                if key is None:
                    raise PolicyInputError("unregistered review marker")
                return lookup(key)
            result = MARKER.sub(marker, value)
            if any(match[1] not in contract["operator_iam_variables"] for match in VARIABLE.finditer(result)):
                raise PolicyInputError("unresolved template variable")
            return result
        return value

    return {name: render(configured(name)) for name in selected}


def attachment_groups(documents: dict, *, package: Path = PACKAGE) -> dict:
    """Propose deterministic identity-policy attachments within stated limits.

    Quotas and other policies on a real role are unknown. Nothing is attached.
    Groups requiring documents absent from this phase are deliberately omitted.
    """
    contract = read_json(package / "attachment-groups.json")
    groups = {}
    for name, group in contract["groups"].items():
        if not all(filename in documents for filename in group["documents"]):
            continue
        limit = contract["limits"]["managed_policy_characters"] if group["attachment_type"] == "managed" else contract["limits"]["aggregate_inline_role_characters"]
        policies = []
        current = {"Version": "2012-10-17", "Statement": []}
        def size(policy):
            return len(json.dumps(policy, separators=(",", ":"), sort_keys=True))
        ordinal = 0
        for filename in group["documents"]:
            for original in documents[filename]["Statement"]:
                ordinal += 1
                # Sids must be unique after combining separate source policies.
                statement = dict(original, Sid=f"S{ordinal:03}" + original.get("Sid", ""))
                candidate = dict(current, Statement=current["Statement"] + [statement])
                if size(candidate) > limit:
                    if not current["Statement"]:
                        raise PolicyInputError("a single statement exceeds its policy size limit")
                    policies.append(current)
                    current = {"Version": "2012-10-17", "Statement": [statement]}
                    if size(current) > limit:
                        raise PolicyInputError("a single statement exceeds its policy size limit")
                else:
                    current = candidate
        if current["Statement"]:
            policies.append(current)
        if group["attachment_type"] == "inline" and len(policies) != 1:
            raise PolicyInputError("aggregate inline role policy limit exceeded")
        if group["attachment_type"] == "managed" and len(policies) > contract["limits"]["managed_policies_per_role"]:
            raise PolicyInputError("default managed policy attachment count exceeded")
        prefix = group.get("policy_name_prefix", f"agent-controller-pilot-{name}")
        groups[name] = dict(group, policy_characters=[size(p) for p in policies],
                            policy_names=[f"{prefix}-{index:02}" for index in range(1, len(policies) + 1)],
                            policies=policies, existing_role_policy_usage_verified=False)
    return groups


def write_review_output(documents: dict, output: Path) -> None:
    """Create a new review directory; refuse existing destinations."""
    grouped = attachment_groups(documents)
    for name in documents:
        if Path(name).name != name or not name.endswith(".json"):
            raise PolicyInputError("unsafe output filename")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, document in documents.items():
        with (output / name).open("x") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
    with (output / "ATTACHMENT_REVIEW.json").open("x") as stream:
        json.dump(grouped, stream, indent=2, sort_keys=True)
        stream.write("\n")
    with (output / "REVIEW_ONLY.json").open("x") as stream:
        json.dump({"status": "review_only_not_deploy_ready", "aws_calls": 0,
                   "policies_applied": False, "provenance_verified": False,
                   "documents": sorted(documents)}, stream, indent=2)
        stream.write("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path, help="absolute trusted operator installation JSON")
    parser.add_argument("--operator-arn", help="reviewed same-account IAM user/role ARN; required only by operator-dependent drafts")
    parser.add_argument("--bindings", required=True, type=Path, help="JSON object of reviewed new-resource outputs; no credentials or secret values")
    parser.add_argument("--document", action="append", help="allowlisted filename; repeat to select a phase")
    parser.add_argument("--output", required=True, type=Path, help="new local review directory; must not exist")
    args = parser.parse_args(argv)
    try:
        rendered = render_documents(read_json(args.bindings), args.document,
                                    installation=load_installation(args.installation), operator_arn=args.operator_arn)
        write_review_output(rendered, args.output)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(2, f"policy render rejected: {exc}\n")
    print(f"Rendered {len(rendered)} review documents; no AWS validation or application performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
