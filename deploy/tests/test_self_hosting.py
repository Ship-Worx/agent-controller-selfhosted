"""Offline installation isolation and exact AWS policy-scope regression checks."""
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess

import pytest

from controller.installation import InstallationConfig
from deploy import aws_readonly, policy_package, self_host
from deploy.bootstrap import bundle


@pytest.fixture(params=[("123456789012", "us-west-2"), ("210987654321", "eu-west-1")])
def installation(request):
    account, region = request.param
    return InstallationConfig(project_id="my-agent", account_id=account, region=region,
                              limit_microusd=12_345_678)


def test_foundation_guards_and_arn_patterns_are_bound_to_operator_installation(installation):
    documents = self_host.foundation_documents(installation)
    template = documents["pilot-template.json"]
    assert template["Conditions"]["ReviewedAccountAndRegion"]["Fn::And"] == [
        {"Fn::Equals": [{"Ref": "AWS::AccountId"}, installation.account_id]},
        {"Fn::Equals": [{"Ref": "AWS::Region"}, installation.region]},
    ]
    for resource in template["Resources"].values():
        assert resource["Condition"] == "ReviewedAccountAndRegion"
    parameter = template["Parameters"]["ProviderSecretArn"]["AllowedPattern"]
    own = f"arn:aws:secretsmanager:{installation.region}:{installation.account_id}:secret:my/provider-AbCd12"
    assert re.fullmatch(parameter, own)
    assert not re.fullmatch(parameter, own.replace(installation.account_id, "999999999999"))
    assert not re.fullmatch(parameter, own + "*")
    trust = documents["iam-worker-trust.json"]["Statement"][0]["Condition"]
    assert trust["StringEquals"]["aws:SourceAccount"] == installation.account_id
    assert f":{installation.region}:{installation.account_id}:" in trust["ArnEquals"]["aws:SourceArn"]
    assert "__INSTALL_" not in json.dumps(documents)


def test_resolved_trust_rejects_other_installation_and_preserves_exact_runtime(installation):
    runtime = f"arn:aws:bedrock-agentcore:{installation.region}:{installation.account_id}:runtime/agent_controller_pilot-UnitTest01"
    arguments = dict(names=["worker-trust-steady-state.json"], installation=installation)
    rendered = policy_package.render_documents({"AgentRuntimeArn": runtime}, **arguments)
    trust = rendered["worker-trust-steady-state.json"]["Statement"][0]["Condition"]
    assert trust["ArnEquals"]["aws:SourceArn"] == runtime
    assert trust["StringEquals"]["aws:SourceAccount"] == installation.account_id
    for wrong in (runtime.replace(installation.account_id, "999999999999"),
                  runtime.replace(installation.region, "us-east-2"), runtime + "*"):
        with pytest.raises(policy_package.PolicyInputError):
            policy_package.render_documents({"AgentRuntimeArn": wrong}, **arguments)


def test_operator_principal_is_explicit_same_account_and_never_a_default(installation):
    arguments = dict(names=["operator-trust.json"], installation=installation)
    with pytest.raises(policy_package.PolicyInputError):
        policy_package.render_documents({}, **arguments)
    for wrong in ("*", "do-not-echo-private-key", "arn:aws:iam::999999999999:role/operator",
                  f"arn:aws:sts::{installation.account_id}:assumed-role/operator/session"):
        with pytest.raises(policy_package.PolicyInputError) as caught:
            policy_package.render_documents({}, operator_arn=wrong, **arguments)
        assert wrong not in str(caught.value)
    operator = f"arn:aws:iam::{installation.account_id}:role/my/operator"
    rendered = policy_package.render_documents({}, operator_arn=operator, **arguments)
    assert rendered["operator-trust.json"]["Statement"][0]["Principal"] == {"AWS": operator}


def test_regional_s3_prefix_list_is_observed_input_instead_of_private_inventory(installation):
    arguments = dict(names=["worker-s3-egress.json"], installation=installation)
    with pytest.raises(policy_package.PolicyInputError, match="S3ManagedPrefixList"):
        policy_package.render_documents({"WorkerSecurityGroup": "sg-01234567"}, **arguments)
    rendered = policy_package.render_documents({"WorkerSecurityGroup": "sg-01234567",
                                                "S3ManagedPrefixList": "pl-01234567"}, **arguments)
    assert rendered["worker-s3-egress.json"]["Properties"]["DestinationPrefixListId"] == "pl-01234567"


def test_readonly_inventory_checks_sts_before_resource_calls_and_pins_every_region(installation):
    calls = []
    def runner(command, **_kwargs):
        calls.append(command)
        payload = {"Account": installation.account_id,
                   "Arn": f"arn:aws:sts::{installation.account_id}:assumed-role/owner/session"} if command[1] == "sts" else []
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
    report = aws_readonly.inventory("fake-aws", installation=installation, runner=runner)
    assert calls[0][1:3] == ["sts", "get-caller-identity"]
    assert len(calls) == len(aws_readonly.QUERIES) + 1
    assert all(command[command.index("--region") + 1] == installation.region for command in calls)
    assert report["expected_account_id"] == installation.account_id
    calls.clear()
    def wrong(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, '{"Account":"999999999999","Arn":"arn:aws:iam::999999999999:user/other"}', "")
    report = aws_readonly.inventory("fake-aws", installation=installation, runner=wrong)
    assert len(calls) == 1 and not report["inventory"]


def test_reconciliation_cap_and_identity_come_from_trusted_installation(installation, tmp_path):
    document = json.loads((Path(aws_readonly.__file__).parent / "reconcile.example.json").read_text())
    document.update(project=installation.project_id, account_id=installation.account_id,
                    region=installation.region, total_project_ceiling="12.345678")
    report = aws_readonly.reconciliation(document, tmp_path, installation=installation)
    assert "scope_mismatch" not in report["reasons"]
    assert "total_project_ceiling_mismatch" not in report["reasons"]
    document["total_project_ceiling"] = "200.00"
    assert "total_project_ceiling_mismatch" in aws_readonly.reconciliation(
        document, tmp_path, installation=installation)["reasons"]


def test_foundation_output_is_review_only_and_never_overwritten(installation, tmp_path):
    output = tmp_path / "new-review"
    self_host.write_foundation(output, installation)
    assert output.stat().st_mode & 0o777 == 0o700
    review = json.loads((output / "REVIEW_ONLY.json").read_text())
    assert review["aws_calls"] == 0 and review["policies_applied"] is False
    with pytest.raises(FileExistsError):
        self_host.write_foundation(output, installation)


def test_public_templates_contain_no_observed_owner_or_region():
    for path in self_host.TEMPLATES.rglob("*.json"):
        text = path.read_text()
        assert re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", text) is None
        assert re.search(r"pl-[0-9a-f]{8,17}(?![0-9a-f])", text) is None
        assert re.search(r"(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-[0-9]+", text) is None
    operator = json.loads((self_host.TEMPLATES / "iam-resolved-proposal" / "operator-trust.json").read_text())
    assert operator["Statement"][0]["Principal"]["AWS"] == "__INSTALL_OPERATOR_ARN__"


@pytest.mark.parametrize("region", ["cn-north-1", "us-gov-west-1", "us-iso-east-1", "eu-isoe-west-1", "eusc-de-east-1"])
def test_unsupported_partitions_fail_before_render_or_inventory(region):
    installation = InstallationConfig(project_id="my-agent", account_id="123456789012",
                                      region=region, limit_microusd=1_000_000)
    with pytest.raises(ValueError, match="commercial_aws_partition_required"):
        self_host.foundation_documents(installation)
    with pytest.raises(ValueError, match="commercial_aws_partition_required"):
        aws_readonly.inventory("fake-aws", installation=installation,
                               runner=lambda *_args, **_kwargs: pytest.fail("unsupported partition reached CLI"))
