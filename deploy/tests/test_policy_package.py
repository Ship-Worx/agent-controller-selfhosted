"""Offline regression tests for review-draft binding and privilege boundaries."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


DEPLOY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("policy_package", DEPLOY / "policy_package.py")
policy_package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy_package)
PACKAGE = policy_package.PACKAGE

from controller.installation import InstallationConfig
INSTALLATION = InstallationConfig(project_id="synthetic-policy", account_id="123456789012", region="us-west-2", limit_microusd=200_000_000)

def render_documents(*args, **kwargs):
    return policy_package.render_documents(*args, installation=INSTALLATION, operator_arn="arn:aws:iam::123456789012:user/release-operator", **kwargs)


def document(name):
    return policy_package.installation_document(PACKAGE / name, INSTALLATION, operator_arn="arn:aws:iam::123456789012:user/release-operator")


def fixture_outputs():
    """Invented unit-test values only; never inventory or deployment inputs."""
    bindings = {
        "PilotVpc": "vpc-00000000000000001", "PilotSubnet": "subnet-00000000000000001",
        "PilotRouteTable": "rtb-00000000000000001", "Controller": "i-00000000000000001",
        "ControllerDataVolume": "vol-00000000000000001", "PreparedControllerImageId": "ami-00000000000000001",
        "PrivateHostedZone": "ZUNITTESTONLY", "S3ManagedPrefixList": "pl-01234567",
        "PilotKey.Arn": "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-0000-0000-000000000001",
        "AdminSecret": "arn:aws:secretsmanager:us-west-2:123456789012:secret:agent-controller/pilot/admin-AbCd12",
        "TlsSecret": "arn:aws:secretsmanager:us-west-2:123456789012:secret:agent-controller/pilot/tls-AbCd12",
        "AgentRuntimeArn": "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/agent_controller_pilot-UnitTest01",
        "SelectedEndpointArn": "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/agent_controller_pilot-UnitTest01/runtime-endpoint/PILOT",
        "WorkerPlatformLogGroupArn": "arn:aws:logs:us-west-2:123456789012:log-group:/aws/bedrock-agentcore/runtimes/agent_controller_pilot-UnitTest01-PILOT",
    }
    for index, key in enumerate(("ControllerSecurityGroup", "WorkerSecurityGroup", "ControllerEndpointSecurityGroup", "WorkerEndpointSecurityGroup"), 1):
        bindings[key] = f"sg-{index:017x}"
    for index, key in enumerate(("EcrApiEndpoint", "EcrDockerEndpoint", "LogsEndpoint", "SecretsManagerEndpoint", "SsmEndpoint", "SsmMessagesEndpoint", "S3GatewayEndpoint"), 1):
        bindings[key] = f"vpce-{index:017x}"
    return bindings


class PolicyBindingTests(unittest.TestCase):
    def test_complete_fixture_resolves_every_registered_document(self):
        rendered = render_documents(fixture_outputs())
        self.assertEqual(set(rendered), set(document("binding-contract.json")["documents"]))
        raw = json.dumps(rendered)
        self.assertNotIn('"Ref":', raw)
        self.assertNotIn('"Fn::', raw)
        self.assertNotIn("__OBSERVED_", raw)
        self.assertIn("${aws:userid}", raw)

    def test_missing_generated_output_fails_instead_of_inventing_it(self):
        with self.assertRaisesRegex(policy_package.PolicyInputError, "missing required output"):
            render_documents({}, ["worker-trust-steady-state.json"])

    def test_unbound_bootstrap_trust_renders_as_its_own_review_phase(self):
        rendered = render_documents({}, ["worker-trust-bootstrap.json"])
        self.assertIn("runtime/agent_controller_pilot-*", json.dumps(rendered))

    def test_wrong_account_region_wildcard_and_secret_values_rejected(self):
        for key, value in [
            ("AdminSecret", fixture_outputs()["AdminSecret"].replace("123456789012", "999999999999")),
            ("AgentRuntimeArn", fixture_outputs()["AgentRuntimeArn"].replace("us-west-2", "eu-west-1")),
            ("Controller", "i-*"), ("admin_token", "do-not-echo-secret"),
            ("AdminSecret", "do-not-echo-secret"),
        ]:
            with self.subTest(key=key, value_type=type(value).__name__):
                with self.assertRaises(policy_package.PolicyInputError) as caught:
                    render_documents({key: value}, ["controller-trust.json"])
                self.assertNotIn("do-not-echo-secret", str(caught.exception))

    def test_runtime_endpoint_and_log_identity_must_agree(self):
        for key in ("SelectedEndpointArn", "WorkerPlatformLogGroupArn"):
            bindings = fixture_outputs()
            bindings[key] = bindings[key].replace("UnitTest01", "UnitTest02")
            with self.assertRaisesRegex(policy_package.PolicyInputError, "different runtime"):
                render_documents(bindings)

    def test_shared_endpoint_security_group_rejected(self):
        bindings = fixture_outputs()
        bindings["ControllerEndpointSecurityGroup"] = bindings["WorkerEndpointSecurityGroup"]
        with self.assertRaisesRegex(policy_package.PolicyInputError, "must be distinct"):
            render_documents(bindings)

    def test_cleanup_requires_each_distinct_returned_endpoint_id(self):
        bindings = fixture_outputs()
        del bindings["S3GatewayEndpoint"]
        with self.assertRaisesRegex(policy_package.PolicyInputError, "missing required output binding: S3GatewayEndpoint"):
            render_documents(bindings, ["cleanup-ephemeral.cfn.json"])
        bindings = fixture_outputs()
        bindings["EcrDockerEndpoint"] = bindings["EcrApiEndpoint"]
        with self.assertRaisesRegex(policy_package.PolicyInputError, "endpoint output bindings must be distinct"):
            render_documents(bindings)

    def test_unknown_document_and_path_traversal_rejected(self):
        for name in ("../kms-key-policy.json", "unreviewed.json"):
            with self.assertRaisesRegex(policy_package.PolicyInputError, "allowlist"):
                render_documents({}, [name])

    def test_duplicate_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bindings.json"
            path.write_text('{"Controller":"i-00000001","Controller":"i-00000002"}')
            with self.assertRaisesRegex(policy_package.PolicyInputError, "duplicate JSON"):
                policy_package.read_json(path)

    def test_unknown_intrinsic_and_ref_cannot_pass_through(self):
        for bad in ({"Fn::ImportValue": "shared-default-vpc"}, {"Ref": "UnregisteredRole"}):
            with tempfile.TemporaryDirectory() as directory:
                package = Path(directory)
                contract = document("binding-contract.json")
                contract["documents"] = ["bad.json"]
                (package / "binding-contract.json").write_text(json.dumps(contract))
                (package / "bad.json").write_text(json.dumps(bad))
                with self.assertRaises(policy_package.PolicyInputError):
                    render_documents({}, package=package)

    def test_output_directory_is_new_and_existing_evidence_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "rendered"
            rendered = render_documents({}, ["controller-trust.json"])
            policy_package.write_review_output(rendered, destination)
            manifest = policy_package.read_json(destination / "REVIEW_ONLY.json")
            self.assertFalse(manifest["policies_applied"])
            self.assertFalse(manifest["provenance_verified"])
            before = (destination / "controller-trust.json").read_bytes()
            with self.assertRaises(FileExistsError):
                policy_package.write_review_output(rendered, destination)
            self.assertEqual(before, (destination / "controller-trust.json").read_bytes())

    def test_attachment_groups_are_sized_and_do_not_mix_policy_types(self):
        rendered = render_documents(fixture_outputs())
        groups = policy_package.attachment_groups(rendered)
        self.assertEqual(set(groups), {"controller", "worker", "operator", "deployment"})
        self.assertLessEqual(len(groups["deployment"]["policies"]), 10)
        for name, group in groups.items():
            limit = 6144 if group["attachment_type"] == "managed" else 10240
            self.assertTrue(all(size <= limit for size in group["policy_characters"]))
            self.assertFalse(group["existing_role_policy_usage_verified"])
            for policy in group["policies"]:
                self.assertEqual(set(policy), {"Version", "Statement"})
                sids = [s["Sid"] for s in policy["Statement"]]
                self.assertEqual(len(sids), len(set(sids)))
                self.assertTrue(all("Principal" not in s for s in policy["Statement"]))
        self.assertNotIn("key-cleanup.cfn.json", groups["deployment"]["documents"])
        self.assertNotIn("deployment-route53-create-exception.json", groups["deployment"]["documents"])

    def test_partial_phase_does_not_claim_a_complete_attachment_group(self):
        rendered = render_documents({}, ["controller-trust.json"])
        self.assertEqual(policy_package.attachment_groups(rendered), {})


class PolicySecurityTests(unittest.TestCase):
    def test_ephemeral_cleanup_has_exact_returned_targets_and_preserves_state(self):
        bindings = fixture_outputs()
        cleanup = render_documents(bindings, ["cleanup-ephemeral.cfn.json"])["cleanup-ephemeral.cfn.json"]
        actions = {action for statement in cleanup["Statement"] for action in statement["Action"]}
        self.assertEqual(actions, {
            "bedrock-agentcore:DeleteAgentRuntimeEndpoint", "bedrock-agentcore:DeleteAgentRuntime",
            "ec2:TerminateInstances", "ec2:DeleteVpcEndpoints",
            "route53:ChangeResourceRecordSets", "route53:DeleteHostedZone",
        })
        by_action = {action: statement for statement in cleanup["Statement"] for action in statement["Action"]}
        self.assertEqual(by_action["bedrock-agentcore:DeleteAgentRuntimeEndpoint"]["Resource"], bindings["SelectedEndpointArn"])
        self.assertEqual(by_action["bedrock-agentcore:DeleteAgentRuntime"]["Resource"], bindings["AgentRuntimeArn"])
        self.assertEqual(by_action["ec2:TerminateInstances"]["Resource"], "arn:aws:ec2:us-west-2:123456789012:instance/" + bindings["Controller"])
        expected = {"arn:aws:ec2:us-west-2:123456789012:vpc-endpoint/" + bindings[key] for key in document("binding-contract.json")["cleanup_endpoint_bindings"]}
        self.assertEqual(set(by_action["ec2:DeleteVpcEndpoints"]["Resource"]), expected)
        self.assertEqual(len(expected), 7)
        for statement in cleanup["Statement"]:
            self.assertNotIn("*", json.dumps(statement["Resource"]))
        record = by_action["route53:ChangeResourceRecordSets"]["Condition"]["ForAllValues:StringEquals"]
        self.assertEqual(record["route53:ChangeResourceRecordSetsActions"], ["DELETE"])
        self.assertEqual(record["route53:ChangeResourceRecordSetsRecordTypes"], ["A"])
        self.assertEqual(record["route53:ChangeResourceRecordSetsNormalizedRecordNames"], ["controller.agent-controller.internal"])
        self.assertEqual(by_action["route53:ChangeResourceRecordSets"]["Condition"]["Null"], {key: "false" for key in record})

    def test_retention_cleanup_is_separate_exact_and_has_secret_recovery_window(self):
        bindings = fixture_outputs()
        cleanup = render_documents(bindings, ["cleanup-retained-data.cfn.json"])["cleanup-retained-data.cfn.json"]
        by_action = {action: statement for statement in cleanup["Statement"] for action in statement["Action"]}
        self.assertEqual(set(by_action), {"ec2:DeleteVolume", "secretsmanager:DeleteSecret", "ecr:DeleteRepository", "logs:DeleteLogGroup"})
        self.assertEqual(by_action["ec2:DeleteVolume"]["Resource"], "arn:aws:ec2:us-west-2:123456789012:volume/" + bindings["ControllerDataVolume"])
        secrets = by_action["secretsmanager:DeleteSecret"]
        self.assertEqual(secrets["Resource"], [bindings["AdminSecret"], bindings["TlsSecret"]])
        self.assertEqual(secrets["Condition"]["BoolIfExists"], {"secretsmanager:ForceDeleteWithoutRecovery": "false"})
        self.assertEqual(secrets["Condition"]["NumericEquals"], {"secretsmanager:RecoveryWindowInDays": "7"})
        self.assertEqual(by_action["ecr:DeleteRepository"]["Resource"], "arn:aws:ecr:us-west-2:123456789012:repository/agent-controller-worker")
        logs = {statement["Resource"] for statement in cleanup["Statement"] if "logs:DeleteLogGroup" in statement["Action"]}
        self.assertEqual(logs, {
            "arn:aws:logs:us-west-2:123456789012:log-group:/agent-controller/agent-controller-pilot/controller:*",
            bindings["WorkerPlatformLogGroupArn"] + ":*",
        })
        for group in document("attachment-groups.json")["groups"].values():
            self.assertNotIn("cleanup-ephemeral.cfn.json", group["documents"])
            self.assertNotIn("cleanup-retained-data.cfn.json", group["documents"])

    def test_no_provider_creation_or_workload_access(self):
        for name in document("binding-contract.json")["documents"]:
            if name == "endpoint-policies.cfn.json":
                raw = json.dumps(document(name)["PolicyDocuments"])
            else:
                raw = json.dumps(document(name))
            self.assertNotIn('"ProviderSecret"', raw, name)
            self.assertNotIn("agent-controller/pilot/provider", raw, name)

    def test_no_wildcard_actions_or_unneeded_workload_privileges(self):
        policies = document("binding-contract.json")["documents"]
        for name in policies:
            data = document(name)
            groups = data.get("PolicyDocuments", {"document": data})
            for group in groups.values():
                for statement in group.get("Statement", []):
                    actions = statement["Action"]
                    for action in actions if isinstance(actions, list) else [actions]:
                        self.assertNotIn("*", action, (name, action))
        worker = json.dumps(document("worker-identity-steady-state.json"))
        for prefix in ("secretsmanager:", "kms:", "ec2:", "iam:", "bedrock:", "xray:", "bedrock-agentcore:"):
            self.assertNotIn(prefix, worker)

    def test_key_resource_wildcard_is_self_only_with_narrow_delegated_principals(self):
        for statement in document("kms-key-policy.json")["Statement"]:
            self.assertEqual(statement["Resource"], "*")
            self.assertEqual(statement["Principal"], {"AWS": "arn:aws:iam::123456789012:root"})
            principals = statement["Condition"]["StringEquals"]["aws:PrincipalArn"]
            for principal in principals if isinstance(principals, list) else [principals]:
                self.assertNotIn("*", principal)
                self.assertNotIn("-worker", principal)
            if "kms:CreateGrant" in statement["Action"]:
                self.assertEqual(statement["Condition"]["Bool"], {"kms:GrantIsForAWSResource": "true"})
            if "kms:ScheduleKeyDeletion" in statement["Action"]:
                self.assertEqual(principals, "arn:aws:iam::123456789012:user/release-operator")
                self.assertEqual(statement["Condition"]["NumericEquals"], {"kms:ScheduleKeyDeletionPendingWindowInDays": "7"})

    def test_secret_decrypt_has_exact_context_and_service(self):
        statements = document("controller-identity.cfn.json")["Statement"]
        decrypt = next(s for s in statements if s["Action"] == "kms:Decrypt")
        condition = decrypt["Condition"]["StringEquals"]
        self.assertEqual(condition["kms:ViaService"], "secretsmanager.us-west-2.amazonaws.com")
        self.assertEqual(condition["kms:EncryptionContext:SecretARN"], [{"Ref": "AdminSecret"}, {"Ref": "TlsSecret"}])

    def test_operator_can_only_forward_fixed_controller_port(self):
        doc = document("operator-session-document.cfn.json")["Properties"]["Content"]
        self.assertEqual(doc["sessionType"], "Port")
        self.assertEqual(doc["properties"], {"portNumber": "8787", "localPortNumber": "8787"})
        self.assertNotIn("parameters", doc)
        policy = document("operator-ssm.cfn.json")
        start = policy["Statement"][0]
        self.assertEqual(start["Action"], ["ssm:StartSession"])
        self.assertEqual(start["Condition"]["BoolIfExists"], {"ssm:SessionDocumentAccessCheck": "true"})
        self.assertNotIn("SendCommand", json.dumps(policy))
        self.assertNotIn("RunShell", json.dumps(policy))

    def test_runtime_creation_and_update_both_require_private_network_inputs(self):
        for name, action in [("deployment-runtime-create.cfn.json", "bedrock-agentcore:CreateAgentRuntime"), ("deployment-runtime-output-bound.json", "bedrock-agentcore:UpdateAgentRuntime")]:
            statement = next(s for s in document(name)["Statement"] if action in s["Action"])
            condition = statement["Condition"]
            for key in ("subnets", "securityGroups"):
                self.assertEqual(condition["Null"]["bedrock-agentcore:" + key], "false")
            self.assertEqual(condition["ForAllValues:StringEquals"], {
                "bedrock-agentcore:subnets": [{"Ref": "PilotSubnet"}],
                "bedrock-agentcore:securityGroups": [{"Ref": "WorkerSecurityGroup"}],
            })

    def test_deployment_service_role_does_not_modify_itself(self):
        role = "arn:aws:iam::123456789012:role/agent-controller-pilot-deployment"
        for name in ("deployment-foundation-create-exceptions.json", "deployment-output-bound.cfn.json"):
            for statement in document(name)["Statement"]:
                if any(action.startswith("iam:") for action in statement["Action"]):
                    self.assertNotIn(role, json.dumps(statement["Resource"]))

    def test_logs_tagging_does_not_use_iam_group_suffix(self):
        rendered = render_documents(fixture_outputs(), ["deployment-output-bound.cfn.json", "deployment-runtime-output-bound.json"])
        for policy in rendered.values():
            for statement in policy["Statement"]:
                if "logs:TagResource" in statement["Action"]:
                    self.assertFalse(statement["Resource"].endswith(":*"))


if __name__ == "__main__":
    unittest.main()
