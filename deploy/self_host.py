"""Render installation-scoped AWS review drafts offline; never provision AWS."""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
from pathlib import Path
import re

from controller.installation import InstallationConfig, load_installation


TEMPLATES = Path(__file__).resolve().parent / "templates"
TOKEN = re.compile(r"__INSTALL_[A-Z_]+__")


def require_commercial_installation(installation: InstallationConfig):
    """These reviewed service ARNs and endpoint DNS names use partition aws."""
    if (not isinstance(installation, InstallationConfig) or re.fullmatch(
            r"(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-[0-9]+", installation.region) is None):
        raise ValueError("commercial_aws_partition_required")
    return installation


def installation_document(path: Path, installation: InstallationConfig, *, operator_arn=None):
    """Resolve only trusted installation fields, preserving exact resource scopes.

    An operator ARN is an independently reviewed same-account IAM user or role;
    credentials, assumed-role session ARNs and worker requests are not inputs.
    """
    require_commercial_installation(installation)
    if operator_arn is not None and (not isinstance(operator_arn, str) or re.fullmatch(
            r"arn:aws:iam::" + installation.account_id
            + r":(?:user|role)/[A-Za-z0-9_+=,.@-]+(?:/[A-Za-z0-9_+=,.@-]+)*", operator_arn) is None):
        raise ValueError("exact_same_account_operator_arn_required")
    values = {
        "__INSTALL_ACCOUNT__": installation.account_id,
        "__INSTALL_REGION__": installation.region,
        "__INSTALL_PROJECT__": installation.project_id,
        "__INSTALL_CEILING_USD__": str(Decimal(installation.limit_microusd) / 1_000_000),
        "__INSTALL_OPERATOR_ARN__": operator_arn,
    }
    def pairs(items):
        output = {}
        for key, item in items:
            if key in output:
                raise ValueError("duplicate_template_field")
            output[key] = item
        return output
    document = json.loads(Path(path).read_text(), object_pairs_hook=pairs)
    def resolve(value):
        if isinstance(value, str):
            def replacement(match):
                if match[0] not in values or values[match[0]] is None:
                    raise ValueError("required_installation_template_input_missing")
                return values[match[0]]
            return TOKEN.sub(replacement, value)
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if isinstance(value, dict):
            return {key: resolve(item) for key, item in value.items()}
        return value
    return resolve(document)


def foundation_documents(installation: InstallationConfig) -> dict:
    """The foundation is a review draft, not a runnable deployment stack."""
    documents = {"pilot-template.json": installation_document(TEMPLATES / "pilot-template.json", installation)}
    for path in sorted((TEMPLATES / "iam").glob("*.json")):
        documents["iam-" + path.name] = installation_document(path, installation)
    return documents


def write_foundation(output: Path, installation: InstallationConfig):
    documents = foundation_documents(installation)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, document in documents.items():
        with (output / name).open("x") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
    with (output / "REVIEW_ONLY.json").open("x") as stream:
        json.dump({"status": "review_only_not_deploy_ready", "aws_calls": 0,
                   "account_id": installation.account_id, "region": installation.region,
                   "policies_applied": False, "operator_review_required": True}, stream, indent=2)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new private local review directory")
    args = parser.parse_args(argv)
    try:
        write_foundation(args.output, load_installation(args.installation))
    except (OSError, ValueError, TypeError):
        parser.exit(2, "render rejected: invalid trusted input or output already exists\n")
    print("Installation-scoped review drafts written; no AWS calls or deployment performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
