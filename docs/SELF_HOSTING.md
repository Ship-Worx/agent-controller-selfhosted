# Self-hosting in your own accounts

The [offline quickstart](../README.md#quickstart) is the runnable starting point.
Cloud installation requires your own AWS account, region, budget decisions and
provider credentials. The current AWS renderer supports the commercial `aws`
partition; other partitions fail closed.

## Create protected installation configuration

```bash
mkdir -p .runtime/private
chmod 700 .runtime/private
cp examples/installation.example.json .runtime/private/installation.json
chmod 600 .runtime/private/installation.json
```

Edit that private copy. Replace its null account and region with your own AWS
account ID and region, choose a project identity, and set your cumulative
`limit_microusd`. One US dollar is 1,000,000 microdollars; the example limit is
USD 100, which you may change before creating a new installation. Null values
are incomplete and are rejected. The file contains no provider secret.

The exact JSON fields are `schema_version`, `project_id`, `account_id`, `region`
and `limit_microusd`. The loader requires an absolute path to a bounded regular,
non-symlink file owned by the operator or root and not writable by other users.
Protect its parent directory too. Worker requests cannot select this identity
or change its limit.

Initialize a new local accounting ledger:

```bash
.venv/bin/python -m controller.project_budget init   --installation "$PWD/.runtime/private/installation.json"   --ledger "$PWD/.runtime/private/project-budget.sqlite3"
```

Initialization refuses an existing ledger and leaves accounting unreconciled.
It does not infer zero prior spending or authorize a provider call. Keep each
project's historical costs, pending usage and outstanding commitments together.
An existing ledger must match its installation identity and stored limit;
changing a JSON file does not reset it or grant a new allowance.

### Reconcile verified accounting explicitly

The inventory/reconciliation review helpers do not write the ledger. The trusted
operator uses the ledger's Python API only after verifying all prior project
spend, pending usage and outstanding commitments against authoritative records
for this exact installation. Copy `examples/accounting.example.json` to a
protected private file and replace every null with reviewed values; do not
replace unknown amounts with zero. Evidence references must identify the
records reviewed, and `as_of` must be an aware ISO-8601 timestamp.

```bash
CONTROLLER_INSTALLATION_CONFIG="$PWD/.runtime/private/installation.json" \
CONTROLLER_PROJECT_LEDGER="$PWD/.runtime/private/project-budget.sqlite3" \
REVIEWED_ACCOUNTING="$PWD/.runtime/private/reviewed-accounting.json" \
.venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
from controller.installation import load_installation
from controller.project_budget import ProjectBudgetLedger

installation = load_installation(os.environ["CONTROLLER_INSTALLATION_CONFIG"])
review = json.loads(Path(os.environ["REVIEWED_ACCOUNTING"]).read_text())
if review["installation"] != installation.as_dict():
    raise SystemExit("reviewed accounting belongs to a different installation")
ledger = ProjectBudgetLedger.open_existing(
    os.environ["CONTROLLER_PROJECT_LEDGER"], installation=installation)
ledger.reconcile(
    prior_spent_microusd=review["prior_spent_microusd"],
    outstanding_reserved_microusd=review["outstanding_reserved_microusd"],
    evidence_refs=review["evidence_refs"],
    as_of=review["as_of"],
)
print("Reviewed reconciliation recorded; existing local operations remain preserved.")
PY
```

This is an operator action, not a worker endpoint. It records the supplied
accounting evidence; it does not independently audit a cloud bill or enforce a
provider-side spending cap. Keep that private review and the ledger out of Git.

## Render an AWS review package offline

```bash
.venv/bin/python -m deploy.self_host   --installation "$PWD/.runtime/private/installation.json"   --output "$PWD/.runtime/private/foundation-review"
```

This writes account/region-scoped foundation and IAM drafts to a new directory.
It makes no AWS calls and refuses an existing output directory. The generated
`REVIEW_ONLY.json` describes the status. These are review inputs: inspect
resource names, IAM trust, account/region bindings, networks, encrypted state,
TLS and cleanup before applying anything with your own deployment process.
There is no automatic application deployment in this command.

After resource outputs are independently reviewed, render selected policy
fragments with your own bindings JSON, for example:

```bash
.venv/bin/python -m deploy.policy_package   --installation "$PWD/.runtime/private/installation.json"   --bindings "$PWD/.runtime/private/outputs.json"   --document worker-trust-steady-state.json   --output "$PWD/.runtime/private/policy-review"
```

Bindings contain reviewed resource identifiers, never credential or secret
values. Operator-dependent documents additionally require `--operator-arn`
with a reviewed same-account IAM user or role ARN. Rendered files are drafts;
no policy is attached by this tool.

## Inspect your own AWS resources

With AWS CLI v2 already configured for your account, this optional command reads
caller identity and selected resource metadata:

```bash
.venv/bin/python -m deploy.aws_readonly inventory   --installation "$PWD/.runtime/private/installation.json"   --output "$PWD/.runtime/private/inventory.json"
```

It checks the observed account against the installation and passes the chosen
region explicitly. The inventory is partial, excludes billing queries and is
private operator data. Use `deploy/reconcile.example.json` for a local accounting
review; unknown amounts remain unknown. Running a local reconciliation report
does not reconcile the durable ledger or establish complete billing coverage.

## Enable a provider only after review

The current live gateway supports the OpenAI Responses API and the reviewed
model contract in `controller/live_model.py`. A protected controller supervisor
provides these settings:

| Setting | Controller-owned value |
| --- | --- |
| `CONTROLLER_INSTALLATION_CONFIG` | Absolute path to the installation JSON |
| `CONTROLLER_PROJECT_LEDGER` | Absolute path to the existing matching ledger |
| `CONTROLLER_LIVE_CONFIG` | Absolute path to a current operator-reviewed price card |
| `CONTROLLER_OPENAI_API_KEY` | Your provider credential, supplied securely |

The price card must use the broker's accepted model/context contract, positive
verified rates and an unexpired verification window. Consult `PriceCard` in
`controller/live_model.py`; no live prices or default paid allowance are bundled.
The ledger must be authoritatively reconciled before it permits spending.
Workers receive scoped run tokens and the controller URL/CA trust, never these
operator settings or the provider key.

The bootstrap helpers and `deploy/bootstrap/inputs.example.json` provide
reviewed service-wiring drafts. They require real operator-supplied state
volume, binary identities, host identities and TLS inputs. CloudFormation/IAM
validation, image build/scan, service activation, Stop/restart and bypass checks
remain installation-specific work. Review [SECURITY.md](../SECURITY.md) and
preserve unknown outcomes and cleanup ownership throughout that process.
See [deployment review details](../deploy/SELF_HOSTING.md) for rendering and
bootstrap input contracts.
