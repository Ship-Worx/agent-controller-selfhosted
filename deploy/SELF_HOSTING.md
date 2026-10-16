# Own-account installation

Each installation uses its operator's AWS account, controller endpoint, model
provider key and durable budget ledger. There is no shared hosted service or
publisher-paid model endpoint. The runnable local demo needs no AWS account or
provider key; see the repository quickstart.

The AWS foundation and IAM files are **review drafts**. This release does not
provide a one-command production deployment. A prepared controller image,
validated ARM64 worker image, private network, observed resource identifiers,
secret delivery and deployed acceptance checks are still required. The tools
below render files or collect metadata; they do not create AWS resources.

## Trusted installation identity

Create an operator-owned JSON file outside the checkout, with mode `0600` and
protected parent directories. Use your account and chosen cumulative ceiling:

```json
{
  "schema_version": 1,
  "project_id": "my-agent-controller",
  "account_id": "123456789012",
  "region": "us-west-2",
  "limit_microusd": 10000000
}
```

The example account is fictional and the example ceiling is $10. One dollar
is 1,000,000 microUSD. Deployment tools support the commercial `aws` partition;
other partitions fail closed. The file contains identifiers and a ceiling,
never AWS credentials, provider keys or tokens. Workers cannot select or edit
the installation identity. Keep it under the trusted controller operator's
control, outside worker mounts and invocation payloads.

Create a new ledger once, using a new private path:

```bash
.venv/bin/python -m controller.project_budget init \
  --installation /absolute/private/installation.json \
  --ledger /absolute/private/project-budget.sqlite3
```

A new ledger is unreconciled and cannot authorize spending.
Before paid use, account for prior project spend, outstanding reservations and
unknown costs. Existing ledgers must match the same project, account, region
and ceiling; changing the config cannot reset history or expand their cap.
The live controller opens an existing reconciled ledger and refuses a missing
one. The application ledger does not enforce an AWS-wide billing stop.

## Render review drafts without AWS calls

```bash
.venv/bin/python -m deploy.self_host \
  --installation /absolute/private/installation.json \
  --output /absolute/private/new-foundation-review
```

The new private directory contains a foundation template and unrendered IAM
fragments bound to that exact account and region. Required resource markers
remain visibly unresolved. The account/region CloudFormation condition,
secret/key ARN patterns, exact role resources, worker trust and separation of
controller/provider permissions remain in force. Nothing is applied.

Resolve selected policy drafts only after independently reviewing metadata
outputs from resources belonging to this installation:

```bash
.venv/bin/python -m deploy.policy_package \
  --installation /absolute/private/installation.json \
  --bindings /absolute/private/reviewed-resource-outputs.json \
  --document worker-trust-steady-state.json \
  --output /absolute/private/new-policy-review
```

The example document requires `AgentRuntimeArn` from the observed exact runtime.
Operator-dependent drafts additionally require `--operator-arn` naming an
explicit same-account IAM user or role. There is no default operator. S3 worker
egress needs an observed regional `S3ManagedPrefixList`; no publisher's inventory
value is supplied. Syntactically valid metadata does not prove ownership or
effective AWS permission.

## Inspect the configured account

Using an already configured AWS CLI identity:

```bash
.venv/bin/python -m deploy.aws_readonly inventory \
  --installation /absolute/private/installation.json \
  --output /absolute/private/new-inventory.json
```

STS identity must match the configured account before any resource inventory
calls. Every request has the configured region. The fixed allowlist excludes
writes, secret values, instance user data and billing queries. An inventory is
partial metadata, not reconciled billing evidence. Keep its output private.

For local cost-evidence checks, fill a private copy of
`deploy/reconcile.example.json` and run `deploy.aws_readonly reconcile` with
`--installation`, `--input` and `--output`. Null amounts remain unknown. The
checker uses the trusted installation ceiling and never grants deployment or
paid-test approval.

## Controller, worker and provider credentials

Set `CONTROLLER_INSTALLATION_CONFIG` to the protected absolute config path and
`CONTROLLER_PROJECT_LEDGER` to the existing private ledger for live model
mode. Supply your own `CONTROLLER_OPENAI_API_KEY` only to your controller through
your secret-delivery mechanism. Workers receive a scoped controller capability
and your installation's `CONTROLLER_URL` and verified CA; they receive neither
the provider key nor AWS credentials. Other users run their own controllers and
pay their own AWS and model-provider bills.

The synthetic bootstrap renderer additionally takes `--installation`; its
`bootstrap.json` has the same nested `installation` object and matching
`account`/`region` fields. It retains exact mount identity, nonroot service
separation, runtime hashes, private TLS hostname and activation checks. See the
bootstrap module's `--help` and source contracts before preparing an image.
