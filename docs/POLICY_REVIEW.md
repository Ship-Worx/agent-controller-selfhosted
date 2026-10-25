# Review the contract your agent must obey

The controller already enforces an operator-owned contract: permitted actions,
resources, recipients, prerequisites, delegation and limits. The worker proposes;
the trusted controller and receiver check that proposal before an effect.

The policy tracker adds offline inspection, saved configuration revisions and
change comparison around that existing contract. It reads the trusted compiled
workflow registry. Review JSON never becomes executable policy or job authority.
The current commands cover the two synthetic workflows; live model pricing and
deployment acceptance retain their existing installation-specific checks.

## See permission enforcement

After the normal installation, run:

```bash
.venv/bin/python -m demo.contract
```

The real Agents SDK worker first reads fictional `candidate-a`, which its contract
permits, then proposes reading `candidate-b`, which is outside its scope. Eight
checks verify the controller's decisions, receiver dispatch and effect journal:

| Proposal | Controller decision | Protected effect |
|---|---|---|
| Read assigned `candidate-a` | Allowed | One fictional read receipt |
| Read unassigned `candidate-b` | Denied: `outside_scope` | Zero additional effects |

The command prints a report path under `.runtime/contract-demo/`. That report
contains the assigned task, actual permitted capabilities, observed decisions
and correlated allowlisted agent/controller events. Temporary credentials,
worker receipts, unfiltered traces and databases are removed
after the processes stop. This scenario demonstrates permission enforcement; it
does not claim the worker completed its assigned report-writing task. The
existing `demo.run` still demonstrates complete workflows, Stop and recovery.
The local processes share an OS user; AWS/OS isolation needs deployment testing.
Run `.venv/bin/python -m demo.observe` to print both trace streams; see
[observability](OBSERVABILITY.md) for their interpretation and coverage.

## Inspect the current contract

```bash
.venv/bin/python -m controller.policy_review inspect --workflow recruiting
```

The JSON describes capabilities, required context field names, payload schemas,
dependencies, approvals, principal scope, limits, trusted synthetic prices and
maximum admitted synthetic budget. It includes the validator policy/source and
fixture hashes, `policy_pin`, exact durable `config_pin` and content-based
`review_id`. Raw fixture records, context values, prompts and credentials are
excluded. Use `--runtime-seconds` and `--budget-microusd` to describe the same
parameters you intend to give a new synthetic job. Defaults match job admission:
60 seconds and 30 microUSD of synthetic budget. These are fictional local costs.

The descriptor uses the same finite, sorted serialization as the durable
authority. It does not construct a broker/authority, open a ledger, activate an
epoch, execute a validator against requests or make a network call.

## Save and list review revisions

```bash
.venv/bin/python -m controller.policy_review capture \
  --workflow recruiting --archive .runtime/policy-reviews
.venv/bin/python -m controller.policy_review history \
  --archive .runtime/policy-reviews
```

Each revision is saved as `<review_id>.json` in the private archive. The directory
must belong to the current operator with mode `0700`; records use mode `0600`.
Symlink aliases, unsafe file permissions, inconsistent hashes and unexpected
archive entries are rejected. Capturing the same configuration again returns
the existing record without rewriting it. There is a limit of 256 records and
256 KiB per snapshot. Keep separate archives when that bound is reached.

History lists saved review revisions and their filesystem modification times.
Those timestamps are informational. There is no active-policy pointer, signer,
authenticated approver or tamper-resistant activation history in this archive.
Hashes prove internal consistency; a person who can rewrite the archive can
also recompute its hashes. Trusted installation and runtime authority remain
separate from these review files. Keep snapshots private and out of Git.

## Compare a proposed configuration

This example previews a smaller synthetic budget without changing any job:

```bash
umask 077
mkdir -p .runtime
.venv/bin/python -m controller.policy_review inspect --workflow recruiting \
  > .runtime/policy-before.json
.venv/bin/python -m controller.policy_review inspect --workflow recruiting \
  --budget-microusd 20 > .runtime/policy-proposed.json
.venv/bin/python -m controller.policy_review compare \
  --before .runtime/policy-before.json --after .runtime/policy-proposed.json
```

Comparison reports added/removed exact capabilities and changes to configuration
fields, including limits, recipients, resources, dependencies, approval rules,
validator version and source hash. A saved archive record can also be used for
`--before` or `--after`. Unknown fields, duplicate JSON keys, nonfinite numbers,
invalid schemas and mismatched hashes are rejected.

A source-hash change remains visible even if the displayed permissions match.
Matching permissions do not prove equivalent validator behavior. The tracker
does not reconstruct historical requests from hashes or run proposed policies
against real tools. Compare output is a review aid, with no execution authority.

## Recover with the original trusted configuration

An existing job is bound to its contract, validator policy, prices and original
budget. The validator currently hashes all of `workflows/definitions.py`, so an
unrelated edit can also change the configuration fingerprint. Restart correctly
refuses a mismatched configuration. Saving a review snapshot does not change
that behavior.

Before changing trusted workflow code, retain the exact reviewed source/runtime,
its dependency lock and the appropriate private review record. Finish or stop
jobs under that configuration when practical. If an upgrade cannot reopen an
old job, compare the saved review record with the proposed configuration and
restore the matching trusted software through the normal deployment process.
Use the original state volume and existing startup/recovery checks. Restoration
of an entire state volume still requires independent recovery evidence.

Never overwrite stored configuration pins, copy old operations into a fresh
ledger, clear an unknown reservation, or replay a paid operation to get past a
mismatch. Old approvals and tickets remain subject to restart/Stop/revocation
checks. Live jobs additionally require their exact trusted pricing configuration.

Running old and new policy revisions concurrently, migrating a job to new rules
and selecting retained executable validators require a separate trusted revision
resolver. This first tracker supplies inspection and review records; it provides
no policy activation, automatic migration or automatic retry command.
