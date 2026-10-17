# Agent Controller

A self-hosted authorization broker for bounded agent workflows. A separate
OpenAI Agents SDK worker proposes actions; the controller owns trusted policy,
durable authorization, budget reservations, protected effects and Stop.

**Experimental release: v0.1.0-alpha.1.** The local synthetic demo is the
validated entry point. AWS deployment and target-environment registry access
require installation-specific validation; no complete AWS deployment is claimed.

Run the local demo without an API key or AWS credentials. For cloud use, each
operator supplies their own AWS account and provider credentials and pays their
own charges. AWS foundation and IAM outputs are review drafts; production
activation requires operator review and deployment validation.

## Quickstart

Use a Linux/POSIX host with Bash, Python **3.12** and
[uv](https://docs.astral.sh/uv/getting-started/installation/). The controller uses
POSIX file locks. Native Windows is not supported; use a suitable Linux host.

```bash
git clone https://github.com/Ship-Worx/agent-controller-selfhosted.git
cd agent-controller-selfhosted
./scripts/install.sh
.venv/bin/python -m demo.run
./scripts/test.sh -q
```

Setup downloads hash-locked wheels from official PyPI into this checkout's
`.venv`. It pins `openai-agents==0.23.1`, `openai==3.29.0` and pytest. After setup,
the demo and tests use synthetic models and local state; no paid model call or
AWS resource is needed. The process demo needs local loopback sockets.

A successful demo prints a JSON summary with `passed: 6` and a trace path under
`.runtime/demo/`. It runs separate controller and SDK worker processes and
exercises two workflows, denied actions, bounded delegation/shared budgets,
Stop/cancellation and restart without replayed effects. Keep generated state
and traces out of version control.

To see the contract and a blocked scope violation directly, run
`.venv/bin/python -m demo.contract`. The SDK worker reads its assigned fictional
record, then attempts another record; the controller denies that second action
and verifies zero additional effects. Only a sanitized educational report is
retained.

Inspect and save the existing permission contract with the offline policy tracker:

```bash
.venv/bin/python -m controller.policy_review inspect --workflow recruiting
.venv/bin/python -m controller.policy_review capture \
  --workflow recruiting --archive .runtime/policy-reviews
.venv/bin/python -m controller.policy_review history --archive .runtime/policy-reviews
```

[Policy review and recovery](docs/POLICY_REVIEW.md) explains configuration
comparisons and recovery under matching trusted rules. Review snapshots record
rules for inspection; they grant no execution authority or policy activation.

## Use your own installation

[Self-hosting setup](docs/SELF_HOSTING.md) explains the operator-owned account,
region, project identity and budget configuration, local ledger initialization,
and offline AWS review rendering. Configuration does not authorize spending:
a new ledger stays unreconciled until the operator supplies verified accounting.

The current live-model broker supports the OpenAI Responses API. Only the
trusted controller receives the provider credential; workers receive scoped
run tokens. There is no shared AWS account, hosted endpoint, bundled key or
funded allowance.

## What the boundary covers

The controller mediates exact protected actions, narrows delegated authority,
fences old authority across restart and retains uncertain cost exposure. Stop
blocks future claims and requests supported cancellation; an external effect
already dispatched may still finish.

Production isolation also depends on separate OS/cloud identities, protected
state, verified TLS and controlled network access. The local demo establishes
application behavior, and AWS templates need installation-specific review.
Read the [security model](SECURITY.md) before enabling live access.

## Project information

- [MIT license](LICENSE) and [source provenance](docs/PROVENANCE.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

This public repository is a clean source snapshot. Installation records,
credentials, billing ledgers and earlier private Git history are excluded.
