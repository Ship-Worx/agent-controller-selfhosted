# Research lessons and implementation status

The controller already enforced a trusted permission contract, narrowed
delegation, bound approvals to actions, checked current authority at dispatch,
shared root budgets and retained uncertain outcomes. The research identified
ways to operate those controls and demonstrate that integrations use them.
The status below distinguishes implemented code from deployment evidence.

| Lesson | Incorporated here | Evidence and practical limit |
|---|---|---|
| Cordum: make policy changes reviewable | Offline contract inspection, saved review history, semantic comparison and a recovery guide | [Policy review](POLICY_REVIEW.md), `tests/test_policy_review.py`. Saved JSON grants no execution authority. Policy activation, shadow evaluation, request replay and job migration remain planned. |
| Arbiter: enforce at the receiving tool | Existing durable reservation, current dispatch claim and result-release gates; a separate closed AWS identity receiver exercises those gates | [AWS identity demonstration](AWS_IDENTITY_DEMO.md), `controller/durable.py`, `controller/aws_identity.py`, `tests/test_aws_identity.py`. The live STS slice passed eight assertions, including a denied action with no adapter dispatch. Operational receipts are retained privately. The reference test does not establish production IAM or OS isolation. |
| AgentArmor: verify the actual integration path | Real Agents SDK process demonstrations, allowed/denied action checks and a claim-to-test map | [Observability](OBSERVABILITY.md), `tests/test_worker_process.py`, `tests/test_contract_demo.py`. The model is scripted. Supported calls are tested; this does not establish protection for arbitrary tools or every SDK feature. |
| Observability: distinguish requests from authorization and effects | Correlated agent/controller streams with source labels, policy/configuration pins, epochs and explicit missing-evidence handling | `integration/telemetry.py`, `tests/test_trace_correlation.py`. Agent observations are diagnostics; external effects need trusted destination evidence. |
| Evaluation: inspect both streams without exporting arbitrary contents | Optional Braintrust file exporter, explicit field/code allowlists, deterministic consistency checks and offline previews | [Braintrust guide](BRAINTRUST.md), `tests/test_trace_export.py`, `tests/test_braintrust_export.py`. Live ingestion is separate validation; imported files do not prove their origin. |

## What the policy addition gives an operator

The rulebook already exists. The addition makes changes visible: for example,
whether a revision expands access from one assigned record to every record,
raises a budget, removes an approval requirement or changes validation code.
An operator can inspect and compare saved revisions, identify the configuration
used by a job, and follow recovery instructions when an old job requires its
original configuration. Existing fingerprints remain enforced.

## What still requires deployment work

Native AWS worker acceptance, least-privilege IAM enforcement, private network
and filesystem isolation, production trace retention and distributed execution
remain separate work. The earlier native ARM64 attempt did not complete runtime
acceptance. A local controller gating a real AWS request does not close that gap.

Policy promotion, shadow evaluation, historical decision replay, an operator
approval interface over the existing core primitive, and distributed controller
ownership are also separate features. No LLM judge can grant permission, release
an uncertain budget hold or substitute for trusted execution evidence.

The upstream projects were inspected at explicit revisions:
[Cordum `24caf512`](https://github.com/cordum-io/cordum/tree/24caf512db79e82efab3667920a24dcd9d8a997c),
[Arbiter `fd794314`](https://github.com/yajasmalhotra/arbiter/tree/fd79431425cb7d395958c839e272f4a12a89137f),
and [AgentArmor `54015b5b`](https://github.com/Agastya910/agentarmor/tree/54015b5ba5d9f63077479147084f42a2f2740653).
These are design lessons and coverage references, not a claim of copied code,
equivalent implementations or production certification.
