# Security

## Report a vulnerability

Use the repository's **Security → Report a vulnerability** flow when private
vulnerability reporting is available. If it is unavailable, open a minimal
issue requesting a private contact channel without including exploit details,
credentials, customer data or deployment records. Do not put sensitive findings
in a public issue or pull request.

Include the affected public commit, a synthetic reproduction and the trust
boundary involved. No response-time or supported-version guarantee is implied.

## Trust model

The controller, its operator configuration, policy/validator factories,
provider gateway, protected receiver and durable state are trusted. Workers,
model output, conversation memory and action proposals are untrusted inputs.
The operator must prevent workers from reading or changing controller state,
installation identity, budget ledgers, provider credentials or operator tokens.

Separate processes on one user account demonstrate protocol behavior. Real
isolation requires independent OS/cloud identities, file permissions, TLS and
network controls. The included development HTTP listener is for loopback use;
production worker ingress requires the reviewed private TLS boundary. Never
publish an operator/admin route as a worker endpoint.

Stop prevents future claims and can request cooperative cancellation. It cannot
undo an external effect already dispatched. Interrupted or uncertain outcomes
retain their reservations until independently reconciled. Preserve the full
state directory and its fence together; backup freshness requires independent
operator evidence.

The budget ledger provides durable admission accounting. It is not a provider-
or AWS-enforced atomic spending cap, and it cannot discover missing historical
spend, unbilled usage or external commitments. Installation identity and a limit
must come from a protected operator-owned file, never a worker request.

## Deployment review

Each operator chooses and pays for their own AWS/provider accounts. Keep keys
in a secret manager or trusted supervisor environment, retain separate worker
and operator identities, and review exact IAM resources and network access.
AWS renderers emit drafts without applying them. Image building, IAM/service
activation, restoration and deployed-boundary checks require explicit local
operator decisions and evidence. Synthetic tests do not establish deployment
acceptance.
