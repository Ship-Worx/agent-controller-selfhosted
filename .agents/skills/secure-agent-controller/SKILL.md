---
name: secure-agent-controller
description: Guide secure agent workflows using this repository's controller. Use when designing, reviewing, integrating, testing, deploying, or operating protected agent actions, including OpenAI Agents SDK workers and AWS boundaries.
---

# Secure Agent Controller

This repo-specific adapter applies the `deploy-secure-aws-openai-agents` lifecycle to this controller. Use the lifecycle skill as additional guidance when it is available; this adapter also works on its own. Neither skill grants access, enforces runtime security, or proves deployment safety.

## Start with the existing system

1. Inspect the current checkout, changes, architecture, installed dependencies, and relevant tests before proposing work. Preserve the separate OpenAI Agents SDK worker and trusted controller unless the task justifies a change. Start read-only; identify the requested workflow, users, tenant binding, allowed and prohibited actions, data, approval boundaries, budgets, and recovery needs. Use synthetic fixtures first.
2. Map each control to code and evidence. Use **planned**, **implemented**, and **verified**, with the evidence and environment for every verified claim. Distinguish application tests, live-service demonstrations, and production isolation; do not infer one from another. Report unknowns and skipped checks.
3. Inspect the security model in `SECURITY.md` and the status and limitations in `docs/SECURITY_LEARNINGS.md`. Read the relevant implementation rather than assuming every action or SDK tool is mediated.

## Apply the controller boundary

- Trace trusted contracts and validation through `controller/engine.py`, `controller/validators.py`, and `workflows/definitions.py`; inspect HTTP authentication and dispatch in `controller/service.py`. Bind user and tenant authority in trusted application code, never in model text, retrieved content, or invocation memory.
- Follow `integration/live_worker.py` and `integration/client.py` from the SDK worker's `protected_action` to the controller. Give each new protected integration an explicit receiver; fail closed on unknown actions and ensure no direct receiver or local fallback bypasses the boundary. Use least privilege, explicit action/resource/recipient scopes, and bounded schemas.
- Preserve the durable reserve, claim, adapter, settle, and release sequence in `controller/durable.py` and the integration's receiver. Recheck current authority and Stop at the dispatch boundary. Use shared budgets, idempotency, durable operation identity, and recovery for uncertain outcomes. Do not automatically repeat an effect whose outcome is unknown; Stop cannot undo an effect already dispatched.
- Inspect `controller/policy_review.py` and `docs/POLICY_REVIEW.md` for policy inspection, capture, history, and comparison. A saved review is not execution authority. If conversation, prompt, or skill memory is needed, design its persistence and trust boundary separately; reauthorize resumed actions against current policy.
- Use `integration/telemetry.py`, `integration/trace_export.py`, and `docs/OBSERVABILITY.md` to correlate proposals, decisions, and effects. Keep sensitive inputs and credentials out of traces; distinguish agent diagnostics from trusted receiver evidence. Optional Braintrust export has its own sanitation and approval boundaries.

## Verify the workflow

Map every untrusted input, including retrieved content and memory, to action surfaces. Add paired benign and adversarial cases and forced direct-call or bypass tests for the integration. Verify blocked access and zero unauthorized effects, not just model refusal wording. Existing starting points include `tests/test_security_boundary.py`, `tests/test_worker_process.py`, and `tests/test_durable.py`; also cover scope, forged authority, Stop races, replay, restart, and unknown outcomes as relevant.

Run appropriate local tests using the existing environment when available (`./scripts/test.sh -q` runs the synthetic suite). Report the commands and results actually observed. Inspect `controller/aws_identity.py`, `tests/test_aws_identity.py`, and `docs/AWS_IDENTITY_DEMO.md` for the existing read-only STS receiver; its application-gate evidence does not establish deployed IAM, network, filesystem, or worker isolation. Verify those separately in the intended environment before claiming them.

## Review deployment and operations

Inspect the existing deployment design and relevant IAM, network, credential, data ACL, and telemetry boundaries before proposing changes. Verify the actual target identity through an authorized read-only connection; do not rely on a profile name. Prepare the exact versioned package, target, infrastructure and permission changes, costs, test evidence, unresolved controls, and rollback plan.

Obtain a fresh explicit **GO** for that package before every AWS deployment or infrastructure mutation, including bootstrap, updates, redeployments, and rollbacks. A prior GO or general request to continue is not sufficient; pause if scope or verified identity changes. Obtain separate bounded approval for paid tests and any required credential, security, or data-transfer authorization. Report what was built, what was deployed, and what was actually verified; do not infer mastery or safety from completing the work.
