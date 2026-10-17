# See the agent and controller at work

Observability is part of the security demonstration. An operator needs to see
what the agent attempted, how the controller decided, whether a protected tool
started, and what outcome is known. Those facts have different sources.

After installation, run the keyless local example:

```bash
.venv/bin/python -m demo.observe
```

It starts separate controller and real Agents SDK processes with a scripted
model. The agent reads its assigned fictional record, then attempts a different
record. The terminal displays the agent and controller streams for each
operation. An allowlisted JSON report is saved under
`.runtime/observability-demo/`; temporary credentials, raw receipts and process
databases are removed when the processes stop.

The permitted operation should show an agent proposal/result alongside the
controller's reservation, tool start/finish and result release. The forbidden
operation should show `outside_scope` and no protected tool start. Eight checks
verify the two streams, matching policy/authority bindings and the independent
effect journal. The model is scripted; SDK model events do not represent paid
provider calls. This example proves local application behavior.

## Interpret each source

| Source | Events | What they establish |
|---|---|---|
| Agent SDK hooks | Agent, model and local tool lifecycle | Which SDK callbacks ran in that agent invocation. A local tool callback is the request wrapper, not proof of an authorized protected effect. |
| Agent transport observations | Action/model request and result; terminal run status | What the agent requested and what response it observed. These are agent-reported diagnostics. |
| Controller journal | Proposal, decision, protected tool start/finish, result release | The trusted controller's observed authorization and protected execution path. |
| Controller budget/provider records | Measured usage or retained unknown outcome | What usage is actually measured and what remains uncertain. An SDK callback cannot establish a bill. |

The effect journal supplies the independent effect count in this synthetic
example. Neither an agent's claim of success nor an absent trace establishes
that an external effect occurred or did not occur. Real tools need their own
trusted receipts, idempotency and reconciliation.

## Join the right events

Agent events contain an invocation ID, increasing `seq` and monotonic
`elapsed_ms`. Controller events contain their durable `event_id` and wallclock
`at`, together with configuration/policy pins, authority epoch and controller
instance ID. Controller restart creates a new instance and advances the epoch;
earlier journal events keep their original metadata.

Use **run-ID hash plus operation-ID hash** when joining the two streams. An
operation name can be reused in another run. Both hashes are diagnostics, never
bearer credentials or authority to execute. The demo additionally verifies the
same policy pins, epoch and controller instance for its single-run scenario.

Preserve each source's own order. Wallclock values from separate processes do
not establish a precise combined timeline. The terminal groups related events
and labels the two source sequences separately. The agent report's common
controller metadata is the latest valid binding it observed; it is not a claim
that every earlier event occurred in that epoch. The controller retains
per-event bindings.

Both the scripted worker and the controller-model worker use the same local SDK
hooks. Model transport events correlate with the existing controller `/model`
operation IDs. Cancellation, malformed replies and unknown model outcomes keep
their existing conservative status and accounting. Tracing adds no retry.

## Keep traces useful and private

Local agent telemetry records fixed event/status labels, reviewed reason codes,
hashes and numeric timing. It deliberately ignores SDK hook arguments, which
can contain prompts, tool arguments, context, responses and final output. A
secret's alphanumeric shape is insufficient to treat it as a safe reason code;
unknown reason strings become `unrecognized_reason`.

The scripted agent wrapper terminates on any non-allowed action response. Its
terminal status describes that wrapper stopping; the correlated `action_result`
retains a controller `held` status when the effect outcome is uncertain. Use the
controller's operation and accounting records to determine that outcome.

Agent traces are held in memory and returned with the agent result. They are
bounded to 64 events and 16 KiB, with explicit `truncated`, `dropped_events` and
`unavailable` fields. A terminal event has reserved space. These observations
are best effort: diagnostic failures do not grant authority, retry a request,
refund an uncertain charge or change an existing outcome. A process killed
before returning can lose its in-memory agent trace. Controller journal records
remain the source for recovery evidence.

The AWS worker HTTP adapter retains its fixed response-size limit. If optional
agent telemetry alone would exceed that limit, it omits the trace and marks the
response header `X-Agent-Trace-Status: omitted_response_limit`, preserving the
otherwise valid result. An absent agent trace always means missing evidence.

The demo projects both streams through explicit field/code allowlists. It keeps
no raw prompts, record contents, bearer tokens, tickets or raw tool responses.
The normal agent result can contain an authorized receipt; the separate
`agent_trace` contains only telemetry. SDK remote export remains disabled via
the existing global and per-run settings; this feature sends no trace data to
an external service.

Keep runtime artifacts private and out of Git. The current controller `/trace`
route retains its existing authenticated operator/run scoping. A local trace
file is not an immutable external audit archive.

For an optional post-run view in the operator's own Braintrust project, see the
[Braintrust exporter](BRAINTRUST.md). It defaults to an offline projection of
this demonstration's report; only an explicit trusted operator invocation sends
the selected metadata. It does not enable SDK remote tracing or make imported
files authoritative controller evidence.

## Verify the claims

| Claim | Enforcement/evidence | Regression coverage |
|---|---|---|
| Authorized read executes; overreach is blocked | Controller decision, protected dispatch and effect journal joined to actual SDK observations | `tests/test_contract_demo.py` |
| Agent success cannot substitute for controller evidence | Renderer reports missing controller evidence as unconfirmed | `tests/test_observability_demo.py` |
| Trace records cannot expose arbitrary hook contents | Fixed fields/reasons, no serialization of prompts or outputs | `tests/test_telemetry.py`, `tests/test_trace_correlation.py` |
| A restart preserves earlier evidence and records the new epoch | Controller per-event pins and fresh instance ID | `tests/test_trace_correlation.py` |
| Unknown model outcomes stay held with unknown usage and no retry | Existing controller-model SDK path, safe model-operation correlation | `tests/test_trace_correlation.py`, `tests/test_live_worker_uncertainty.py` |
| Stop blocks later actions and restart does not repeat effects | Existing authority and receiver checks | `tests/test_worker_process.py`, `tests/test_service.py` |
| Truncation is visible; missing observations do not imply no effect | Bounded trace envelope and renderer | `tests/test_telemetry.py`, `tests/test_observability_demo.py` |

The standalone joined demonstration covers allowed and denied actions. Existing
tests cover Stop, restart and uncertainty; this document does not claim a single
combined production trace has exercised all of them on AWS. Native AWS runtime
acceptance, live streaming, CloudWatch retention and distributed trace
collection remain deployment work. The optional file-based Braintrust exporter
does not close those gaps. No paid model call or AWS resource is needed for
these local demonstrations and tests.
