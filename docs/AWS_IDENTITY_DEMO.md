# Control one real, read-only AWS operation

This demonstration routes a separate OpenAI Agents SDK process through the
existing durable authority before the trusted operator calls AWS STS
`GetCallerIdentity`. The model is scripted: there are no model-provider calls.
The agent then requests `sts.AssumeRole`, which the controller rejects before
the AWS adapter runs. No AWS resource is created or changed.

The contract allows one call, one action, an empty payload and one account
resource. Trusted installation configuration pins the expected AWS account,
region and SHA-256 of the exact principal ARN. Neither the agent nor its plan
can choose a credential, SDK callback, endpoint, role or region. This is a new
closed demonstration factory; existing synthetic workflow policy pins are
unchanged.

The controller follows `reserve → claim → adapter → settle → release_result`.
A reservation alone never calls AWS. Unknown or cross-run tickets, stale
authority epochs and Stop before claim prevent dispatch. Stop after claim
cannot cancel an already committed read; it prevents the receipt from being
released. Adapter errors, malformed receipts or identity mismatches leave the
operation unknown, without automatic retry or reset. State is retained privately.

## Operator bridge

Run this only in a trusted operator environment. Use fresh directories with
mode `0700`. Supply the SHA-256 of the exact reviewed principal ARN, not its
display name. The example values below are fictional.

```sh
.venv/bin/python -m demo.aws_identity \
  --bridge-dir .runtime/aws-identity-private \
  --expected-account 123456789012 \
  --region us-east-1 \
  --expected-principal-sha256 YOUR_REVIEWED_64_CHARACTER_LOWERCASE_HASH \
  --output-dir .runtime/aws-identity-report
```

This starts a controller on loopback and a separate scripted SDK agent. The
agent environment includes only a small process-variable allowlist and its
controller token. It receives no AWS, model-provider, Braintrust or controller
operator key. Local processes running as the same operating-system user are
not a filesystem isolation boundary.

The controller publishes `request.json` **only after durable claim**. A trusted
operator bridge must read and verify this closed request before making one STS
call:

```json
{
  "schema_version": 1,
  "service": "sts",
  "operation": "GetCallerIdentity",
  "region": "us-east-1",
  "params": {},
  "request_nonce": "32 lowercase hexadecimal characters",
  "run_id_hash": "64 lowercase hexadecimal characters",
  "operation_id_hash": "64 lowercase hexadecimal characters",
  "config_pin": "64 lowercase hexadecimal characters"
}
```

Verify the corresponding `dispatched` operation and `dispatch_authorized`
audit record in `state/authority.sqlite` before calling AWS. The bridge should
use the configured account and region independently of request contents. It
must make no mutating or fallback operation and must not retry an unknown
outcome. Raw AWS identity results stay in the operator environment.

After the call, publish `receipt.json` with a fresh exclusive mode-`0600` file
and atomic rename; never overwrite a previous receipt. It must have exactly
these fields:

```json
{
  "schema_version": 1,
  "request_nonce": "the exact request nonce",
  "source": "aws_mcp",
  "api_call_status": "success",
  "account_matches": true,
  "principal_sha256": "SHA-256 of the actual returned ARN",
  "request_id_sha256": null,
  "http_status": null
}
```

`account_matches` must reflect an exact comparison of the actual returned
account to trusted configuration. The principal hash must match the pinned
expected principal. If AWS response metadata is available, supply its numeric
HTTP status (`200` is required) and the hash of its actual request ID. The AWS
MCP connector may confirm a successful API call without returning either
metadata field; preserve those fields as `null`. Never infer status `200` or
invent a request ID. The receipt records a trusted operator observation, not a
cryptographic statement from AWS.

Bridge files are limited to 4 KiB, mode `0600`, regular files with one link,
owned by the current user. Symlinks, duplicate JSON keys and nonfinite values
are rejected. There is one pending request and no automatic retry. The bridge
wait is bounded to 45 seconds. This demonstration's separate SDK entrypoint
uses a fixed 60 second controller request timeout and a 75 second execution
limit to accommodate the operator tool bridge. Production client and worker
timeouts remain unchanged.

## Evidence and scope

On success, `contract-report.json` contains eight checked assertions, the
sanitized identity receipt and separately labeled agent/controller traces.
Records correlate by run and operation hashes and include policy/configuration
pins, authority epoch and controller instance. Raw account IDs, ARNs, tokens,
credentials, request/response contents and raw request IDs are excluded.

An offline test can inject a trusted fake adapter; its report explicitly says
`evidence_source: injected_test_adapter`. A live operator run says
`operator_aws_mcp_bridge`. Neither mode uploads to Braintrust automatically.

This demonstrates application-level control of a real read-only service call.
`GetCallerIdentity` does not require IAM permission, so this does **not** prove
IAM denial, credential containment against a hostile same-user process, a
write-operation boundary, a deployed AWS worker runtime, or cancellation of an
already dispatched call. AWS worker deployment validation remains separate.
The zero-price metadata model and one-call limit are local demo accounting;
they do not alter the private project budget ledger or establish AWS billing.

Relevant offline coverage lives in `tests/test_aws_identity.py`: successful and
replayed requests, operation conflicts, cross-run/wrong tickets, Stop and
fencing, identity/metadata mismatch, unknown outcomes without retry, private
file bounds and a real SDK subprocess with a fake AWS adapter.

AWS documents both that [GetCallerIdentity requires no IAM permission](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
and that [AWS STS is offered at no additional charge](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html).
This narrow read-only check does not authorize a paid build or provision a
deployment. The operator's hosting and other service costs remain separate.
