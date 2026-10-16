# Offline synthetic controller bootstrap

This directory contains working local bundle rendering, installed-host startup
checks, service units and a separate explicit fresh-state initializer. Nothing
has been installed, provisioned, mounted, formatted or started. No prepared AMI,
Nginx binary/package bundle, certificate/private key or live credential is
supplied. The example inputs deliberately fail validation while required values
are null. These artifacts do not authorize deployment or charges.

## Render a new review bundle locally

Populate a private copy of [inputs.example.json](inputs.example.json) from
observed deployment outputs and the reviewed prepared image. The proposed
controller and proxy IDs, 42010/42011, must match actual distinct service users
`agent-controller` and `agent-controller-proxy`; they are not observed accounts.
Record exact Python and Nginx binary SHA256/version values. Python is pinned to
3.12.14 or 3.12.15, with all 43 versions from the existing requirements lock.
This code never installs or downloads them.

Supply the same trusted installation object described in
[SELF_HOSTING.md](../SELF_HOSTING.md) in the nested `installation` field. The
top-level `account` and `region` must match it exactly. The separate protected
installation file is also required by the CLI; no publisher account is a
default.

Provide the **public CA certificate chain only**, at most four certificates and
16 KiB, in a separate local file. No private key or secret belongs in the render
inputs. Rendering validates certificates with stdlib SSL and emits canonical
PEM compatible with the worker's actual `CONTROLLER_CA_PEM` parser. It does not
claim that a server certificate/private key exists or matches the hostname.

```bash
.venv/bin/python -B -m deploy.bootstrap.bundle \
  --installation /absolute/private/installation.json \
  --config /tmp/reviewed-controller-inputs.json \
  --public-ca /tmp/reviewed-controller-public-ca.pem \
  --source-root "$PWD" \
  --output /tmp/agent-controller-bootstrap-review
```

The output directory must not exist. The renderer writes only a new private
directory, with mode 0600 files, and never overwrites earlier evidence. It emits
`bootstrap.json`, exact `state-policy.json`, rendered Nginx configuration,
controller/proxy units, `controller-ca.pem`, public
`worker-runtime-environment.json`, source/dependency hashes, and a hash manifest
of all generated files. `CONTROLLER_URL` is the exact private HTTPS hostname on
8443; the worker environment contains no token or key. Review hashes against
the source used for the candidate image. Hash consistency is not provenance or
proof that code executed successfully.

## Prepared-image contract — not executed here

An authorized image preparation step must supply the exact source files named
by `SOURCE_FILES` in [bundle.py](bundle.py) under `/opt/agent-controller` and a
root-owned, non-writable runtime at `/opt/agent-controller/.venv`. Use a copied
Python executable (`venv --copies` or equivalent reviewed packaging), because
startup rejects symlinked/hardlinked executable inputs. The runtime and its
standard library/package bytes require independent image/package provenance;
metadata version checks do not authenticate every installed byte.

Install the reviewed configuration bundle in `/etc/agent-controller`, root-owned
with directories 0755 and files 0644 or 0444, and the two exact units in
`/etc/systemd/system`. No service has an `[Install]` section and `Restart=no`:
the AMI must leave both services disabled. This package has no cloud-init,
secret retrieval, automatic network/package setup or production credential
creation. It never edits existing network rules or other projects.

The image must already supply `/usr/sbin/nginx`, `/usr/sbin/ip`, `findmnt` and
`lsblk`, the recorded Python/runtime dependencies, systemd, and the two distinct
nonroot users with no supplementary groups. Missing or mismatched items block
startup. Exact package bytes, their verified manifests and AMI generation remain
unfinished inputs; no placeholder successful image receipt is included.

The controller unit preserves device-node visibility for `lsblk` with
`PrivateDevices=no`, drops all capabilities, and uses `DevicePolicy=closed`.
Its dedicated `/srv/controller-volume` mount remains writable inside the service
namespace so the existing guard can require the real EBS mount to be `rw`.
The proxy has a private device namespace and AF_NETLINK only for read-only
assigned-address inspection. Its lack of network-administration capabilities
remains required. Actual systemd/device-cgroup/Nginx validation is still pending
on the prepared host; static files and fixture tests are not that evidence.

## Explicit first initialization — never a restart fallback

An operator must separately provision, format and mount the reviewed new EBS
volume, observe its volume ID and filesystem UUID, and precreate the exact mount
root and `/srv/controller-volume/controller` directory with controller ownership
and mode 0700. This package performs **none** of those actions. The directory
must contain no entries, including no old lock, database or recovery remnants.

Only after review, the future one-time command, run as `agent-controller`, is:

```bash
/opt/agent-controller/.venv/bin/python -I -B \
  /opt/agent-controller/deploy/bootstrap/initialize.py \
  --policy /etc/agent-controller/state-policy.json \
  --initialize-empty-synthetic-state
```

This command was not run on real state. It verifies the exact mount/owner first,
creates the lock with `O_EXCL`, and has Broker acquire and verify that lease
before creating schema. A competing entry or changed mount is rejected. It
creates one **zero-budget synthetic seed job and immediately stops it** because
the existing state guard rejects an empty job registry. No protected effect,
provider request, project-budget ledger or real-spending history is created.
The initializer validates the resulting databases under the same held lease
and reports counts and volume identifiers, never generated authority tokens.

A failure or crash leaves partial files intact. Every later initialization
attempt refuses a nonempty directory; no retry cleans, resets or restores it.
Resolve such a partial initialization through a separate reviewed recovery
procedure. The guard's whole-volume rollback limitation still applies. A local
successful initialization report is not independent recovery/freshness evidence.

## Trusted activation and startup

Outside the mutable volume, supply a root-owned protected
`/etc/agent-controller/activation.json` with exactly these fields:

```json
{
  "schema_version": 1,
  "mode": "synthetic",
  "bootstrap_sha256": "SHA256 of the exact generated bootstrap.json",
  "source_manifest_sha256": "SHA256 of the exact generated source-manifest.json",
  "not_before": 0,
  "expires_at": 0,
  "recovery_reference": "independent-operator-review-reference"
}
```

This deliberately invalid example is not an approval. Actual UTC epoch seconds
must describe a current window no longer than two hours. An operator must review
the referenced independent recovery evidence, costs and activation authority;
the file only records that decision and binds it to the inputs. It does not
authenticate or establish external evidence. No renderer manufactures this
activation file, and state initialization does not grant activation.

Trusted credential delivery must precreate
`/run/agent-controller-secrets/admin-token` (controller-owned 0600, protected
0700 directory) with 24–512 URL-safe ASCII characters and no trailing newline.
This is the actual controller administrator secret; it is read only at startup,
not put in arguments, rendered outputs or logs. The proxy's separate 0700
directory `/run/agent-controller-tls` contains proxy-owned 0600 `server.crt` and
`server.key`. Deliver only that server key, never the private CA signing key.
No credential-fetch implementation or secret value is included here.

The installed launch wrapper verifies protected ancestry, exact bundle/source
and unit hashes, service identity, runtime pins and current activation before
starting either service. Ambient AWS, provider, proxy and live-model settings
are discarded. The controller requires the existing exact mount and starts
through `--state-policy`: the existing Broker-held-lease guard still precedes
schema/recovery changes and the HTTP listener. It binds only `127.0.0.1:8787`.
The proxy waits for controller `ExecStartPost` to validate the current PID and
exact loopback readiness record; a failed or stale readiness check blocks it.

The proxy verifies assigned private IPv4, the pinned Nginx binary/version and
`nginx -t`. Stdlib `SSLContext`/`MemoryBIO` validate the supplied key, certificate
chain, current validity and DNS hostname without creating a socket. Only then
does Nginx bind the private worker endpoint. The existing method/path allowlist,
TLS verification, credential separation and no-retry controls remain intact.
Operator access to admission/Stop still needs its separately reviewed private
path; no admin route is added to worker ingress.

Future explicit activation, after all those inputs and host acceptance checks,
is `systemctl start agent-controller-proxy.service`; dependency ordering starts
the controller first. No `enable` command is supplied. The controller arms an
absolute activation-expiry alarm; systemd also caps lifetime and stops the
dependent proxy. Expiry/forced termination can leave in-flight uncertainty or a
SQLite recovery requirement, so operator Stop/quiesce must precede ordinary
cleanup. These timers do not terminate EC2, reconcile spend or implement an AWS
cost hard stop. The pilot shutdown owner and infrastructure deadline remain
separate requirements.

## Current offline checks and limits

```bash
.venv/bin/python -B -m pytest deploy/tests/test_bootstrap.py -q -p no:cacheprovider
```

The 35 focused cases passed without sockets using public trust-store
certificates, injected mount observations and temporary synthetic state. They
cover input injection, exact identities/paths, worker CA compatibility, private
non-overwriting output, held-lease initialization, stopped zero-budget seed,
crash/partial refusal, activation expiry, credential-read ordering and readiness.
They do not prove actual EBS mounting, Nginx/systemd acceptance, a real
server-key/certificate handshake, image provenance, deployed isolation or
external recovery evidence. No local live state, archived evidence, network
security setting, installation or AWS resource was changed.
