# Source provenance

Ship-Worx maintains this source release under the [MIT license](../LICENSE).
The portable controller core (`controller/engine.py`, `controller/durable.py`
and `controller/validators.py`) and associated durable regression tests
originated in an earlier Ship-Worx controller implementation. The broker,
workers, workflow integration and self-hosting configuration are maintained as
part of this project.

The MIT file is the organization's grant for this public release. The earlier
internal source had no pre-existing license file; this document does not claim
an inherited third-party permissive grant. Existing attribution is retained.
No separately licensed third-party implementation is vendored in this release.

OpenAI Agents SDK, the OpenAI Python client, pytest and transitive dependencies
are installed separately from official PyPI using the checked-in hash lock.
Those distributions keep their own licenses and notices. This project's license
does not replace dependency licenses.

The public repository starts from a clean, allowlisted source snapshot. Earlier
private Git objects, deployment evidence, account inventories, credentials and
accounting state are not part of it. `PUBLIC_RELEASE_MANIFEST.json` records
hashes of the exported source files; it contains no private source path or
private-history identifier.

Test results describe the source and environment actually exercised. Local
synthetic behavior does not establish AWS runtime acceptance, account security,
network isolation or real provider spending bounds.
