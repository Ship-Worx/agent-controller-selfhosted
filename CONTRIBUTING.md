# Contributing

Use the public repository and keep changes scoped to a concrete behavior.
Explain what changes, why it is needed and the relevant validation. Security
findings follow [SECURITY.md](SECURITY.md).

## Local development

Use Python 3.12 and uv on a POSIX host:

```bash
./scripts/install.sh
./scripts/test.sh -q
.venv/bin/python -m demo.run
```

Use synthetic fixtures for AWS/provider tests. Do not require contributors to
supply credentials or incur charges to run the default suite. Add focused
regressions for changed authorization, accounting, identity or recovery
behavior; keep tests independent of private deployment artifacts.

Dependency changes require a reviewed update of `requirements.in` and the
hash-locked `requirements.lock`, with verified official-PyPI wheel provenance.
Ordinary setup uses the existing lock.

## Public source hygiene

Never commit keys, account-specific inventories, real resource identifiers,
customer content, runtime databases, traces or billing exports. Use obvious
fictional fixture identities. Keep generated state under the ignored
`.runtime/` directory and review your staged diff before opening a PR.

The release exporter uses `public-release-files.json` as an exact file allowlist
and refuses existing destinations. A clean export has no inherited `.git`
directory or operational history. New public files need an explicit allowlist
entry and an independent source/credential review before publication.

Contributions are submitted under this project's [MIT license](LICENSE).
Preserve attribution and identify any separately licensed material you add.
