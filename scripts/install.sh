#!/usr/bin/env bash
# Install only official PyPI wheels, with TLS and pinned artifact hashes checked.
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
command -v uv >/dev/null || {
  echo "uv is required; install a trusted uv release before running setup." >&2
  exit 1
}

# Do not let an index override, local artifact source, or disabled verification
# change approved package provenance. uv does not consume pip-specific options;
# reject their source/trust overrides too so the setup contract is unambiguous.
# Preserve inherited proxies and CA trust.
for option_name in \
  UV_INDEX UV_DEFAULT_INDEX UV_INDEX_URL UV_EXTRA_INDEX_URL UV_FIND_LINKS \
  UV_INSECURE_HOST UV_NO_VERIFY_HASHES \
  PIP_INDEX_URL PIP_EXTRA_INDEX_URL PIP_FIND_LINKS PIP_TRUSTED_HOST PIP_NO_INDEX; do
  if [[ -n "${!option_name:-}" ]]; then
    echo "Unset $option_name for this verified official-PyPI-only installation." >&2
    exit 1
  fi
done

mkdir -p .runtime/uv-cache
uv_options=(--cache-dir "$project_dir/.runtime/uv-cache" --no-config)
if [[ ! -x .venv/bin/python ]]; then
  uv "${uv_options[@]}" venv --python 3.12 --no-python-downloads .venv
fi
.venv/bin/python - <<'PY'
import pathlib
import sys

expected = pathlib.Path('.venv').resolve()
if sys.version_info[:2] != (3, 12):
    raise SystemExit('This lock requires Python 3.12; recreate .venv with that interpreter.')
if pathlib.Path(sys.prefix).resolve() != expected or sys.prefix == sys.base_prefix:
    raise SystemExit('Refusing installation outside this project virtual environment.')
PY

uv "${uv_options[@]}" pip sync requirements.lock \
  --python "$project_dir/.venv/bin/python" \
  --default-index https://pypi.org/simple \
  --only-binary :all: --require-hashes --strict --link-mode copy
uv "${uv_options[@]}" pip check --python "$project_dir/.venv/bin/python"
.venv/bin/python - <<'PY'
from importlib.metadata import version

expected = {'openai-agents': '0.23.1', 'openai': '3.29.0', 'pytest': '8.4.2'}
for package, pin in expected.items():
    actual = version(package)
    if actual != pin:
        raise SystemExit(f'{package}: expected exactly {pin}, found {actual}')
print('Verified exact SDK pins: openai-agents==0.23.1, openai==3.29.0; pytest==8.4.2')
PY
