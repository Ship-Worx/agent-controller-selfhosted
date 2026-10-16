#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
if [[ ! -x .venv/bin/python ]]; then
  echo "Run ./scripts/install.sh first." >&2
  exit 1
fi
# The milestone uses an injected fake model and local tools only.
export OPENAI_AGENTS_DISABLE_TRACING=1
exec .venv/bin/python -m pytest "$@"
