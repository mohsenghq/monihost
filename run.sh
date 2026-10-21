#!/usr/bin/env bash
# netwatch — single process, no build step.
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] || uv venv .venv >/dev/null
uv pip install -q --python .venv/bin/python -r requirements.txt
export NETWATCH_INTERVAL="${NETWATCH_INTERVAL:-60}"
exec .venv/bin/uvicorn app:app --host "${NETWATCH_HOST:-127.0.0.1}" --port "${NETWATCH_PORT:-8099}"
