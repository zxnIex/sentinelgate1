#!/usr/bin/env sh
set -eu

PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
[ -d .venv ] || "$PYTHON_BIN" -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/sentinelgate init
.venv/bin/sentinelgate doctor

printf '%s\n' "Installation verified. Start with:" \
  "  . .venv/bin/activate" \
  "  sentinelgate serve --reload" \
  "Or start PostgreSQL + gateway: docker compose up --build"
