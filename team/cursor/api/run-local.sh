#!/bin/sh
# Starts the local Cursor Usage API on http://127.0.0.1:8787 (logs to data/server.log).
# HOST and PORT override the address, e.g. PORT=9000 ./run-local.sh
cd "$(dirname "$0")" || exit 1
mkdir -p data
exec .venv/bin/python -m uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8787}" >> data/server.log 2>&1
