#!/usr/bin/env bash
# The full local check, identical to what CI runs. Run it on Linux (scripts/vm.sh check).
set -euo pipefail

uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked pytest
