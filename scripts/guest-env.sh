#!/usr/bin/env bash
# Run a command with the environment Convergence's checks expect on Linux.
#
# The virtualenv lives on the Linux side's own disk, not inside the repository, so a repo
# shared with macOS (for example over virtiofs) never gets a Linux .venv in it.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-$HOME/.venvs/convergence}"

exec "$@"
