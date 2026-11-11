#!/usr/bin/env bash
# Run Convergence on a real Linux kernel.
#
# On macOS this drives a Lima VM (Ubuntu 24.04, the stock GA kernel). On Linux the same
# subcommands run directly on the host, so contributors on Linux need no VM.
#
# Enforcement tests must never run under Docker Desktop: its VM kernel and default seccomp
# profile can hide or block the primitives being tested (see docs/adr/0001).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM="${CONVERGENCE_VM:-convergence}"
TEMPLATE="${CONVERGENCE_VM_TEMPLATE:-template:ubuntu-24.04}"

usage() {
    cat <<EOF
usage: scripts/vm.sh <command> [args...]

  create      create and start the Lima VM "$VM" (macOS only)
  start       start the VM
  stop        stop the VM
  provision   install the pinned toolchain inside Linux (scripts/provision.sh)
  facts       print kernel facts relevant to sandboxing
  lock        refresh uv.lock inside Linux
  sync        install the locked environment inside Linux
  test [...]  run pytest inside Linux (extra args go to pytest)
  check       lint, format check, type check, and tests inside Linux
  shell [...] open a shell in the repo inside Linux, or run a command there

Environment: CONVERGENCE_VM (default: convergence),
             CONVERGENCE_VM_TEMPLATE (default: template:ubuntu-24.04)
EOF
}

on_linux() {
    [[ "$(uname -s)" == "Linux" ]]
}

require_macos() {
    if on_linux; then
        echo "error: '$1' manages the Lima VM and is only needed on macOS" >&2
        exit 2
    fi
}

# Run a command in the repository root on Linux, with the project's environment.
in_linux() {
    if on_linux; then
        (cd "$ROOT" && "$ROOT/scripts/guest-env.sh" "$@")
    else
        limactl shell --workdir "$ROOT" "$VM" -- "$ROOT/scripts/guest-env.sh" "$@"
    fi
}

cmd="${1:-}"
[[ $# -gt 0 ]] && shift

case "$cmd" in
    create)
        require_macos create
        # The repo is mounted read-write at the same path, so paths match on both sides.
        limactl create --name="$VM" --tty=false \
            --cpus=4 --memory=3 --disk=20 \
            --vm-type=vz --mount-type=virtiofs \
            --mount-only "$ROOT:w" \
            "$TEMPLATE"
        limactl start "$VM" --tty=false
        ;;
    start)
        require_macos start
        limactl start "$VM" --tty=false
        ;;
    stop)
        require_macos stop
        limactl stop "$VM"
        ;;
    provision)
        in_linux bash scripts/provision.sh
        ;;
    facts)
        in_linux bash scripts/kernel-facts.sh
        ;;
    lock)
        in_linux uv lock
        ;;
    sync)
        in_linux uv sync --locked
        ;;
    test)
        in_linux uv run --locked pytest "$@"
        ;;
    check)
        in_linux bash scripts/check.sh
        ;;
    shell)
        if [[ $# -eq 0 ]]; then
            if on_linux; then
                (cd "$ROOT" && exec "$ROOT/scripts/guest-env.sh" bash -l)
            else
                limactl shell --workdir "$ROOT" "$VM" -- "$ROOT/scripts/guest-env.sh" bash -l
            fi
        else
            in_linux "$@"
        fi
        ;;
    "" | -h | --help | help)
        usage
        ;;
    *)
        echo "error: unknown command '$cmd'" >&2
        usage >&2
        exit 2
        ;;
esac
