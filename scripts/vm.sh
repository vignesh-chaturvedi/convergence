#!/usr/bin/env bash
# Run Convergence on a real Linux kernel.
#
# On macOS this drives a Lima VM (Ubuntu 24.04, the stock GA kernel). On Linux the same
# subcommands run directly on the host, so contributors on Linux need no VM. Setting
# CONVERGENCE_USE_VM=1 on Linux uses a Lima VM anyway (QEMU/KVM); CI does this to test the
# stock Ubuntu 24.04 kernel, which no GitHub-hosted runner provides.
#
# Enforcement tests must never run under Docker Desktop: its VM kernel and default seccomp
# profile can hide or block the primitives being tested (see docs/adr/0001).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM="${CONVERGENCE_VM:-convergence}"
TEMPLATE="${CONVERGENCE_VM_TEMPLATE:-template:ubuntu-24.04}"
CPUS="${CONVERGENCE_VM_CPUS:-4}"
MEMORY="${CONVERGENCE_VM_MEMORY:-3}"

if [[ "$(uname -s)" == "Darwin" ]]; then
    VM_TYPE="${CONVERGENCE_VM_TYPE:-vz}"
    MOUNT_TYPE="${CONVERGENCE_VM_MOUNT_TYPE:-virtiofs}"
else
    VM_TYPE="${CONVERGENCE_VM_TYPE:-qemu}"
    MOUNT_TYPE="${CONVERGENCE_VM_MOUNT_TYPE:-9p}"
fi

usage() {
    cat <<EOF
usage: scripts/vm.sh <command> [args...]

  create      create and start the Lima VM "$VM"
  start       start the VM
  stop        stop the VM
  provision   install the pinned toolchain inside Linux (scripts/provision.sh)
  facts       print kernel facts relevant to sandboxing
  lock        refresh uv.lock inside Linux
  sync        install the locked environment inside Linux
  test [...]  run pytest inside Linux (extra args go to pytest)
  check       lint, format check, type check, and tests inside Linux
  shell [...] open a shell in the repo inside Linux, or run a command there

Environment:
  CONVERGENCE_USE_VM=1          use the Lima VM even on Linux
  CONVERGENCE_VM                VM name (default: convergence)
  CONVERGENCE_VM_TEMPLATE       Lima template (default: template:ubuntu-24.04)
  CONVERGENCE_VM_CPUS, _MEMORY  VM size (default: 4 CPUs, 3 GiB)
  CONVERGENCE_VM_TYPE           vz on macOS, qemu on Linux
  CONVERGENCE_VM_MOUNT_TYPE     virtiofs on macOS, 9p on Linux
EOF
}

# True when commands run directly on this machine instead of inside a VM.
run_locally() {
    [[ "$(uname -s)" == "Linux" && "${CONVERGENCE_USE_VM:-0}" != "1" ]]
}

require_vm_mode() {
    if run_locally; then
        echo "error: '$1' manages the Lima VM; on Linux set CONVERGENCE_USE_VM=1 to use one" >&2
        exit 2
    fi
}

# Run a command in the repository root on Linux, with the project's environment.
in_linux() {
    if run_locally; then
        (cd "$ROOT" && "$ROOT/scripts/guest-env.sh" "$@")
    else
        limactl shell --workdir "$ROOT" "$VM" -- "$ROOT/scripts/guest-env.sh" "$@"
    fi
}

cmd="${1:-}"
[[ $# -gt 0 ]] && shift

case "$cmd" in
    create)
        require_vm_mode create
        # The repo is mounted read-write at the same path, so paths match on both sides.
        # containerd is not needed, so Lima does not download it.
        limactl create --name="$VM" --tty=false \
            --cpus="$CPUS" --memory="$MEMORY" --disk=20 \
            --vm-type="$VM_TYPE" --mount-type="$MOUNT_TYPE" \
            --containerd=none \
            --mount-only "$ROOT:w" \
            "$TEMPLATE"
        limactl start "$VM" --tty=false
        ;;
    start)
        require_vm_mode start
        limactl start "$VM" --tty=false
        ;;
    stop)
        require_vm_mode stop
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
            if run_locally; then
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
