#!/usr/bin/env bash
# Print kernel facts that matter for sandboxing. Informational only: this is not the
# capability probe (that is `convergence doctor`, Phase 1), and it enforces nothing.
set -uo pipefail

echo "kernel:        $(uname -srm)"
if [[ -r /etc/os-release ]]; then
    echo "os:            $(. /etc/os-release && echo "$PRETTY_NAME")"
fi
echo "lsm:           $(cat /sys/kernel/security/lsm 2>/dev/null || echo unavailable)"

# landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) returns the ABI version.
# The syscall number (444) is the same on x86_64 and aarch64.
python3 - <<'EOF'
import ctypes
import errno
import os

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
abi = libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
if abi < 0:
    err = ctypes.get_errno()
    print(f"landlock abi:  unavailable ({errno.errorcode.get(err, err)}: {os.strerror(err)})")
else:
    print(f"landlock abi:  {abi}")
EOF

grep -E '^(Seccomp|Seccomp_filters|NoNewPrivs):' /proc/self/status | sed 's/:\t/: /'
echo "strace:        $(strace -V 2>/dev/null | head -1 || echo missing)"
libseccomp="$(ldconfig -p 2>/dev/null | grep -m1 'libseccomp.so.2 ' | awk '{print $NF}')"
echo "libseccomp:    ${libseccomp:-missing}"
for key in kernel.yama.ptrace_scope kernel.unprivileged_userns_clone \
    kernel.apparmor_restrict_unprivileged_userns; do
    printf '%-46s %s\n' "$key" "$(sysctl -n "$key" 2>/dev/null || echo n/a)"
done
echo "uid:           $(id -u)"
