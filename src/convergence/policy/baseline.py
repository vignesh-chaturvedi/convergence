"""Protections every sandbox gets, whatever its policy says.

The built-in syscall deny list removes kernel interfaces that agent tools do not need and
that are common routes to escape or to interfere with other processes. It is defined here as
data so that ``explain``, the documentation, and the runtime (Phase 4) all use one list.
The list is not a substitute for an allow list: ``syscalls.mode: allow-list`` is stricter.
"""

from __future__ import annotations

import errno
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DeniedSyscall:
    name: str
    reason: str
    errno: int = errno.EPERM


def _group(reason: str, *names: str, err: int = errno.EPERM) -> tuple[DeniedSyscall, ...]:
    return tuple(DeniedSyscall(name, reason, err) for name in names)


DENIED_SYSCALLS: tuple[DeniedSyscall, ...] = (
    *_group("trace or inspect other processes", "ptrace", "kcmp"),
    *_group(
        "read or change another process's memory or file descriptors",
        "process_vm_readv",
        "process_vm_writev",
        "process_madvise",
        "pidfd_getfd",
        "migrate_pages",
        "move_pages",
    ),
    *_group(
        "mount filesystems or change the root",
        "mount",
        "umount2",
        "pivot_root",
        "chroot",
        "move_mount",
        "open_tree",
        "fsopen",
        "fsconfig",
        "fsmount",
        "fspick",
        "mount_setattr",
    ),
    *_group("create or enter namespaces", "unshare", "setns"),
    *_group(
        "takes its flags in a structure seccomp cannot inspect; it fails with ENOSYS so the "
        "C library falls back to clone, whose namespace flags are checked",
        "clone3",
        err=errno.ENOSYS,
    ),
    *_group(
        "io_uring operations are not seen by seccomp, so they would bypass this filter",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    ),
    *_group(
        "large kernel attack surface not needed by agent tools",
        "bpf",
        "perf_event_open",
        "userfaultfd",
        "fanotify_init",
    ),
    *_group(
        "kernel keyrings are shared with the user's session", "keyctl", "add_key", "request_key"
    ),
    *_group(
        "open files by handle, bypassing path-based checks",
        "open_by_handle_at",
        "name_to_handle_at",
    ),
    *_group(
        "privileged system administration",
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "delete_module",
        "reboot",
        "swapon",
        "swapoff",
        "acct",
        "quotactl",
        "quotactl_fd",
        "syslog",
        "vhangup",
        "settimeofday",
        "clock_settime",
        "sethostname",
        "setdomainname",
    ),
    *_group(
        "obsolete or x86-specific interfaces",
        "lookup_dcookie",
        "nfsservctl",
        "uselib",
        "ustat",
        "sysfs",
        "_sysctl",
        "iopl",
        "ioperm",
        "modify_ldt",
        "vm86",
        "vm86old",
    ),
)


@dataclass(frozen=True, slots=True)
class ArgumentRule:
    syscall: str
    rule: str


# Syscalls that stay allowed but are denied for specific integer arguments.
ARGUMENT_RULES: tuple[ArgumentRule, ...] = (
    ArgumentRule(
        "clone",
        "denied when the flags create a namespace (CLONE_NEWNS, NEWUSER, NEWPID, NEWNET, "
        "NEWIPC, NEWUTS, NEWCGROUP, NEWTIME)",
    ),
    ArgumentRule(
        "seccomp",
        "denied when installing a filter with SECCOMP_FILTER_FLAG_NEW_LISTENER, so the sandbox "
        "cannot become its own user-notification supervisor",
    ),
    ArgumentRule("ioctl", "TIOCSTI and TIOCLINUX are denied (terminal input injection)"),
    ArgumentRule(
        "personality",
        "denied when it sets ADDR_NO_RANDOMIZE, READ_IMPLIES_EXEC, MMAP_PAGE_ZERO, or "
        "ADDR_COMPAT_LAYOUT (no disabling of address space randomisation), or any value "
        "with bit 31 set; queries work",
    ),
    ArgumentRule(
        "prlimit64",
        "denied for any process but the caller (pid 0), so the tool cannot change the "
        "resource limits of other processes of the same user",
    ),
    ArgumentRule(
        "sendto",
        "denied with MSG_FASTOPEN unless tcp_connect is 'any': it would connect a TCP "
        "socket without Landlock's port check",
    ),
    ArgumentRule("sendmsg", "denied with MSG_FASTOPEN, as for sendto"),
    ArgumentRule("sendmmsg", "denied with MSG_FASTOPEN, as for sendto"),
    ArgumentRule(
        "listen",
        "denied unless the policy grants a TCP port to bind or unix sockets can be "
        "created: listening without bind would take a port Landlock never checks",
    ),
    ArgumentRule(
        "socket",
        "only the families, types, and protocols the network policy grants: unix (if allowed), "
        "and IPv4/IPv6 TCP or UDP (if any port is granted), with no other protocol",
    ),
)


def denied_names() -> frozenset[str]:
    return frozenset(d.name for d in DENIED_SYSCALLS)
