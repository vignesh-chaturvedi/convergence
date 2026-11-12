"""The seccomp programs for a run (ADR 0006).

libseccomp refuses a rule that compares one argument twice (``EINVAL``) and two rules with
different actions for one syscall (``EACCES``). So a run gets up to two filters:

- the **baseline filter** allows by default and lists only denials: the built-in deny list,
  the policy's ``deny``, and argument patterns. Each argument pattern is a set of rules that
  together cover exactly the denied values;
- in **allow-list mode**, a second filter denies by default and allows the policy's list.
  The kernel applies the most restrictive answer of all filters, so the baseline's argument
  checks hold in both modes.

The kernel reads some arguments as 32-bit integers, but seccomp sees all 64 bits. Every such
argument is compared through a 32-bit mask, or with a 64-bit comparison that fails safe: a
value with high bits set is denied, never allowed.
"""

from __future__ import annotations

import errno
from dataclasses import dataclass, field

from convergence.kernel import seccomp as sc
from convergence.kernel.seccomp import ArgCmp, Compare
from convergence.policy.baseline import DENIED_SYSCALLS
from convergence.policy.model import Policy

LOW32 = 0xFFFFFFFF

# include/uapi/linux/sched.h
CLONE_NAMESPACE_FLAGS: dict[str, int] = {
    "CLONE_NEWTIME": 0x00000080,
    "CLONE_NEWNS": 0x00020000,
    "CLONE_NEWCGROUP": 0x02000000,
    "CLONE_NEWUTS": 0x04000000,
    "CLONE_NEWIPC": 0x08000000,
    "CLONE_NEWUSER": 0x10000000,
    "CLONE_NEWPID": 0x20000000,
    "CLONE_NEWNET": 0x40000000,
}

# include/uapi/asm-generic/ioctls.h (the same values on x86_64 and arm64)
DENIED_IOCTLS: dict[str, int] = {"TIOCSTI": 0x5412, "TIOCLINUX": 0x541C}

# include/uapi/linux/seccomp.h
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3

# include/uapi/linux/personality.h. Bit 31 is never a personality flag; it is set in the
# query value 0xffffffff, so "flag set and bit 31 clear" never matches a query.
PERSONALITY_QUERY_BIT = 0x80000000
DENIED_PERSONALITY_FLAGS: dict[str, int] = {
    "ADDR_NO_RANDOMIZE": 0x0040000,
    "MMAP_PAGE_ZERO": 0x0100000,
    "ADDR_COMPAT_LAYOUT": 0x0200000,
    "READ_IMPLIES_EXEC": 0x0400000,
}

AF_UNIX, AF_INET, AF_INET6 = 1, 2, 10
HIGHEST_KNOWN_FAMILY = AF_INET6  # every family above this is denied
SOCK_STREAM, SOCK_DGRAM = 1, 2
SOCK_TYPE_MASK = 0xF
IPPROTO_TCP, IPPROTO_UDP = 6, 17

# Syscalls an allow-list filter always permits: without them the launch cannot finish, and
# the tool could not even exit.
ALWAYS_ALLOWED = ("execve", "exit", "exit_group")


class FilterError(Exception):
    """The policy names a syscall libseccomp does not know, or libseccomp failed."""


@dataclass(frozen=True, slots=True)
class SocketGrants:
    """What ``socket()`` may create, derived from the network policy and the kernel."""

    families: frozenset[int]
    inet_types: frozenset[int]

    @classmethod
    def from_policy(cls, policy: Policy, landlock_abi: int) -> SocketGrants:
        net = policy.network
        families: set[int] = set()
        # Unix sockets are only allowed to be created where Landlock can keep them inside
        # the sandbox (RESOLVE_UNIX and abstract-socket scoping, ABI 9), or when allowed.
        if net.unix_sockets == "allow" or landlock_abi >= 9:
            families.add(AF_UNIX)
        types: set[int] = set()
        if net.tcp_connect or net.tcp_bind:
            types.add(SOCK_STREAM)
        if net.udp_send or net.udp_bind:
            types.add(SOCK_DGRAM)
        if types:
            families |= {AF_INET, AF_INET6}
        return cls(frozenset(families), frozenset(types))


@dataclass(slots=True)
class Programs:
    """Compiled classic-BPF programs, installed in this order."""

    baseline: bytes
    allow_list: bytes | None
    skipped: list[str] = field(default_factory=list)  # names with no effect on this arch

    @property
    def instructions(self) -> dict[str, int | None]:
        return {
            "baseline": len(self.baseline) // sc.BPF_INSTRUCTION_SIZE,
            "allow_list": (
                len(self.allow_list) // sc.BPF_INSTRUCTION_SIZE if self.allow_list else None
            ),
        }


def _cmp(arg: int, op: Compare, a: int, b: int = 0) -> ArgCmp:
    return ArgCmp(arg, op, a, b)


def _low32_eq(arg: int, value: int) -> ArgCmp:
    return _cmp(arg, Compare.MASKED_EQ, LOW32, value)


class _Builder:
    def __init__(self, library: sc.Library, default_action: int) -> None:
        self.library = library
        self.filter = library.new_filter(default_action)
        self.skipped: list[str] = []

    def rule(self, action: int, name: str, *conditions: ArgCmp, known: bool = False) -> bool:
        """Add a rule. Returns False for a syscall that does not exist on this architecture.

        A name libseccomp does not know is an error when it comes from the policy. For the
        built-in list (``known=True``) it is skipped: the installed libseccomp predates it.
        """
        found = self.library.lookup(name)
        if found.kind is sc.SyscallKind.UNKNOWN and not known:
            raise FilterError(f"libseccomp does not know the syscall {name!r}")
        if found.kind is not sc.SyscallKind.NATIVE:
            self.skipped.append(name)
            return False
        try:
            self.filter.add_rule(action, name, *conditions)
        except OSError as exc:
            raise FilterError(f"could not add a seccomp rule for {name}: {exc}") from exc
        return True

    def compile(self) -> bytes:
        try:
            return self.filter.export_bpf()
        finally:
            self.filter.release()


def _deny_socket_complement(builder: _Builder, grants: SocketGrants) -> None:
    """Deny every ``socket()`` call that ``grants`` does not cover."""
    deny = sc.act_errno(errno.EPERM)
    # Families: anything above the highest known family (this also catches high bits),
    # then each value at or below it that is not granted.
    builder.rule(deny, "socket", _cmp(0, Compare.GT, HIGHEST_KNOWN_FAMILY))
    for family in range(HIGHEST_KNOWN_FAMILY + 1):
        if family not in grants.families:
            builder.rule(deny, "socket", _cmp(0, Compare.EQ, family))
    for family in sorted(grants.families & {AF_INET, AF_INET6}):
        same_family = _cmp(0, Compare.EQ, family)
        # Types, as the kernel reads them: the low four bits; the rest are flags.
        for sock_type in range(SOCK_TYPE_MASK + 1):
            if sock_type not in grants.inet_types:
                builder.rule(
                    deny,
                    "socket",
                    same_family,
                    _cmp(1, Compare.MASKED_EQ, SOCK_TYPE_MASK, sock_type),
                )
        # Protocols: only the default (0) or the one the type implies. Anything else would
        # be SCTP, MPTCP, UDP-Lite, or ICMP, which Landlock's TCP and UDP rules do not cover.
        for sock_type, protocol in ((SOCK_STREAM, IPPROTO_TCP), (SOCK_DGRAM, IPPROTO_UDP)):
            if sock_type not in grants.inet_types:
                continue
            of_type = _cmp(1, Compare.MASKED_EQ, SOCK_TYPE_MASK, sock_type)
            builder.rule(deny, "socket", same_family, of_type, _cmp(2, Compare.GT, protocol))
            for other in range(1, protocol):
                builder.rule(deny, "socket", same_family, of_type, _cmp(2, Compare.EQ, other))


def _baseline(library: sc.Library, policy: Policy, grants: SocketGrants) -> tuple[bytes, list[str]]:
    builder = _Builder(library, sc.ACT_ALLOW)
    denied_whole: set[str] = set()
    for item in DENIED_SYSCALLS:
        if builder.rule(sc.act_errno(item.errno), item.name, known=True):
            denied_whole.add(item.name)
    for name in policy.syscalls.deny:
        if name not in denied_whole and builder.rule(sc.act_errno(errno.EPERM), name):
            denied_whole.add(name)

    eperm = sc.act_errno(errno.EPERM)
    if "clone" not in denied_whole:
        for flag in CLONE_NAMESPACE_FLAGS.values():
            builder.rule(eperm, "clone", _cmp(0, Compare.MASKED_EQ, flag, flag))
    if "seccomp" not in denied_whole:
        builder.rule(
            eperm,
            "seccomp",
            _cmp(0, Compare.EQ, SECCOMP_SET_MODE_FILTER),
            _cmp(
                1,
                Compare.MASKED_EQ,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            ),
        )
    if "ioctl" not in denied_whole:
        for request in DENIED_IOCTLS.values():
            builder.rule(eperm, "ioctl", _low32_eq(1, request))
    if "personality" not in denied_whole:
        for flag in DENIED_PERSONALITY_FLAGS.values():
            builder.rule(
                eperm,
                "personality",
                _cmp(0, Compare.MASKED_EQ, PERSONALITY_QUERY_BIT | flag, flag),
            )
    if "socket" not in denied_whole:
        _deny_socket_complement(builder, grants)
    return builder.compile(), builder.skipped


def _allow_list(library: sc.Library, policy: Policy) -> tuple[bytes, list[str]]:
    builder = _Builder(library, sc.act_errno(errno.EPERM))
    names = list(dict.fromkeys(policy.syscalls.allow))
    for name in names:
        builder.rule(sc.ACT_ALLOW, name)
    for name in ALWAYS_ALLOWED:
        if name not in names:
            builder.rule(sc.ACT_ALLOW, name, known=True)
    if "clone3" not in names:
        # The C library only falls back to clone() when clone3() fails with ENOSYS.
        builder.rule(sc.act_errno(errno.ENOSYS), "clone3", known=True)
    return builder.compile(), builder.skipped


def build_programs(policy: Policy, landlock_abi: int, library: sc.Library) -> Programs:
    grants = SocketGrants.from_policy(policy, landlock_abi)
    baseline, skipped = _baseline(library, policy, grants)
    allow_list: bytes | None = None
    if policy.syscalls.mode == "allow-list":
        allow_list, more = _allow_list(library, policy)
        skipped += more
    return Programs(baseline=baseline, allow_list=allow_list, skipped=sorted(set(skipped)))


# The tracer (ADR 0007) needs these from the built-in deny list; it gets nothing else.
TRACER_NEEDS = frozenset({"ptrace", "process_vm_readv"})


def build_tracer_program(library: sc.Library) -> bytes:
    """The filter strace runs under: the built-in deny list minus what tracing needs, and no
    sockets at all."""
    builder = _Builder(library, sc.ACT_ALLOW)
    for item in DENIED_SYSCALLS:
        if item.name not in TRACER_NEEDS:
            builder.rule(sc.act_errno(item.errno), item.name, known=True)
    builder.rule(sc.act_errno(errno.EPERM), "socket", known=True)
    return builder.compile()
