"""Everything a run needs, built in the supervisor before it forks (ADR 0006).

``prepare`` does all the work that can fail or allocate: it checks the policy against the
kernel, opens every granted path, builds the Landlock ruleset, compiles the seccomp
programs, resolves the executable, and builds the environment. The child only applies what
it is given.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import re
import resource
import shutil
import stat
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from convergence.kernel import landlock as ll
from convergence.kernel import seccomp as sc
from convergence.kernel._libc import syscall
from convergence.kernel.landlock import AccessFs, AccessNet, Scope
from convergence.policy.baseline import ARGUMENT_RULES, denied_names
from convergence.policy.enforce import Assessment, Capabilities, RuleAssessment, assess
from convergence.policy.model import Policy
from convergence.policy.paths import PathKind, ResolvedPath, Variables, resolve_all
from convergence.policy.rights import Bucket, handled_rights, names, rights_for
from convergence.runtime.denials import Context
from convergence.runtime.filters import FilterError, Programs, build_programs

MIB = 1024 * 1024

# Exit codes of `convergence run` when the tool itself did not decide the status.
EXIT_TIMEOUT = 124
EXIT_NOT_STARTED = 125  # Convergence could not start the tool (policy, kernel, setup)
EXIT_CANNOT_EXECUTE = 126  # the tool exists but could not be executed (often: not granted)
EXIT_NOT_FOUND = 127

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# openat2(2): the same number on x86_64 and arm64; flags from include/uapi/linux/openat2.h.
SYS_OPENAT2 = 437
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
MAX_SYMLINKS = 40  # the kernel's own limit for one path walk


class RunError(Exception):
    """The tool was not started. ``exit_code`` is what ``convergence run`` exits with."""

    def __init__(
        self, message: str, exit_code: int = EXIT_NOT_STARTED, details: list[str] | None = None
    ):
        super().__init__(message)
        self.exit_code = exit_code
        self.details = details or []


@dataclass(slots=True)
class LandlockPlan:
    abi: int
    ruleset: ll.Ruleset
    handled_fs: AccessFs
    handled_net: AccessNet
    scope: Scope
    path_rules: int = 0
    port_rules: int = 0
    # /proc/self paths only the sandboxed process can resolve: (bucket, path, optional).
    proc_self: list[tuple[Bucket, str, bool]] = field(default_factory=list)
    # Real paths of the directories granted for writing: all, and the trusted ones (see
    # open_grant).
    writable: list[str] = field(default_factory=list)
    writable_trusted: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "abi": self.abi,
            "handled_fs": names(self.handled_fs),
            "handled_net": [f.name for f in AccessNet if f & self.handled_net and f.name],
            "scoped": [f.name for f in Scope if f & self.scope and f.name],
            "path_rules": self.path_rules + len(self.proc_self),
            "port_rules": self.port_rules,
        }


@dataclass(slots=True)
class Plan:
    argv: list[str]
    executable: str
    cwd: str
    env: dict[str, str]
    assessment: Assessment
    degraded: list[RuleAssessment]
    landlock: LandlockPlan | None
    programs: Programs | None
    rlimits: list[tuple[int, int]]  # (resource, value); RLIMIT_NPROC is added at fork time
    max_processes: int | None
    scratch: Path | None
    landlock_abi: int | None
    attribution: Context | None = None

    def close(self) -> None:
        if self.landlock is not None:
            self.landlock.ruleset.close()

    def remove_scratch(self) -> None:
        if self.scratch is not None and self.scratch.exists():
            _remove_tree(self.scratch)


def _remove_tree(root: Path) -> None:
    """Remove a directory even if the tool made parts of it unreadable."""

    def fix(func: object, path: str, _exc: object) -> None:
        try:
            if not os.path.islink(path):  # chmod would follow a link out of the tree
                os.chmod(path, stat.S_IRWXU)
            parent = os.path.dirname(path)
            os.chmod(parent, stat.S_IRWXU)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.unlink(path)
        except OSError:
            pass

    shutil.rmtree(root, onexc=fix)


def expand_variables(text: str, values: dict[str, str]) -> str:
    """Replace ``${HOME}``, ``${CWD}``, ``${SCRATCH}``; leave anything else as written."""
    return _VARIABLE.sub(lambda m: values.get(m.group(1), m.group(0)), text)


def resolve_executable(command: str, search_path: str | None, cwd: str) -> str:
    """The file ``execve`` will run, found the way a shell would find it."""
    if not command:
        raise RunError("the command is empty", EXIT_NOT_FOUND)
    if "/" in command:
        path = os.path.normpath(os.path.join(cwd, command))
        if not os.path.exists(path):
            raise RunError(f"{command}: no such file", EXIT_NOT_FOUND)
        return path
    for directory in (search_path if search_path is not None else os.defpath).split(":"):
        candidate = os.path.join(os.path.join(cwd, directory) if directory else cwd, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.normpath(candidate)
    where = "the policy's PATH" if search_path is not None else f"the default PATH ({os.defpath})"
    raise RunError(f"{command}: command not found in {where}", EXIT_NOT_FOUND)


def _uses_scratch(policy: Policy, argv: list[str]) -> bool:
    texts = [rule.path for b in ("read", "write", "execute") for rule in policy.filesystem.rules(b)]
    texts += list(policy.environment.set.values()) + argv
    return any("${SCRATCH}" in text for text in texts)


def build_environment(policy: Policy, values: dict[str, str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for name in policy.environment.pass_:
        if name in os.environ:
            env[name] = os.environ[name]
    for name, value in policy.environment.set.items():
        env[name] = expand_variables(value, values)
    return env


def _handled_net(policy: Policy, abi: int) -> AccessNet:
    available = ll.features_for_abi(abi).net
    net = policy.network
    handled = AccessNet(0)
    for value, right in (
        (net.tcp_connect, AccessNet.CONNECT_TCP),
        (net.tcp_bind, AccessNet.BIND_TCP),
        (net.udp_send, AccessNet.CONNECT_SEND_UDP),
        (net.udp_bind, AccessNet.BIND_UDP),
    ):
        if right & available and value != "any":
            handled |= right
    return handled


def build_landlock(
    policy: Policy, paths: list[ResolvedPath], abi: int, scratch: Path | None
) -> LandlockPlan:
    features = ll.features_for_abi(abi)
    handled_fs = handled_rights(abi, unix_sockets=policy.network.unix_sockets)
    handled_net = _handled_net(policy, abi)
    scope = features.scope & Scope.SIGNAL
    if policy.network.unix_sockets == "deny":
        scope |= features.scope & Scope.ABSTRACT_UNIX_SOCKET
    ruleset = ll.Ruleset(handled_fs, handled_net, scope)
    plan = LandlockPlan(abi, ruleset, handled_fs, handled_net, scope)
    plan.writable, plan.writable_trusted = writable_directories(
        [
            item.expanded
            for item in paths
            if item.bucket == "write" and item.kind is PathKind.DIRECTORY and item.expanded
        ]
    )
    try:
        for item in paths:
            if item.kind is PathKind.PROC_SELF:
                plan.proc_self.append((item.bucket, item.expanded or "", item.rule.optional))
                continue
            if item.kind is PathKind.SCRATCH:
                target: str | None = str(scratch) if scratch is not None else None
            elif item.kind in (PathKind.MISSING, PathKind.INACCESSIBLE):
                continue  # only reached with --allow-degraded, or an optional path
            else:
                target = item.expanded
            if target is None:
                continue
            _allow_path(plan, item, target)
        net = policy.network
        for value, right in (
            (net.tcp_connect, AccessNet.CONNECT_TCP),
            (net.tcp_bind, AccessNet.BIND_TCP),
            (net.udp_send, AccessNet.CONNECT_SEND_UDP),
            (net.udp_bind, AccessNet.BIND_UDP),
        ):
            if right & handled_net and isinstance(value, tuple):
                for port in value:
                    ruleset.allow_port(port, right)
                    plan.port_rules += 1
    except BaseException:
        ruleset.close()
        raise
    return plan


class GrantRedirected(Exception):
    """A granted path leaves the directories the tool may write to, through a symbolic link."""

    def __init__(self, root: str) -> None:
        super().__init__(root)
        self.root = root


def _open_beneath(root: str, relative: str) -> int:
    """Open ``relative`` under ``root`` (O_PATH), with no symbolic link on the way.

    The path given here has already been resolved, so a link can only appear if something
    is changing the directory at this moment. The kernel then refuses the open.
    """
    resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
    how = struct.pack("=QQQ", os.O_PATH | os.O_CLOEXEC, 0, resolve)
    buffer = ctypes.create_string_buffer(how, len(how))
    root_fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return syscall(
            SYS_OPENAT2,
            ctypes.c_int(root_fd),
            ctypes.c_char_p(os.fsencode(relative)),
            buffer,
            ctypes.c_size_t(len(how)),
        )
    except OSError as exc:
        if exc.errno in (errno.EXDEV, errno.ELOOP):
            raise GrantRedirected(root) from exc
        raise
    finally:
        os.close(root_fd)


def _writable_root(path: str, roots: list[str]) -> str | None:
    """The outermost of ``roots`` that ``path`` is, or is inside."""
    inside = [r for r in roots if path == r or path.startswith(r.rstrip("/") + "/")]
    return min(inside, key=len) if inside else None


def resolve_grant(path: str, writable: list[str]) -> tuple[str, str | None]:
    """Resolve the symbolic links of ``path`` one step at a time.

    Returns the real path, and the first directory of ``writable`` inside which a part of
    the path was looked up (None if there was none). What is found there is whatever the
    tool last put there.
    """
    current = "/"
    pending = [part for part in path.split("/") if part and part != "."]
    links = 0
    through: str | None = None
    while pending:
        if through is None and writable:
            through = _writable_root(current, writable)
        part = pending.pop(0)
        if part == "..":  # only from a link's target: policy paths cannot contain it
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, part)
        try:
            target = os.readlink(candidate)
        except OSError as exc:
            if exc.errno != errno.EINVAL:  # EINVAL: it exists and is not a link
                raise
            current = candidate
            continue
        links += 1
        if links > MAX_SYMLINKS:
            raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), path)
        if target.startswith("/"):
            current = "/"
        pending = [p for p in target.split("/") if p and p != "."] + pending
    return current, through


def writable_directories(paths: list[str]) -> tuple[list[str], list[str]]:
    """``(every, trusted)`` real paths of the directories a policy grants for writing.

    ``paths`` are those grants as written. A grant that itself lies inside another
    writable directory is not trusted: the tool may have pointed it somewhere else.
    """
    every: set[str] = set()
    for path in paths:
        with contextlib.suppress(OSError):
            every.add(os.path.realpath(path, strict=True))
    trusted: set[str] = set()
    for path in paths:
        with contextlib.suppress(OSError):
            real, through = resolve_grant(path, sorted(every))
            if through is None:
                trusted.add(real)
    return sorted(every), sorted(trusted)


def open_grant(path: str, writable: list[str], trusted: list[str]) -> int:
    """Open a granted path for a Landlock rule (O_PATH), following symbolic links.

    Landlock attaches the rule to whatever the path points at when the run starts. Inside
    a directory the policy lets the tool write to, the tool decides what that is: an
    earlier run can replace a granted entry with a link to anything, and the next run
    would grant it. So a path that passes through such a directory (``writable``) must end
    inside one (``trusted``), where the tool can write already and gains nothing.
    :class:`GrantRedirected` is raised otherwise.
    """
    real, through = resolve_grant(path, writable) if writable else (path, None)
    if through is None:
        # Nothing the tool can write to lies on the way: open it as the kernel sees it.
        return os.open(path, os.O_PATH | os.O_CLOEXEC)
    root = _writable_root(real, trusted)
    if root is None:
        raise GrantRedirected(through)
    return _open_beneath(root, os.path.relpath(real, root))


def _allow_path(plan: LandlockPlan, item: ResolvedPath, target: str) -> None:
    try:
        fd = open_grant(target, plan.writable, plan.writable_trusted)
    except GrantRedirected as exc:
        raise RunError(
            f"{item.location} ({target}): this path leaves the directories granted for "
            f"writing through a symbolic link inside {exc.root}. The tool may write there, "
            "so it can change that link and point this grant at anything. Grant the link's "
            "real target instead."
        ) from exc
    except OSError as exc:
        if item.rule.optional and isinstance(exc, FileNotFoundError):
            return
        raise RunError(f"{item.location} ({target}): {exc.strerror}") from exc
    try:
        # The rights depend on what was actually opened, not on what was checked earlier.
        is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
        rights = rights_for(item.bucket, is_directory=is_dir, abi=plan.abi) & plan.handled_fs
        if rights:
            plan.ruleset.allow_path_fd(fd, rights)
            plan.path_rules += 1
    finally:
        os.close(fd)


def build_rlimits(policy: Policy) -> list[tuple[int, int]]:
    """Every rlimit except RLIMIT_NPROC, capped at the current hard limits."""
    res = policy.resources
    wanted: list[tuple[int, int | None]] = [
        (resource.RLIMIT_CORE, 0),  # a crash in the sandbox never writes a core file
        (resource.RLIMIT_CPU, res.cpu_seconds),
        (resource.RLIMIT_DATA, res.memory_mb * MIB if res.memory_mb else None),
        (resource.RLIMIT_AS, res.address_space_mb * MIB if res.address_space_mb else None),
        (resource.RLIMIT_FSIZE, res.max_file_size_mb * MIB if res.max_file_size_mb else None),
        (resource.RLIMIT_NOFILE, res.max_open_files),
    ]
    limits: list[tuple[int, int]] = []
    for which, value in wanted:
        if value is None:
            continue
        _, hard = resource.getrlimit(which)
        if hard != resource.RLIM_INFINITY:
            value = min(value, hard)
        limits.append((which, value))
    return limits


def count_user_tasks() -> int:
    """Tasks (threads) of this real user: what the kernel compares with RLIMIT_NPROC."""
    uid = os.getuid()
    total = 0
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            text = Path(entry.path, "status").read_text()
        except OSError:
            continue
        real_uid = threads = None
        for line in text.splitlines():
            if line.startswith("Uid:"):
                real_uid = int(line.split()[1])
            elif line.startswith("Threads:"):
                threads = int(line.split()[1])
        if real_uid == uid and threads is not None:
            total += threads
    return total


def attribution_context(policy: Policy, paths: list[ResolvedPath], scratch: Path | None) -> Context:
    grants: dict[str, list[str]] = {"read": [], "write": [], "execute": []}
    for item in paths:
        if item.kind is PathKind.SCRATCH and scratch is not None:
            grants[item.bucket].append(str(scratch))
        elif item.real is not None:
            grants[item.bucket].append(item.real)
        elif item.kind is PathKind.PROC_SELF and item.expanded:
            grants[item.bucket].append(item.expanded)
    res = policy.resources
    limits = {
        name
        for name in (
            "cpu_seconds",
            "memory_mb",
            "address_space_mb",
            "max_processes",
            "max_file_size_mb",
            "max_open_files",
        )
        if getattr(res, name) is not None
    }
    sys_policy = policy.syscalls
    return Context(
        denied_syscalls=denied_names() | frozenset(sys_policy.deny),
        argument_rules=frozenset(rule.syscall for rule in ARGUMENT_RULES),
        allow_list=frozenset(sys_policy.allow) if sys_policy.mode == "allow-list" else None,
        grants={bucket: tuple(values) for bucket, values in grants.items()},
        limits=frozenset(limits),
    )


def prepare(
    policy: Policy,
    argv: list[str],
    *,
    allow_degraded: bool,
    capabilities: Capabilities | None = None,
) -> Plan:
    if not argv:
        raise RunError("no command given (use: convergence run --policy P -- COMMAND ...)", 2)
    cwd = os.getcwd()
    caps = capabilities or Capabilities.from_kernel()
    paths = resolve_all(policy, Variables.from_environment(cwd))
    assessment = assess(policy, paths, caps)
    degraded = assessment.blocking
    if degraded and not allow_degraded:
        raise RunError(
            f"this kernel cannot fully enforce {len(degraded)} rule(s) of the policy; "
            "refusing to run (pass --allow-degraded to run anyway)",
            EXIT_NOT_STARTED,
            [
                f"{r.status.value}: {r.id} {r.rule}" + (f" ({r.detail})" if r.detail else "")
                for r in degraded
            ],
        )

    scratch = (
        Path(tempfile.mkdtemp(prefix="convergence-scratch-"))
        if _uses_scratch(policy, argv)
        else None
    )
    landlock: LandlockPlan | None = None
    try:
        values = {"CWD": cwd}
        if os.environ.get("HOME"):
            values["HOME"] = os.environ["HOME"]
        if scratch is not None:
            values["SCRATCH"] = str(scratch)
        argv = [expand_variables(arg, values) for arg in argv]
        env = build_environment(policy, values)
        executable = resolve_executable(argv[0], env.get("PATH"), cwd)

        abi = caps.landlock_abi
        if abi:
            try:
                landlock = build_landlock(policy, paths, abi, scratch)
            except OSError as exc:
                raise RunError(f"could not build the Landlock ruleset: {exc}") from exc
        programs: Programs | None = None
        if caps.has("seccomp_filter"):
            try:
                programs = build_programs(policy, abi or 0, sc.library())
            except (FilterError, sc.SeccompUnavailable) as exc:
                raise RunError(f"could not build the seccomp filter: {exc}") from exc
        return Plan(
            argv=argv,
            executable=executable,
            cwd=cwd,
            env=env,
            assessment=assessment,
            degraded=degraded,
            landlock=landlock,
            programs=programs,
            rlimits=build_rlimits(policy),
            max_processes=policy.resources.max_processes,
            scratch=scratch,
            landlock_abi=abi,
            attribution=attribution_context(policy, paths, scratch),
        )
    except BaseException:
        if landlock is not None:
            landlock.ruleset.close()
        if scratch is not None:
            _remove_tree(scratch)
        raise
