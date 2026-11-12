"""Everything a run needs, built in the supervisor before it forks (ADR 0006).

``prepare`` does all the work that can fail or allocate: it checks the policy against the
kernel, opens every granted path, builds the Landlock ruleset, compiles the seccomp
programs, resolves the executable, and builds the environment. The child only applies what
it is given.
"""

from __future__ import annotations

import os
import re
import resource
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from convergence.kernel import landlock as ll
from convergence.kernel import seccomp as sc
from convergence.kernel.landlock import AccessFs, AccessNet, Scope
from convergence.policy.enforce import Assessment, Capabilities, RuleAssessment, assess
from convergence.policy.model import Policy
from convergence.policy.paths import PathKind, ResolvedPath, Variables, resolve_all
from convergence.policy.rights import Bucket, handled_rights, names, rights_for
from convergence.runtime.filters import FilterError, Programs, build_programs

MIB = 1024 * 1024

# Exit codes of `convergence run` when the tool itself did not decide the status.
EXIT_TIMEOUT = 124
EXIT_NOT_STARTED = 125  # Convergence could not start the tool (policy, kernel, setup)
EXIT_CANNOT_EXECUTE = 126  # the tool exists but could not be executed (often: not granted)
EXIT_NOT_FOUND = 127

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


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


def _allow_path(plan: LandlockPlan, item: ResolvedPath, target: str) -> None:
    try:
        fd = os.open(target, os.O_PATH | os.O_CLOEXEC)
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
        )
    except BaseException:
        if landlock is not None:
            landlock.ruleset.close()
        if scratch is not None:
            _remove_tree(scratch)
        raise
