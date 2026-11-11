"""``convergence validate``: is this policy well-formed, and is anything in it dangerous?

Schema errors are found when the policy is parsed (:mod:`convergence.policy.load`). This
module adds the checks that need the host (do the paths exist, does libseccomp know these
syscalls) and warns about grants that are valid but risky. Warnings never change what a
policy means; they are there so a person reads them before running a tool.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path

from convergence.kernel import seccomp as sc
from convergence.policy.baseline import denied_names
from convergence.policy.load import PolicyError, load_policy
from convergence.policy.model import Policy
from convergence.policy.paths import PathKind, ResolvedPath, Variables, resolve_all

SCHEMA = "convergence.validation/1"


class Severity(StrEnum):
    ERROR = "error"  # the policy cannot be used
    WARNING = "warning"  # valid, but grants something risky; read it before running
    NOTE = "note"  # valid; worth knowing


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    location: str
    message: str


@dataclass(slots=True)
class ValidationReport:
    schema: str
    source: str
    valid: bool
    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARNING]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# Credentials commonly kept in a home directory. A grant on any of these, or on a directory
# that contains one, is reported.
CREDENTIAL_PATHS = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".netrc",
    ".git-credentials",
    ".config/gh",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".docker",
    ".npmrc",
    ".pypirc",
    ".config/convergence",
)

SYSTEM_DIRECTORIES = ("/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var", "/opt")

HOST_SERVICE_SOCKETS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
)

SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY)", re.I)

# Without these an allow-list program cannot even start or exit.
ESSENTIAL_SYSCALLS = ("execve", "exit_group", "rt_sigreturn", "brk", "mmap")


def _is_within(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def _path_findings(paths: list[ResolvedPath], variables: Variables) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[tuple[str, str], str] = {}
    for item in paths:
        loc = item.location
        key = (item.bucket, item.rule.path)
        if key in seen:
            findings.append(Finding(Severity.WARNING, loc, f"duplicate of {seen[key]}"))
        seen.setdefault(key, loc)

        if item.kind is PathKind.MISSING:
            if item.rule.optional:
                findings.append(
                    Finding(
                        Severity.NOTE, loc, f"{item.rule.path}: {item.error}; skipped (optional)"
                    )
                )
            else:
                hint = ""
                if item.bucket == "write" and item.error == "does not exist":
                    hint = (
                        ". Landlock can only grant rights on paths that exist; to let the tool "
                        "create it, grant write on its parent directory"
                    )
                findings.append(
                    Finding(Severity.ERROR, loc, f"{item.rule.path}: {item.error}{hint}")
                )
            continue
        if item.kind is PathKind.INACCESSIBLE:
            findings.append(Finding(Severity.ERROR, loc, f"{item.rule.path}: {item.error}"))
            continue
        if item.kind is PathKind.PROC_SELF:
            findings.append(
                Finding(
                    Severity.NOTE,
                    loc,
                    f"{item.rule.path} is resolved inside the sandboxed process when it starts. "
                    "It covers that process only, not processes it starts later.",
                )
            )
            continue
        if item.kind is PathKind.SCRATCH:
            continue

        real = item.real or ""
        if real != item.expanded and item.expanded is not None:
            findings.append(
                Finding(
                    Severity.NOTE, loc, f"{item.expanded} is a symlink; the rule applies to {real}"
                )
            )
        if real == "/":
            findings.append(
                Finding(Severity.WARNING, loc, f"grants {item.bucket} on the entire filesystem")
            )
        if item.bucket == "write" and any(_is_within(real, d) for d in SYSTEM_DIRECTORIES):
            findings.append(
                Finding(Severity.WARNING, loc, f"grants write inside the system directory {real}")
            )
        if item.bucket == "execute" and item.kind is PathKind.FILE and not os.access(real, os.X_OK):
            findings.append(Finding(Severity.WARNING, loc, f"{real} is not executable"))
        if item.kind in (PathKind.SOCKET, PathKind.FIFO):
            findings.append(
                Finding(
                    Severity.NOTE,
                    loc,
                    f"{real} is a {item.kind.value}; filesystem rights do not control "
                    "connecting to sockets (see network.unix_sockets)",
                )
            )
        if _is_within(real, "/proc"):
            findings.append(
                Finding(
                    Severity.WARNING,
                    loc,
                    "grants access to /proc, which shows other processes' command lines and "
                    "system information (use /proc/self for the tool's own entries)",
                )
            )
        if _is_within(real, "/sys"):
            findings.append(Finding(Severity.WARNING, loc, "grants access to /sys"))
        if real == "/dev":
            findings.append(
                Finding(
                    Severity.WARNING, loc, "grants every device in /dev; list the devices needed"
                )
            )

        if variables.home:
            home = str(Path(variables.home).resolve())
            if _is_within(home, real):
                findings.append(
                    Finding(
                        Severity.WARNING,
                        loc,
                        f"includes your home directory {home}, with any credentials kept there",
                    )
                )
            else:
                for cred in CREDENTIAL_PATHS:
                    target = f"{home}/{cred}"
                    overlaps = _is_within(target, real) or _is_within(real, target)
                    if overlaps and os.path.lexists(target):
                        findings.append(
                            Finding(
                                Severity.WARNING,
                                loc,
                                f"grants {item.bucket} on credentials in {target}",
                            )
                        )
    return findings


def _network_findings(policy: Policy) -> list[Finding]:
    net = policy.network
    findings: list[Finding] = []
    for name in ("tcp_connect", "tcp_bind", "udp_send", "udp_bind"):
        value = getattr(net, name)
        if value == "any":
            what = (
                "connect or send to any port on any host"
                if name.endswith(("connect", "send"))
                else ("bind any local port")
            )
            findings.append(Finding(Severity.WARNING, f"network.{name}", f"the tool may {what}"))
        elif value:
            findings.append(
                Finding(
                    Severity.NOTE,
                    f"network.{name}",
                    "port rules apply to every host: Landlock filters by port, not by host or IP "
                    "address (host allowlisting is out of scope for v1)",
                )
            )
    if net.unix_sockets == "allow":
        reachable = [s for s in HOST_SERVICE_SOCKETS if os.path.exists(s)]
        extra = f"; present here: {', '.join(reachable)}" if reachable else ""
        findings.append(
            Finding(
                Severity.WARNING,
                "network.unix_sockets",
                "unix sockets are not restricted: the tool can reach host services such as a "
                "container runtime (root-equivalent) or the session bus" + extra,
            )
        )
    return findings


def _syscall_findings(policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    sys_policy = policy.syscalls
    try:
        library = sc.library()
    except sc.SeccompUnavailable as exc:
        return [Finding(Severity.NOTE, "syscalls", f"syscall names not checked: {exc}")]
    builtin = denied_names()
    for field_name in ("deny", "allow"):
        for index, name in enumerate(getattr(sys_policy, field_name)):
            loc = f"syscalls.{field_name}.{index}"
            found = library.lookup(name)
            if found.kind is sc.SyscallKind.UNKNOWN:
                version = ".".join(map(str, library.info().version))
                findings.append(
                    Finding(
                        Severity.ERROR,
                        loc,
                        f"libseccomp {version} does not know the syscall {name!r} (a typo, or "
                        "newer than this libseccomp)",
                    )
                )
            elif found.kind is sc.SyscallKind.OTHER_ARCH:
                findings.append(
                    Finding(
                        Severity.NOTE,
                        loc,
                        f"{name} does not exist on this architecture; no effect here",
                    )
                )
            if field_name == "allow" and name in builtin:
                findings.append(
                    Finding(
                        Severity.NOTE, loc, f"{name} is always denied by the built-in deny list"
                    )
                )
    if sys_policy.mode == "allow-list":
        missing = [n for n in ESSENTIAL_SYSCALLS if n not in sys_policy.allow]
        if missing:
            findings.append(
                Finding(
                    Severity.WARNING,
                    "syscalls.allow",
                    f"missing {', '.join(missing)}: most programs cannot start or exit "
                    "without them",
                )
            )
    return findings


def _environment_findings(policy: Policy) -> list[Finding]:
    env = policy.environment
    findings: list[Finding] = []
    for index, name in enumerate(env.pass_):
        if SECRET_NAME.search(name):
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"environment.pass.{index}",
                    f"passes {name}, which looks like a secret",
                )
            )
    for name in env.set:
        if SECRET_NAME.search(name):
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"environment.set.{name}",
                    f"sets {name}, which looks like a secret",
                )
            )
    if "PATH" not in env.pass_ and "PATH" not in env.set:
        findings.append(
            Finding(
                Severity.NOTE,
                "environment",
                "PATH is neither passed nor set; programs that search PATH use the C "
                "library's default",
            )
        )
    return findings


def _resource_findings(policy: Policy) -> list[Finding]:
    res = policy.resources
    findings: list[Finding] = []
    if res.max_processes is not None:
        findings.append(
            Finding(
                Severity.NOTE,
                "resources.max_processes",
                "the kernel counts RLIMIT_NPROC per user, not per sandbox; the limit is set "
                "relative to your process count when the sandbox starts",
            )
        )
    if res.address_space_mb is not None:
        findings.append(
            Finding(
                Severity.NOTE,
                "resources.address_space_mb",
                "RLIMIT_AS counts reserved virtual memory; runtimes such as V8 and Go may "
                "fail under it",
            )
        )
    return findings


def validate_policy(
    policy: Policy, source: str, variables: Variables | None = None
) -> ValidationReport:
    variables = variables or Variables.from_environment()
    paths = resolve_all(policy, variables)
    findings = (
        _path_findings(paths, variables)
        + _network_findings(policy)
        + _syscall_findings(policy)
        + _environment_findings(policy)
        + _resource_findings(policy)
    )
    valid = not any(f.severity is Severity.ERROR for f in findings)
    return ValidationReport(SCHEMA, source, valid, findings)


def validate_file(path: str | Path, variables: Variables | None = None) -> ValidationReport:
    """Parse and validate a policy file. Schema errors become findings, not exceptions."""
    try:
        policy = load_policy(path)
    except PolicyError as exc:
        findings = [Finding(Severity.ERROR, i.location, i.message) for i in exc.issues]
        return ValidationReport(SCHEMA, str(path), False, findings)
    return validate_policy(policy, str(path), variables)


def render_text(report: ValidationReport) -> str:
    lines: list[str] = []
    errors, warnings = len(report.errors), len(report.warnings)
    verdict = "valid" if report.valid else "INVALID"
    lines.append(f"{report.source}: {verdict} ({errors} error(s), {warnings} warning(s))")
    order = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.NOTE: 2}
    for finding in sorted(report.findings, key=lambda f: order[f.severity]):
        where = f"{finding.location}: " if finding.location else ""
        lines.append(f"  {finding.severity.value:<8} {where}{finding.message}")
    return "\n".join(lines) + "\n"
