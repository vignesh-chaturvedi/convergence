"""``convergence explain --policy``: which rules of a policy can this kernel enforce?

Every rule gets one status:

- ``enforced``: the kernel enforces the rule as written;
- ``enforced-with-caveat``: enforced, with a documented difference (stricter than asked, or
  shown by the kernel's ABI but not yet proven by a live probe);
- ``partial``: part of the rule is not enforced;
- ``unenforceable``: the kernel cannot enforce the rule;
- ``skipped``: an optional path that does not exist;
- ``not-available``: a baseline protection this kernel lacks. Baseline protections are not
  policy rules; they are reported but do not block a run.

``run`` (Phase 4) refuses any policy with a ``partial`` or ``unenforceable`` rule unless it
is given ``--allow-degraded``, and then prints exactly those rules. Nothing is dropped
silently.

The assessment is a pure function of the policy, the resolved paths, and the kernel's
capabilities, so it can be checked for every ABI level without a kernel of each kind.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from convergence.policy.baseline import DENIED_SYSCALLS
from convergence.policy.model import Policy
from convergence.policy.paths import PathKind, ResolvedPath
from convergence.policy.rights import names, rights_for
from convergence.probe.report import DoctorReport, ProtectionStatus

SCHEMA = "convergence.enforceability/1"


class Status(StrEnum):
    ENFORCED = "enforced"
    CAVEAT = "enforced-with-caveat"
    PARTIAL = "partial"
    UNENFORCEABLE = "unenforceable"
    SKIPPED = "skipped"
    NOT_AVAILABLE = "not-available"


BLOCKING = (Status.PARTIAL, Status.UNENFORCEABLE)


class Proof(StrEnum):
    VERIFIED = "verified"  # a live probe on this machine proved it
    ABI_ONLY = "abi-only"  # the kernel's ABI includes it; no live probe exists yet
    ASSUMED = "assumed"  # --assume-abi: nothing was checked on a real kernel
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What the kernel can do, and how that is known."""

    source: str
    landlock_abi: int | None
    features: dict[str, Proof]

    def proof(self, feature: str) -> Proof:
        return self.features.get(feature, Proof.MISSING)

    def has(self, feature: str) -> bool:
        return self.proof(feature) is not Proof.MISSING

    @classmethod
    def from_doctor(cls, report: DoctorReport) -> Capabilities:
        mapping = {
            ProtectionStatus.VERIFIED: Proof.VERIFIED,
            ProtectionStatus.ABI_ONLY: Proof.ABI_ONLY,
        }
        features = {p.id: mapping.get(p.status, Proof.MISSING) for p in report.protections}
        return cls(
            "live probes on this machine (convergence doctor)", report.landlock.abi, features
        )

    @classmethod
    def assumed(cls, abi: int) -> Capabilities:
        """Capabilities of a hypothetical kernel at ``abi``. Nothing is verified."""
        from convergence.probe.report import PROTECTIONS

        features: dict[str, Proof] = {}
        for spec in PROTECTIONS:
            if spec.min_abi is None or abi >= spec.min_abi:
                features[spec.id] = Proof.ASSUMED
        return cls(f"assumed Landlock ABI {abi} (not checked on a real kernel)", abi, features)


@dataclass(slots=True)
class RuleAssessment:
    id: str
    rule: str
    mechanism: str
    status: Status
    detail: str = ""


@dataclass(slots=True)
class Assessment:
    schema: str
    source: str
    capabilities: str
    landlock_abi: int | None
    runtime_implemented: bool
    baseline: list[RuleAssessment] = field(default_factory=list)
    rules: list[RuleAssessment] = field(default_factory=list)

    @property
    def blocking(self) -> list[RuleAssessment]:
        return [r for r in self.rules if r.status in BLOCKING]

    @property
    def would_run(self) -> bool:
        return not self.blocking

    def to_json(self) -> str:
        data = asdict(self)
        data["would_run_without_allow_degraded"] = self.would_run
        data["blocking_rules"] = [r.id for r in self.blocking]
        return json.dumps(data, indent=2)


def _landlock(caps: Capabilities, feature: str, abi_needed: int) -> tuple[str, Status, str]:
    """Mechanism, status, and detail for something only Landlock can enforce."""
    proof = caps.proof(feature)
    mechanism = f"Landlock ABI {abi_needed}+"
    if proof is Proof.MISSING:
        have = f"ABI {caps.landlock_abi}" if caps.landlock_abi is not None else "no Landlock"
        return (
            mechanism,
            Status.UNENFORCEABLE,
            f"needs Landlock ABI {abi_needed}; this kernel has {have}",
        )
    if proof is Proof.ABI_ONLY:
        return (
            mechanism,
            Status.CAVEAT,
            "the kernel's ABI includes this, but no live probe has verified it on this machine",
        )
    return mechanism, Status.ENFORCED, ""


def _baseline(
    policy: Policy, caps: Capabilities
) -> tuple[list[RuleAssessment], list[RuleAssessment]]:
    """Protections every sandbox gets. Returns (blocking ones, informational ones)."""
    blocking: list[RuleAssessment] = []
    info: list[RuleAssessment] = []

    mech, status, detail = _landlock(caps, "fs_access", 1)
    blocking.append(
        RuleAssessment(
            "baseline.filesystem",
            "every path not granted is denied (read, write, execute, create, remove)",
            mech,
            status,
            detail,
        )
    )
    mech, status, detail = _landlock(caps, "fs_truncate", 3)
    blocking.append(
        RuleAssessment(
            "baseline.truncate",
            "files outside write grants cannot be truncated",
            mech,
            status,
            detail or "",
        )
    )
    if caps.has("fs_refer"):
        refer = RuleAssessment(
            "baseline.refer",
            "renames and links are limited to write grants",
            "Landlock ABI 2+",
            Status.ENFORCED,
        )
    elif caps.has("fs_access"):
        refer = RuleAssessment(
            "baseline.refer",
            "renames and links are limited to write grants",
            "Landlock ABI 1",
            Status.CAVEAT,
            "stricter than asked: before ABI 2 Landlock refuses every rename or link across "
            "directories (EXDEV)",
        )
    else:
        refer = RuleAssessment(
            "baseline.refer",
            "renames and links are limited to write grants",
            "Landlock",
            Status.UNENFORCEABLE,
            "no Landlock",
        )
    blocking.append(refer)

    seccomp = caps.has("seccomp_filter")
    blocking.append(
        RuleAssessment(
            "baseline.syscalls",
            f"built-in deny list ({len(DENIED_SYSCALLS)} syscalls, plus argument checks on clone, "
            "seccomp, ioctl, personality, socket)",
            "seccomp-bpf",
            Status.ENFORCED if seccomp else Status.UNENFORCEABLE,
            "" if seccomp else "seccomp filtering is not available",
        )
    )
    nnp = caps.has("no_new_privs")
    blocking.append(
        RuleAssessment(
            "baseline.no_new_privs",
            "setuid binaries and file capabilities cannot raise privileges",
            "prctl(PR_SET_NO_NEW_PRIVS)",
            Status.ENFORCED if nnp else Status.UNENFORCEABLE,
            "" if nnp else "no_new_privs is not available",
        )
    )
    blocking.append(
        RuleAssessment(
            "baseline.process_inspection",
            "processes outside the sandbox cannot be traced or have their memory read",
            "Landlock (any ABI) and seccomp (ptrace, process_vm_*)",
            Status.ENFORCED if caps.has("fs_access") and seccomp else Status.UNENFORCEABLE,
        )
    )
    blocking.append(
        RuleAssessment(
            "baseline.socket_families",
            "socket families other than unix and IPv4/IPv6 are denied",
            "seccomp-bpf (socket domain argument)",
            Status.ENFORCED if seccomp else Status.UNENFORCEABLE,
        )
    )
    blocking.append(
        RuleAssessment(
            "baseline.inherited_state",
            "no inherited file descriptors beyond stdin/stdout/stderr; no controlling terminal",
            "supervisor (close_range before exec, new session)",
            Status.ENFORCED,
        )
    )

    if caps.has("scope_signal"):
        mech, status, detail = _landlock(caps, "scope_signal", 6)
        info.append(
            RuleAssessment(
                "baseline.signals",
                "signals to processes outside the sandbox are denied",
                mech,
                status,
                detail,
            )
        )
    else:
        info.append(
            RuleAssessment(
                "baseline.signals",
                "signals to processes outside the sandbox are denied",
                "Landlock ABI 6+",
                Status.NOT_AVAILABLE,
                "this kernel cannot scope signals: the sandboxed tool can send signals to other "
                "processes run by the same user",
            )
        )
    # Landlock does not control these syscall families on any ABI (warning in
    # include/uapi/linux/landlock.h). They are listed on every kernel.
    info.append(
        RuleAssessment(
            "baseline.metadata_reads",
            "file metadata outside the grants cannot be read (stat, access, chdir, readlink)",
            "not controlled by Landlock",
            Status.NOT_AVAILABLE,
            "the tool can learn whether paths exist, and their type, size, owner, and timestamps; "
            "it cannot read their contents",
        )
    )
    info.append(
        RuleAssessment(
            "baseline.metadata_changes",
            "file metadata outside the grants cannot be changed (chmod, chown, setxattr, utime)",
            "not controlled by Landlock",
            Status.NOT_AVAILABLE,
            "the tool can change permissions, group ownership, extended attributes, and "
            "timestamps of files the user owns, wherever they are; it cannot read or change "
            "their contents. Convergence does not mitigate this yet",
        )
    )
    return blocking, info


def _path_rules(paths: list[ResolvedPath], caps: Capabilities) -> list[RuleAssessment]:
    rules: list[RuleAssessment] = []
    abi = caps.landlock_abi or 0
    have_landlock = caps.has("fs_access")
    for item in paths:
        label = f"{item.bucket} {item.rule.path}"
        if item.kind is PathKind.MISSING and item.rule.optional:
            rules.append(
                RuleAssessment(item.location, label, "-", Status.SKIPPED, f"{item.error}; optional")
            )
            continue
        if item.kind in (PathKind.MISSING, PathKind.INACCESSIBLE):
            rules.append(
                RuleAssessment(
                    item.location,
                    label,
                    "Landlock",
                    Status.UNENFORCEABLE,
                    f"{item.error}: Landlock can only grant rights on paths that exist",
                )
            )
            continue
        if not have_landlock:
            rules.append(
                RuleAssessment(
                    item.location, label, "Landlock", Status.UNENFORCEABLE, "no Landlock"
                )
            )
            continue

        # Under /proc/self only the directory itself is known to be one; deeper entries are
        # shown with file rights, and the runtime checks their real type in the child.
        is_dir = item.is_directory or (
            item.kind is PathKind.PROC_SELF
            and item.rule.path.rstrip("/") in ("/proc/self", "/proc/thread-self")
        )
        rights = rights_for(item.bucket, is_directory=is_dir, abi=abi)
        target = item.real or item.expanded or item.rule.path
        detail = f"{target}: {', '.join(names(rights))}"
        status = Status.ENFORCED
        notes: list[str] = []
        if item.kind is PathKind.PROC_SELF:
            status = Status.CAVEAT
            notes.append("resolved in the sandboxed process at launch; covers that process only")
        if item.kind is PathKind.SCRATCH:
            notes.append("a fresh directory created for each run and removed afterwards")
        if item.bucket != "write" and item.may_contain_devices and not caps.has("fs_ioctl_dev"):
            status = Status.PARTIAL
            notes.append(
                "ioctl on these devices cannot be denied (needs Landlock ABI 5), so the tool may "
                "do more than read them"
            )
        if notes:
            detail += ". " + "; ".join(notes)
        rules.append(RuleAssessment(item.location, label, f"Landlock ABI {abi}", status, detail))
    return rules


def _port_rule(
    rule_id: str,
    label: str,
    value: tuple[int, ...] | str,
    feature: str,
    abi_needed: int,
    caps: Capabilities,
    protocol_needed: bool,
) -> RuleAssessment:
    if value == "any":
        return RuleAssessment(rule_id, f"{label}: any port", "-", Status.ENFORCED, "not restricted")
    ports = ", ".join(map(str, value)) if value else "none"
    if not value and not protocol_needed:
        # The protocol is not granted at all, so seccomp denies its sockets on any kernel.
        seccomp = caps.has("seccomp_filter")
        return RuleAssessment(
            rule_id,
            f"{label}: none",
            "seccomp-bpf (socket type argument)",
            Status.ENFORCED if seccomp else Status.UNENFORCEABLE,
            "" if seccomp else "seccomp filtering is not available",
        )
    mech, status, detail = _landlock(caps, feature, abi_needed)
    if status is Status.UNENFORCEABLE:
        detail += "; this kernel can only allow or deny the protocol entirely"
    return RuleAssessment(rule_id, f"{label}: {ports}", mech, status, detail)


def _network_rules(policy: Policy, caps: Capabilities) -> list[RuleAssessment]:
    net = policy.network
    tcp_needed = bool(net.tcp_connect) or bool(net.tcp_bind)
    udp_needed = bool(net.udp_send) or bool(net.udp_bind)
    rules = [
        _port_rule(
            "network.tcp_connect", "TCP connect", net.tcp_connect, "net_tcp", 4, caps, tcp_needed
        ),
        _port_rule("network.tcp_bind", "TCP bind", net.tcp_bind, "net_tcp", 4, caps, tcp_needed),
        _port_rule("network.udp_send", "UDP send", net.udp_send, "net_udp", 10, caps, udp_needed),
        _port_rule("network.udp_bind", "UDP bind", net.udp_bind, "net_udp", 10, caps, udp_needed),
    ]
    if net.unix_sockets == "allow":
        rules.append(
            RuleAssessment(
                "network.unix_sockets",
                "unix sockets: allow",
                "-",
                Status.ENFORCED,
                "not restricted",
            )
        )
    elif caps.has("scope_abstract_unix") and caps.has("fs_resolve_unix"):
        scope = _landlock(caps, "scope_abstract_unix", 6)
        resolve = _landlock(caps, "fs_resolve_unix", 9)
        status = Status.CAVEAT if Status.CAVEAT in (scope[1], resolve[1]) else Status.ENFORCED
        rules.append(
            RuleAssessment(
                "network.unix_sockets",
                "unix sockets: deny connections outside the sandbox",
                "Landlock ABI 9+ (RESOLVE_UNIX and abstract-socket scope)",
                status,
                "; ".join(d for d in (scope[2], resolve[2]) if d),
            )
        )
    else:
        seccomp = caps.has("seccomp_filter")
        rules.append(
            RuleAssessment(
                "network.unix_sockets",
                "unix sockets: deny connections outside the sandbox",
                "seccomp-bpf (socket and socketpair arguments)",
                Status.CAVEAT if seccomp else Status.UNENFORCEABLE,
                "stricter than asked: this kernel cannot limit unix sockets to the sandbox "
                "(needs Landlock ABI 9), so creating unix sockets is denied altogether; "
                "socketpair() still works"
                if seccomp
                else "seccomp filtering is not available",
            )
        )
    return rules


def _syscall_rules(policy: Policy, caps: Capabilities) -> list[RuleAssessment]:
    seccomp = caps.has("seccomp_filter")
    status = Status.ENFORCED if seccomp else Status.UNENFORCEABLE
    detail = "" if seccomp else "seccomp filtering is not available"
    rules: list[RuleAssessment] = []
    sys_policy = policy.syscalls
    if sys_policy.mode == "allow-list":
        rules.append(
            RuleAssessment(
                "syscalls.allow",
                f"allow-list of {len(sys_policy.allow)} syscalls; everything else denied",
                "seccomp-bpf",
                status,
                detail,
            )
        )
    for index, name in enumerate(sys_policy.deny):
        rules.append(
            RuleAssessment(f"syscalls.deny.{index}", f"deny {name}", "seccomp-bpf", status, detail)
        )
    return rules


def _resource_rules(policy: Policy, caps: Capabilities) -> list[RuleAssessment]:
    res = policy.resources
    rlimits = caps.has("rlimits")
    rules = [
        RuleAssessment(
            "resources.wall_clock_seconds",
            f"wall clock: {res.wall_clock_seconds} s",
            "supervisor (SIGKILL to the process group and every descendant)",
            Status.ENFORCED,
        )
    ]
    limits = (
        ("cpu_seconds", "RLIMIT_CPU", "s"),
        ("memory_mb", "RLIMIT_DATA", "MiB"),
        ("address_space_mb", "RLIMIT_AS", "MiB"),
        ("max_processes", "RLIMIT_NPROC", "processes"),
        ("max_file_size_mb", "RLIMIT_FSIZE", "MiB"),
        ("max_open_files", "RLIMIT_NOFILE", "files"),
    )
    for name, limit, unit in limits:
        value = getattr(res, name)
        if value is None:
            rules.append(
                RuleAssessment(
                    f"resources.{name}", f"{name}: not limited", "-", Status.ENFORCED, "not limited"
                )
            )
            continue
        status = Status.ENFORCED if rlimits else Status.UNENFORCEABLE
        detail = "per process" if rlimits else "resource limits are not available"
        if name == "max_processes" and rlimits:
            status = Status.CAVEAT
            detail = (
                "the kernel counts RLIMIT_NPROC per user, not per sandbox; it is set to your "
                f"current process count plus {value} at launch"
            )
        rules.append(
            RuleAssessment(
                f"resources.{name}",
                f"{name}: {value} {unit}",
                f"setrlimit({limit})",
                status,
                detail,
            )
        )
    return rules


def assess(policy: Policy, paths: list[ResolvedPath], caps: Capabilities) -> Assessment:
    blocking_baseline, info_baseline = _baseline(policy, caps)
    env = policy.environment
    env_rule = RuleAssessment(
        "environment",
        f"environment: {len(env.pass_)} passed, {len(env.set)} set; nothing else inherited",
        "execve environment built by the supervisor",
        Status.ENFORCED,
    )
    rules = (
        blocking_baseline
        + _path_rules(paths, caps)
        + _network_rules(policy, caps)
        + _syscall_rules(policy, caps)
        + _resource_rules(policy, caps)
        + [env_rule]
    )
    return Assessment(
        schema=SCHEMA,
        source="",
        capabilities=caps.source,
        landlock_abi=caps.landlock_abi,
        runtime_implemented=False,
        baseline=info_baseline,
        rules=rules,
    )


def render_text(assessment: Assessment) -> str:
    abi = assessment.landlock_abi
    lines = [
        f"{assessment.source}",
        f"  capabilities: {assessment.capabilities}"
        + (f"; Landlock ABI {abi}" if abi is not None else "; no Landlock"),
        "  Pre-alpha: `convergence run` is not implemented yet. This shows how each rule would",
        "  be enforced on this kernel.",
        "",
    ]
    width = max((len(s.value) for s in Status), default=10)
    for rule in assessment.rules:
        lines.append(f"  {rule.status.value:<{width}}  {rule.id}  {rule.rule}")
        how = [f"via {rule.mechanism}"] if rule.mechanism != "-" else []
        if rule.detail:
            how.append(rule.detail)
        if how:
            lines.append(f"  {'':<{width}}  " + ". ".join(how))
    if assessment.baseline:
        lines += ["", "  Not policy rules (reported, never block a run):"]
        for rule in assessment.baseline:
            lines.append(f"  {rule.status.value:<{width}}  {rule.id}  {rule.rule}")
            if rule.detail:
                lines.append(f"  {'':<{width}}  {rule.detail}")
    lines.append("")
    if assessment.would_run:
        lines.append("  Result: this kernel can enforce every rule in this policy.")
    else:
        ids = ", ".join(r.id for r in assessment.blocking)
        lines.append(
            f"  Result: {len(assessment.blocking)} rule(s) are not fully enforceable here ({ids})."
        )
        lines.append("  `run` will refuse this policy unless --allow-degraded is given.")
    return "\n".join(lines) + "\n"
