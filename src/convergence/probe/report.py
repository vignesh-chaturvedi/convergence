"""Turn host facts and probe results into the ``convergence doctor`` report."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from convergence import __version__
from convergence.kernel import landlock as ll
from convergence.kernel import seccomp as sc
from convergence.probe.facts import HostFacts
from convergence.probe.live import ProbeResult, ProbeStatus

SCHEMA = "convergence.doctor/1"


class ProtectionStatus(StrEnum):
    VERIFIED = "verified"  # proven by a live probe on this machine
    ABI_ONLY = "abi-only"  # the kernel's ABI includes it; no live probe exists yet
    MISSING = "missing"  # the kernel or host lacks it
    FAILED = "failed"  # should be present, but the live probe did not behave as expected
    UNKNOWN = "unknown"  # the probe could not complete


@dataclass(frozen=True, slots=True)
class ProtectionSpec:
    id: str
    title: str
    mechanism: str
    min_abi: int | None  # Landlock ABI needed, if the mechanism is Landlock
    probe: str | None  # live probe that proves it, if one exists
    when_missing: str
    minimum: bool = False  # part of the minimum enforcement set


PROTECTIONS: tuple[ProtectionSpec, ...] = (
    ProtectionSpec(
        "fs_access",
        "Filesystem access control (read, write, execute, create, remove)",
        "Landlock",
        1,
        "landlock.fs",
        "Filesystem rules cannot be enforced.",
        minimum=True,
    ),
    ProtectionSpec(
        "fs_refer",
        "Renames and links across directories (REFER)",
        "Landlock",
        2,
        "landlock.refer",
        "Landlock refuses every rename or link across directories (EXDEV), so tools that "
        "move files between directories fail under any filesystem policy.",
    ),
    ProtectionSpec(
        "fs_truncate",
        "File truncation (TRUNCATE)",
        "Landlock",
        3,
        "landlock.truncate",
        "Truncation is not controlled by Landlock: a file the user may write under normal "
        "permissions can be truncated even outside the policy's paths.",
    ),
    ProtectionSpec(
        "net_tcp",
        "TCP bind and connect limited by port",
        "Landlock",
        4,
        "landlock.net_tcp",
        "Landlock cannot limit TCP bind or connect by port.",
    ),
    ProtectionSpec(
        "fs_ioctl_dev",
        "ioctl on character and block devices (IOCTL_DEV)",
        "Landlock",
        5,
        "landlock.ioctl_dev",
        "ioctl on devices the sandboxed process can open is not controlled by Landlock.",
    ),
    ProtectionSpec(
        "scope_abstract_unix",
        "Abstract unix socket scoping",
        "Landlock",
        6,
        "landlock.scope_abstract_unix",
        "A sandboxed process can connect to abstract unix sockets of processes outside "
        "the sandbox.",
    ),
    ProtectionSpec(
        "scope_signal",
        "Signal scoping",
        "Landlock",
        6,
        "landlock.scope_signal",
        "A sandboxed process can send signals to other processes run by the same user.",
    ),
    ProtectionSpec(
        "fs_resolve_unix",
        "Pathname unix socket connections (RESOLVE_UNIX)",
        "Landlock",
        9,
        None,
        "connect(2) to pathname unix sockets that exist outside the sandbox is not "
        "controlled by Landlock.",
    ),
    ProtectionSpec(
        "net_udp",
        "UDP bind and send limited by port",
        "Landlock",
        10,
        None,
        "Landlock cannot limit UDP bind or send by port.",
    ),
    ProtectionSpec(
        "namespace_use",
        "Namespace use restriction",
        "Landlock",
        12,
        None,
        "Landlock cannot restrict namespace creation or entry.",
    ),
    ProtectionSpec(
        "capability_use",
        "Capability use restriction",
        "Landlock",
        12,
        None,
        "Landlock cannot restrict capability use.",
    ),
    ProtectionSpec(
        "seccomp_filter",
        "Syscall filtering with argument checks",
        "seccomp-bpf",
        None,
        "seccomp.filter",
        "No syscalls can be filtered.",
        minimum=True,
    ),
    ProtectionSpec(
        "no_new_privs",
        "no_new_privs (setuid and file capabilities cannot raise privileges)",
        "prctl",
        None,
        "no_new_privs",
        "Executing a setuid binary could raise privileges, and Landlock and seccomp cannot "
        "be applied without privileges.",
        minimum=True,
    ),
    ProtectionSpec(
        "rlimits",
        "Resource limits via setrlimit (the file-size limit is tested live)",
        "setrlimit",
        None,
        "rlimits",
        "Resource limits cannot be applied.",
        minimum=True,
    ),
    ProtectionSpec(
        "tracing",
        "Denial tracing and observe mode",
        "ptrace (strace)",
        None,
        "ptrace.strace",
        "Policies can still be enforced, but denials cannot be traced and observe mode cannot run.",
    ),
)

# Landlock errata (security/landlock/errata/abi-*.h): number -> (ABI it applies to, title).
ERRATA: dict[int, tuple[int, str]] = {
    1: (4, "TCP socket identification"),
    2: (6, "scoped signal handling"),
    3: (1, "disconnected directory handling"),
    4: (1, "creation of whiteout objects"),
}


@dataclass(slots=True)
class Protection:
    id: str
    title: str
    mechanism: str
    status: ProtectionStatus
    requirement: str
    detail: str
    minimum: bool


@dataclass(slots=True)
class LandlockInfo:
    abi: int | None
    unavailable_reason: str | None
    known_max_abi: int
    errata_mask: int | None
    errata_fixed: list[int]
    errata_not_fixed: list[int]


@dataclass(slots=True)
class SeccompInfo:
    library_path: str | None
    library_version: str | None
    api_level: int | None
    error: str | None


@dataclass(slots=True)
class DoctorReport:
    schema: str
    convergence_version: str
    generated_at: str
    enforcement_implemented: bool
    host: HostFacts
    landlock: LandlockInfo
    seccomp: SeccompInfo
    probes: list[ProbeResult]
    protections: list[Protection]
    minimum_met: bool
    minimum_missing: list[str]
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=False)


def landlock_info(abi: int | None, reason: str | None, errata_mask: int | None) -> LandlockInfo:
    fixed: list[int] = []
    not_fixed: list[int] = []
    if abi is not None and errata_mask is not None:
        for number, (applies_to, _) in sorted(ERRATA.items()):
            if errata_mask & (1 << (number - 1)):
                fixed.append(number)
            elif applies_to <= abi:
                not_fixed.append(number)
    return LandlockInfo(abi, reason, ll.KNOWN_MAX_ABI, errata_mask, fixed, not_fixed)


def seccomp_info() -> SeccompInfo:
    try:
        info = sc.library().info()
    except sc.SeccompUnavailable as exc:
        return SeccompInfo(None, None, None, str(exc))
    return SeccompInfo(info.path, ".".join(map(str, info.version)), info.api_level, None)


def _protection(
    spec: ProtectionSpec, abi: int | None, probes: dict[str, ProbeResult]
) -> Protection:
    requirement = f"Landlock ABI {spec.min_abi}" if spec.min_abi is not None else spec.mechanism
    if spec.probe is not None:
        result = probes.get(spec.probe)
        if result is None:
            status, detail = ProtectionStatus.UNKNOWN, "probe did not run"
        elif result.status is ProbeStatus.VERIFIED:
            status, detail = ProtectionStatus.VERIFIED, result.summary
        elif result.status is ProbeStatus.UNAVAILABLE:
            status, detail = ProtectionStatus.MISSING, f"{result.summary}. {spec.when_missing}"
        elif result.status is ProbeStatus.FAILED:
            status = ProtectionStatus.FAILED
            detail = f"live probe failed ({result.summary}). Treat as missing: {spec.when_missing}"
        else:
            status, detail = ProtectionStatus.UNKNOWN, f"probe error: {result.summary}"
    else:
        if spec.min_abi is None:
            raise ValueError(f"protection {spec.id} has neither a probe nor an ABI gate")
        if abi is not None and abi >= spec.min_abi:
            status = ProtectionStatus.ABI_ONLY
            detail = (
                f"the kernel reports ABI {abi}; this version has no live probe for it yet, "
                "and does not claim it is verified"
            )
        else:
            have = f"ABI {abi}" if abi is not None else "no Landlock"
            status = ProtectionStatus.MISSING
            detail = (
                f"needs Landlock ABI {spec.min_abi}; this kernel has {have}. {spec.when_missing}"
            )
    return Protection(
        spec.id, spec.title, spec.mechanism, status, requirement, detail, spec.minimum
    )


def _warnings(host: HostFacts, landlock: LandlockInfo, probes: list[ProbeResult]) -> list[str]:
    warnings: list[str] = []
    if not host.is_linux:
        warnings.append(f"Not Linux ({host.platform}): no Convergence protection is available.")
    if host.euid == 0:
        warnings.append(
            "Running as root. Convergence is designed to run unprivileged; this report does "
            "not describe an unprivileged run."
        )
    elif host.has_effective_capabilities:
        warnings.append(
            f"This process has effective capabilities (CapEff={host.effective_capabilities})."
        )
    if host.seccomp_mode == 2:
        warnings.append(
            "This process is already under a seccomp filter (for example a container's default "
            "profile). The probe results include that outer filter's effect."
        )
    if host.no_new_privs:
        warnings.append("no_new_privs was already set on this process.")
    if host.container_hints:
        warnings.append(
            "Container indicators: " + "; ".join(host.container_hints) + ". The results "
            "describe this container, not necessarily the host."
        )
    if landlock.abi is not None and landlock.abi > ll.KNOWN_MAX_ABI:
        warnings.append(
            f"The kernel's Landlock ABI {landlock.abi} is newer than this version knows "
            f"({ll.KNOWN_MAX_ABI}); features added after ABI {ll.KNOWN_MAX_ABI} are not used."
        )
    for probe in probes:
        if probe.status is ProbeStatus.FAILED:
            warnings.append(
                f"Probe {probe.name} failed although the kernel should support it: {probe.summary}"
            )
        elif probe.status is ProbeStatus.ERROR:
            warnings.append(f"Probe {probe.name} could not complete: {probe.summary}")
    return warnings


def build(
    host: HostFacts,
    landlock: LandlockInfo,
    seccomp: SeccompInfo,
    probes: list[ProbeResult],
) -> DoctorReport:
    by_name = {probe.name: probe for probe in probes}
    protections = [_protection(spec, landlock.abi, by_name) for spec in PROTECTIONS]
    missing = [
        p.title for p in protections if p.minimum and p.status is not ProtectionStatus.VERIFIED
    ]
    return DoctorReport(
        schema=SCHEMA,
        convergence_version=__version__,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        enforcement_implemented=False,
        host=host,
        landlock=landlock,
        seccomp=seccomp,
        probes=probes,
        protections=protections,
        minimum_met=not missing,
        minimum_missing=missing,
        warnings=_warnings(host, landlock, probes),
    )


def _wrap(text: str, indent: int, width: int = 92) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width - indent:
            lines.append(" " * indent + current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(" " * indent + current)
    return lines


def render_text(report: DoctorReport) -> str:
    host = report.host
    lines = [f"convergence doctor ({report.convergence_version})", ""]
    lines += _wrap(
        "Pre-alpha: Convergence does not enforce policies yet. This report shows what this "
        "machine's kernel supports, proven by live tests in throwaway child processes.",
        0,
    )

    caps = (
        "no effective capabilities"
        if not host.has_effective_capabilities
        else (f"effective capabilities {host.effective_capabilities}")
    )
    who = "root" if host.euid == 0 else "unprivileged"
    nnp = {True: "set", False: "not set", None: "unknown"}[host.no_new_privs]
    lines += ["", "Host"]
    rows = [
        ("kernel", f"{host.system} {host.kernel_release} {host.machine}"),
        ("os", host.os_pretty_name or "unknown"),
        ("lsm", ",".join(host.lsm) if host.lsm else "unknown"),
        ("user", f"uid {host.uid} ({who}, {caps})"),
        ("this process", f"seccomp mode {host.seccomp_mode}, no_new_privs {nnp}"),
        ("yama", f"ptrace_scope {host.yama_ptrace_scope}"),
        (
            "userns",
            f"unprivileged_userns_clone {host.unprivileged_userns_clone}, "
            f"apparmor_restrict_unprivileged_userns {host.apparmor_restrict_unprivileged_userns}",
        ),
        ("python", host.python),
        (
            "libseccomp",
            f"{report.seccomp.library_version} (API level {report.seccomp.api_level})"
            if report.seccomp.library_version
            else f"unavailable: {report.seccomp.error}",
        ),
        ("strace", host.strace_version or ("installed" if host.strace_path else "not installed")),
    ]
    lines += [f"  {key:<13} {value}" for key, value in rows]

    landlock = report.landlock
    lines += ["", "Landlock"]
    if landlock.abi is None:
        lines.append(f"  {'ABI':<13} unavailable: {landlock.unavailable_reason}")
    else:
        lines.append(
            f"  {'ABI':<13} {landlock.abi} (this version knows ABI 1-{landlock.known_max_abi})"
        )
        if landlock.errata_mask is None:
            errata = "this kernel does not support the errata query"
        else:
            fixed = ", ".join(map(str, landlock.errata_fixed)) or "none"
            not_fixed = ", ".join(map(str, landlock.errata_not_fixed)) or "none"
            errata = f"fixed: {fixed}; applicable but not fixed: {not_fixed} (informational)"
        lines.append(f"  {'errata':<13} {errata}")

    lines += ["", "Live probes"]
    for probe in report.probes:
        lines.append(f"  {probe.status.value:<12} {probe.name}")
        lines += _wrap(probe.summary, 15)

    lines += ["", "What this machine supports"]
    for protection in report.protections:
        lines.append(
            f"  {protection.status.value:<12} {protection.title} [{protection.requirement}]"
        )
        if protection.status is not ProtectionStatus.VERIFIED:
            lines += _wrap(protection.detail, 15)

    if report.warnings:
        lines += ["", "Warnings"]
        for warning in report.warnings:
            wrapped = _wrap(warning, 4)
            lines.append("  - " + wrapped[0].strip())
            lines += wrapped[1:]

    lines.append("")
    minimum = "filesystem, seccomp, no_new_privs, resource limits"
    if report.minimum_met:
        lines.append(f"Minimum enforcement set ({minimum}): available")
    else:
        lines.append(f"Minimum enforcement set ({minimum}): NOT available")
        lines += _wrap("Missing: " + "; ".join(report.minimum_missing), 2)
    return "\n".join(lines) + "\n"
