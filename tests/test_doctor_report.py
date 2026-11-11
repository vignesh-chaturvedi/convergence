"""How probe results become protections, warnings, and the minimum set (pure logic)."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from convergence.kernel import landlock as ll
from convergence.probe import report
from convergence.probe.facts import HostFacts
from convergence.probe.live import ProbeResult, ProbeStatus
from convergence.probe.report import ProtectionStatus

LIVE_PROBE_MIN_ABI = {
    "landlock.fs": 1,
    "landlock.refer": 2,
    "landlock.truncate": 3,
    "landlock.net_tcp": 4,
    "landlock.ioctl_dev": 5,
    "landlock.scope_signal": 6,
    "landlock.scope_abstract_unix": 6,
}
OTHER_PROBES = ("seccomp.filter", "no_new_privs", "rlimits", "ptrace.strace")


def host(**overrides: object) -> HostFacts:
    base = HostFacts(
        platform="linux",
        system="Linux",
        kernel_release="6.8.0-test",
        kernel_version="#1",
        machine="aarch64",
        os_pretty_name="Test",
        lsm=["landlock"],
        uid=1000,
        euid=1000,
        gid=1000,
        effective_capabilities="0000000000000000",
        seccomp_mode=0,
        seccomp_filters=0,
        no_new_privs=False,
        yama_ptrace_scope=1,
        unprivileged_userns_clone=1,
        apparmor_restrict_unprivileged_userns=1,
        python="3.12.3",
        strace_path="/usr/bin/strace",
        strace_version="strace -- version 6.8",
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def simulated_probes(abi: int | None) -> list[ProbeResult]:
    """What a healthy kernel at ``abi`` would report."""
    results = []
    for name, min_abi in LIVE_PROBE_MIN_ABI.items():
        ok = abi is not None and abi >= min_abi
        status = ProbeStatus.VERIFIED if ok else ProbeStatus.UNAVAILABLE
        results.append(ProbeResult(name, status, "simulated"))
    results += [ProbeResult(name, ProbeStatus.VERIFIED, "simulated") for name in OTHER_PROBES]
    return results


def build(
    abi: int | None, probes: list[ProbeResult] | None = None, **host_overrides: object
) -> report.DoctorReport:
    info = report.landlock_info(abi, None if abi is not None else "no Landlock", None)
    seccomp = report.SeccompInfo("libseccomp.so.2", "2.5.5", 6, None)
    return report.build(host(**host_overrides), info, seccomp, probes or simulated_probes(abi))


def statuses(doctor: report.DoctorReport) -> dict[str, ProtectionStatus]:
    return {p.id: p.status for p in doctor.protections}


@pytest.mark.parametrize("abi", range(1, ll.KNOWN_MAX_ABI + 2))
def test_landlock_protections_follow_the_abi(abi: int) -> None:
    got = statuses(build(abi))
    for spec in report.PROTECTIONS:
        if spec.min_abi is None:
            assert got[spec.id] is ProtectionStatus.VERIFIED
        elif abi < spec.min_abi:
            assert got[spec.id] is ProtectionStatus.MISSING, spec.id
        elif spec.probe is None:
            # No live probe yet: reported from the ABI, never as verified.
            assert got[spec.id] is ProtectionStatus.ABI_ONLY, spec.id
        else:
            assert got[spec.id] is ProtectionStatus.VERIFIED, spec.id


def test_minimum_set_is_met_with_any_landlock_abi() -> None:
    doctor = build(1)
    assert doctor.minimum_met
    assert doctor.minimum_missing == []


def test_minimum_set_is_not_met_without_landlock() -> None:
    doctor = build(None)
    assert not doctor.minimum_met
    assert doctor.minimum_missing == [
        "Filesystem access control (read, write, execute, create, remove)"
    ]
    assert all(
        status is ProtectionStatus.MISSING
        for pid, status in statuses(doctor).items()
        if pid.startswith(("fs_", "net_", "scope_"))
    )


def test_a_failed_probe_is_never_reported_as_available() -> None:
    probes = [
        replace(p, status=ProbeStatus.FAILED, summary="read_outside: expected EACCES, got ok")
        if p.name == "landlock.fs"
        else p
        for p in simulated_probes(4)
    ]
    doctor = build(4, probes)
    assert statuses(doctor)["fs_access"] is ProtectionStatus.FAILED
    assert not doctor.minimum_met
    assert any("landlock.fs failed" in w for w in doctor.warnings)


def test_probe_error_is_unknown_not_verified() -> None:
    probes = [
        replace(p, status=ProbeStatus.ERROR, summary="boom") if p.name == "seccomp.filter" else p
        for p in simulated_probes(4)
    ]
    doctor = build(4, probes)
    assert statuses(doctor)["seccomp_filter"] is ProtectionStatus.UNKNOWN
    assert not doctor.minimum_met


def test_missing_tracing_does_not_break_the_minimum_set() -> None:
    probes = [
        replace(p, status=ProbeStatus.UNAVAILABLE, summary="strace is not installed")
        if p.name == "ptrace.strace"
        else p
        for p in simulated_probes(4)
    ]
    doctor = build(4, probes)
    assert statuses(doctor)["tracing"] is ProtectionStatus.MISSING
    assert doctor.minimum_met


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"euid": 0, "uid": 0}, "Running as root"),
        ({"effective_capabilities": "0000000000200000"}, "effective capabilities"),
        ({"seccomp_mode": 2}, "already under a seccomp filter"),
        ({"no_new_privs": True}, "no_new_privs was already set"),
        ({"container_hints": ["/.dockerenv exists"]}, "Container indicators"),
        ({"platform": "darwin"}, "Not Linux"),
    ],
)
def test_warnings(overrides: dict[str, object], fragment: str) -> None:
    assert any(fragment in w for w in build(4, None, **overrides).warnings)


def test_newer_kernel_abi_is_warned_about() -> None:
    doctor = build(ll.KNOWN_MAX_ABI + 1)
    assert any("newer than this version knows" in w for w in doctor.warnings)


def test_errata_are_split_into_fixed_and_applicable() -> None:
    info = report.landlock_info(4, None, 0b0001)
    assert info.errata_fixed == [1]
    assert info.errata_not_fixed == [3, 4]  # erratum 2 applies to ABI 6, not to ABI 4
    assert report.landlock_info(4, None, None).errata_fixed == []


def test_report_states_that_nothing_is_enforced_yet() -> None:
    doctor = build(4)
    assert doctor.enforcement_implemented is False
    text = report.render_text(doctor)
    assert "does not enforce policies yet" in " ".join(text.split())


def test_json_round_trips_with_schema() -> None:
    data = json.loads(build(6).to_json())
    assert data["schema"] == "convergence.doctor/1"
    assert data["landlock"]["abi"] == 6
    assert {p["id"] for p in data["protections"]} == {s.id for s in report.PROTECTIONS}
    assert all(p["status"] in {s.value for s in ProtectionStatus} for p in data["protections"])


def test_text_lists_every_missing_protection_with_its_consequence() -> None:
    text = " ".join(report.render_text(build(4)).split())
    assert "Signal scoping [Landlock ABI 6]" in text
    assert "can send signals to other processes run by the same user" in text
    assert "Minimum enforcement set" in text
