"""Live tests against the running kernel. No mocks: every assertion is about real behaviour.

The same tests run on kernels with different Landlock ABIs (the GA Ubuntu 24.04 VM has ABI
4; the CI runners have newer ABIs), so ABI-gated expectations are computed from the
kernel's own answer rather than hard-coded.
"""

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from convergence.kernel import landlock as ll
from convergence.kernel import seccomp as sc
from convergence.probe import run_doctor
from convergence.probe.child import attempt, run_in_child
from convergence.probe.facts import parse_status
from convergence.probe.live import ProbeStatus
from convergence.probe.report import PROTECTIONS, ProtectionStatus

pytestmark = pytest.mark.kernel

LIVE_PROBE_MIN_ABI = {
    "landlock.fs": 1,
    "landlock.refer": 2,
    "landlock.truncate": 3,
    "landlock.net_tcp": 4,
    "landlock.ioctl_dev": 5,
    "landlock.scope_signal": 6,
    "landlock.scope_abstract_unix": 6,
}


def own_status() -> dict[str, str]:
    return parse_status(Path("/proc/self/status").read_text())


# --- the forked-child runner -------------------------------------------------------------


def test_child_result_is_returned() -> None:
    outcome = run_in_child(lambda: {"pid": str(os.getpid())})
    assert outcome.ok
    assert outcome.result["pid"] != str(os.getpid())


def test_child_exception_is_reported_not_raised() -> None:
    def boom() -> dict[str, str]:
        raise RuntimeError("probe broke")

    outcome = run_in_child(boom)
    assert not outcome.ok
    assert outcome.error is not None
    assert "probe broke" in outcome.error


def test_child_timeout_kills_the_child() -> None:
    def hang() -> dict[str, str]:
        time.sleep(30)
        return {}

    started = time.monotonic()
    outcome = run_in_child(hang, timeout=0.5)
    assert time.monotonic() - started < 10
    assert not outcome.ok
    assert outcome.error is not None
    assert "timed out" in outcome.error
    assert outcome.exit_status == "killed by SIGKILL"


def test_attempt_names_the_errno() -> None:
    assert attempt(lambda: Path("/nonexistent/x").read_text()) == "ENOENT"
    assert attempt(lambda: None) == "ok"


# --- the Landlock binding ----------------------------------------------------------------


def test_abi_version_is_positive() -> None:
    assert ll.abi_version() >= 1


def test_kernel_rejects_rights_it_does_not_know() -> None:
    # One bit above everything this module knows: no current kernel accepts it. This is why
    # rulesets are always built from features_for_abi() and never from a fixed mask.
    unknown = ll.AccessFs(1 << 40)
    with pytest.raises(OSError, match="syscall") as exc:
        ll.Ruleset(fs=unknown)
    assert exc.value.errno == errno.EINVAL


def test_ruleset_needs_something_to_handle() -> None:
    with pytest.raises(ValueError, match="at least one"):
        ll.Ruleset()


def test_port_range_is_checked() -> None:
    abi = ll.abi_version()
    if abi < 4:
        pytest.skip("needs Landlock ABI 4 for network rules")
    with (
        ll.Ruleset(net=ll.AccessNet.CONNECT_TCP) as ruleset,
        pytest.raises(ValueError, match="out of range"),
    ):
        ruleset.allow_port(70000, ll.AccessNet.CONNECT_TCP)


def test_restrict_self_without_no_new_privs_is_refused() -> None:
    fs = ll.features_for_abi(ll.abi_version()).fs

    def child() -> dict[str, str]:
        ruleset = ll.Ruleset(fs=fs)
        return {"restrict": attempt(ruleset.restrict_self)}

    outcome = run_in_child(child)
    assert outcome.ok
    assert outcome.result["restrict"] == "EPERM"


# --- the libseccomp binding --------------------------------------------------------------


def test_libseccomp_loads_and_resolves_native_syscalls() -> None:
    lib = sc.library()
    info = lib.info()
    assert info.version[0] >= 2
    assert lib.resolve_syscall("openat") >= 0
    with pytest.raises(KeyError):
        lib.resolve_syscall("definitely_not_a_syscall")


def test_exported_program_is_whole_instructions() -> None:
    with sc.library().new_filter(sc.ACT_ALLOW) as flt:
        flt.add_rule(sc.act_errno(errno.EPERM), "ptrace")
        program = flt.export_bpf()
    assert len(program) % sc.BPF_INSTRUCTION_SIZE == 0
    assert len(program) > 0


def test_install_program_rejects_a_truncated_program() -> None:
    with pytest.raises(ValueError, match="invalid BPF program size"):
        sc.install_program(b"\x00" * 7)


# --- doctor end to end -------------------------------------------------------------------


def test_doctor_on_this_kernel() -> None:
    before = own_status()
    doctor = run_doctor()
    after = own_status()

    abi = ll.abi_version()
    assert doctor.landlock.abi == abi
    probes = {p.name: p for p in doctor.probes}

    # Every probe either proves its feature or reports it unavailable. None may fail or error.
    bad = [
        f"{p.name}: {p.status} {p.summary}"
        for p in doctor.probes
        if p.status in (ProbeStatus.FAILED, ProbeStatus.ERROR)
    ]
    assert bad == []

    for name, min_abi in LIVE_PROBE_MIN_ABI.items():
        expected = ProbeStatus.VERIFIED if abi >= min_abi else ProbeStatus.UNAVAILABLE
        assert probes[name].status is expected, f"{name} on ABI {abi}"

    for name in ("seccomp.filter", "no_new_privs", "rlimits"):
        assert probes[name].status is ProbeStatus.VERIFIED, probes[name].summary
    assert doctor.minimum_met

    # Probing must never confine the calling process.
    for key in ("NoNewPrivs", "Seccomp", "Seccomp_filters"):
        assert after.get(key) == before.get(key), key
    assert Path("/etc/hostname").exists()
    os.listdir("/")


def test_verified_protections_have_live_evidence() -> None:
    doctor = run_doctor()
    probes = {p.name: p for p in doctor.probes}
    specs = {spec.id: spec for spec in PROTECTIONS}
    for protection in doctor.protections:
        if protection.status is not ProtectionStatus.VERIFIED:
            continue
        # A protection is only "verified" if its own probe ran and compared observations.
        probe_name = specs[protection.id].probe
        assert probe_name is not None, protection.id
        probe = probes[probe_name]
        assert probe.status is ProbeStatus.VERIFIED
        assert probe.expected, probe_name
        assert all(probe.observed.get(k) == v for k, v in probe.expected.items()), probe_name


def test_doctor_cli_json() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "convergence", "doctor", "--json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["schema"] == "convergence.doctor/1"
    assert data["enforcement_implemented"] is False
    assert data["minimum_met"] is True


def test_doctor_cli_text() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "convergence", "doctor"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "Minimum enforcement set" in result.stdout
    assert "Live probes" in result.stdout
