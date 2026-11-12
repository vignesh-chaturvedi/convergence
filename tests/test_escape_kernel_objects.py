"""The kernel-object oracles, the new preconditions, and task counting.

Live tests sample benign stand-ins (an eventfd, a plain child process); the "observed" paths
use synthetic evidence. No attack payloads here: those live in escape/cases/.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from convergence.policy.load import parse_policy
from escape import preconditions
from escape.launchers import Exit, Output
from escape.oracles import CaseDirs, Evidence, Oracle, OracleConfigError, create
from escape.procs import Peak, Sampler, SamplerOptions, count_own_tasks, namespaces, own_processes
from escape.schema import OracleSpec

pytestmark = pytest.mark.kernel


def make(type_name: str, **config: Any) -> Oracle:
    return create(OracleSpec.model_validate({"type": type_name, **config}))


def evidence(peaks: list[Peak] | None = None, max_keys: int | None = None) -> Evidence:
    return Evidence(
        exit=Exit(0, None, 1.0, False),
        output=Output(),
        peaks=peaks or [],
        max_concurrent=1,
        survivors=[],
        overhead_processes=0,
        policy=parse_policy("version: 1\n"),
        max_keys=max_keys,
    )


@pytest.fixture
def dirs(tmp_path: Path) -> CaseDirs:
    return CaseDirs.create(tmp_path / "case")


def sample_child(code: str, options: SamplerOptions) -> list[Peak]:
    child = subprocess.Popen([sys.executable, "-c", code], start_new_session=True)
    sampler = Sampler(child.pid, options, exclude=set())
    sampler.start()
    child.wait()
    sampler.stop()
    return sampler.peaks()


# --- fd-kind -----------------------------------------------------------------------------


def test_sampler_records_anonymous_inode_descriptors() -> None:
    peaks = sample_child(
        "import os, time\nfd = os.eventfd(0)\ntime.sleep(0.4)\n", SamplerOptions(anon_inodes=True)
    )
    assert any("anon_inode:[eventfd]" in p.anon_inodes for p in peaks)


@pytest.mark.parametrize(
    ("kinds", "held", "observed"),
    [
        (["io_uring"], "anon_inode:[io_uring]", True),
        (["userfaultfd"], "anon_inode:[userfaultfd]", True),
        (["perf_event"], "anon_inode:[perf_event]", True),
        (["bpf"], "anon_inode:bpf-map", True),
        (["bpf"], "anon_inode:bpf_link", True),
        (["io_uring"], "anon_inode:[userfaultfd]", False),
        (["io_uring", "userfaultfd"], "anon_inode:[eventfd]", False),
    ],
)
def test_fd_kind(dirs: CaseDirs, kinds: list[str], held: str, observed: bool) -> None:
    oracle = make("fd-kind", kinds=kinds)
    assert oracle.setup(dirs).sampler.anon_inodes
    peak = Peak(pid=7, anon_inodes={held})
    assert oracle.check(dirs, evidence([peak])).observed is observed


def test_fd_kind_needs_kinds() -> None:
    with pytest.raises(OracleConfigError, match="kinds"):
        make("fd-kind", kinds=[])
    with pytest.raises(OracleConfigError, match="kinds"):
        make("fd-kind", kinds=["eventfd"])


# --- namespace-change --------------------------------------------------------------------


def test_a_plain_child_stays_in_the_runners_namespaces(dirs: CaseDirs) -> None:
    oracle = make("namespace-change")
    setup = oracle.setup(dirs)
    assert setup.sampler.namespaces
    peaks = sample_child("import time\ntime.sleep(0.3)\n", setup.sampler)
    assert any(p.namespaces for p in peaks)
    assert not oracle.check(dirs, evidence(peaks)).observed


def test_namespace_change_is_observed(dirs: CaseDirs) -> None:
    oracle = make("namespace-change", types=["user"])
    oracle.setup(dirs)
    mine = namespaces("self")
    other = Peak(pid=9, namespaces={"user": {"user:[1]"}, "mnt": {mine["mnt"]}})
    assert oracle.check(dirs, evidence([other])).observed
    # Only the requested types count.
    mnt_only = make("namespace-change", types=["mnt"])
    mnt_only.setup(dirs)
    assert not mnt_only.check(dirs, evidence([other])).observed


def test_unsharing_pid_shows_in_pid_for_children(dirs: CaseDirs) -> None:
    oracle = make("namespace-change", types=["pid"])
    oracle.setup(dirs)
    mine = namespaces("self")
    changed = Peak(pid=9, namespaces={"pid": {mine["pid"]}, "pid_for_children": {"pid:[2]"}})
    assert oracle.check(dirs, evidence([changed])).observed


# --- key-created -------------------------------------------------------------------------


def test_key_created(dirs: CaseDirs) -> None:
    oracle = make("key-created")
    assert oracle.setup(dirs).sampler.keys
    baseline: int = oracle.baseline  # type: ignore[attr-defined]
    assert not oracle.check(dirs, evidence(max_keys=baseline)).observed
    assert oracle.check(dirs, evidence(max_keys=baseline + 1)).observed
    with pytest.raises(RuntimeError, match="key-users"):
        oracle.check(dirs, evidence(max_keys=None))


def test_sampler_reads_the_key_count() -> None:
    child = subprocess.Popen(["/bin/sleep", "0.2"], start_new_session=True)
    sampler = Sampler(child.pid, SamplerOptions(keys=True), exclude=set())
    sampler.start()
    child.wait()
    sampler.stop()
    assert sampler.max_keys is not None
    assert sampler.max_keys >= 0


# --- process accounting ------------------------------------------------------------------


def test_task_count_includes_threads() -> None:
    stop = threading.Event()
    thread = threading.Thread(target=stop.wait)
    thread.start()
    try:
        own_threads = len(os.listdir("/proc/self/task"))
        assert own_threads >= 2
        assert count_own_tasks() >= own_threads
    finally:
        stop.set()
        thread.join()


def test_own_processes_includes_this_process() -> None:
    assert os.getpid() in own_processes()


# --- preconditions -----------------------------------------------------------------------


def test_every_precondition_has_a_probe() -> None:
    assert set(preconditions.PROBES) == set(preconditions.PRECONDITIONS)


def test_probes_are_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake() -> preconditions.Availability:
        calls.append(1)
        return preconditions.Availability(True, "fake")

    monkeypatch.setitem(preconditions.PROBES, "legacy-tiocsti", fake)
    monkeypatch.setattr(preconditions, "_CACHE", {})
    first = preconditions.probe("legacy-tiocsti")
    assert preconditions.probe("legacy-tiocsti") is first
    assert calls == [1]


@pytest.mark.parametrize(
    "name", ["userns-create", "io-uring", "userfaultfd", "unprivileged-bpf", "unprivileged-perf"]
)
def test_syscall_probes_answer_with_a_reason(name: preconditions.Precondition) -> None:
    result = preconditions.PROBES[name]()
    assert isinstance(result.available, bool)
    assert result.detail


def test_usable_namespaces_imply_creatable_ones() -> None:
    if preconditions.PROBES["unprivileged-userns"]().available:
        assert preconditions.PROBES["userns-create"]().available


def test_unknown_syscall_is_unavailable_not_an_error() -> None:
    result = preconditions._syscall_probe("not_a_syscall", lambda libc, nr: 0, "do nothing")
    assert not result.available
    assert "cannot resolve" in result.detail
