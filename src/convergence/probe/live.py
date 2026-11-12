"""Live probes: prove each kernel feature works by using it.

Every probe applies a feature inside a throwaway forked child and then attempts an operation
the feature must allow (a positive control) and one it must deny. Where possible the parent
also checks the effect from outside, for example that a denied file write left no file
behind. A version number alone is never taken as proof.

Probe children must not import modules after confining themselves (an import is a file
read that Landlock may deny), so everything they use is imported here at module level.
"""

from __future__ import annotations

import errno
import fcntl
import os
import resource
import signal
import socket
import subprocess
import termios
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from convergence.kernel import _libc
from convergence.kernel import landlock as ll
from convergence.kernel import seccomp as sc
from convergence.probe.child import ChildOutcome, attempt, run_in_child
from convergence.probe.facts import HostFacts, parse_status


class ProbeStatus(StrEnum):
    VERIFIED = "verified"  # the feature behaved exactly as expected
    UNAVAILABLE = "unavailable"  # the kernel or host lacks the feature
    FAILED = "failed"  # the feature should work here but did not behave as expected
    ERROR = "error"  # the probe itself could not complete


@dataclass(slots=True)
class ProbeResult:
    name: str
    status: ProbeStatus
    summary: str
    expected: dict[str, str] = field(default_factory=dict)
    observed: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProbeContext:
    abi: int | None
    landlock_reason: str | None
    workdir: Path
    parent_pid: int
    facts: HostFacts


def _evaluate(
    name: str,
    outcome: ChildOutcome,
    expected: dict[str, str],
    verified_summary: str,
    external: dict[str, bool] | None = None,
) -> ProbeResult:
    """Compare a child's observations (and external checks) with expectations."""
    if not outcome.ok:
        return ProbeResult(
            name, ProbeStatus.ERROR, f"probe child failed: {outcome.error} ({outcome.exit_status})"
        )
    observed = dict(outcome.result)
    for check, passed in (external or {}).items():
        observed[check] = "ok" if passed else "violated"
        expected = {**expected, check: "ok"}
    mismatches = [
        f"{key}: expected {want}, got {observed.get(key, 'nothing')}"
        for key, want in expected.items()
        if observed.get(key) != want
    ]
    if mismatches:
        return ProbeResult(
            name, ProbeStatus.FAILED, "; ".join(mismatches), expected=expected, observed=observed
        )
    return ProbeResult(
        name, ProbeStatus.VERIFIED, verified_summary, expected=expected, observed=observed
    )


def _gate(ctx: ProbeContext, name: str, min_abi: int) -> ProbeResult | None:
    """Return an UNAVAILABLE result if the kernel's Landlock ABI is too old."""
    if ctx.abi is None:
        return ProbeResult(name, ProbeStatus.UNAVAILABLE, ctx.landlock_reason or "no Landlock")
    if ctx.abi < min_abi:
        return ProbeResult(
            name,
            ProbeStatus.UNAVAILABLE,
            f"needs Landlock ABI {min_abi}; this kernel has ABI {ctx.abi}",
        )
    return None


def _confine(ruleset: ll.Ruleset) -> None:
    _libc.set_no_new_privs()
    ruleset.restrict_self()


def _features(ctx: ProbeContext) -> ll.AbiFeatures:
    if ctx.abi is None:
        raise RuntimeError("Landlock probe ran without a Landlock ABI")
    return ll.features_for_abi(ctx.abi)


# --- Landlock ----------------------------------------------------------------------------


def probe_landlock_fs(ctx: ProbeContext) -> ProbeResult:
    name = "landlock.fs"
    if (gated := _gate(ctx, name, 1)) is not None:
        return gated
    base = ctx.workdir / "fs"
    allowed = base / "allowed"
    allowed.mkdir(parents=True)
    (allowed / "inside.txt").write_text("inside")
    (base / "outside.txt").write_text("outside")
    stray = base / "created-outside.txt"
    fs = _features(ctx).fs

    def child() -> dict[str, str]:
        ruleset = ll.Ruleset(fs=fs)
        ruleset.allow_path(allowed, fs)
        _confine(ruleset)
        return {
            "read_inside": attempt(lambda: (allowed / "inside.txt").read_text()),
            "create_inside": attempt(lambda: (allowed / "new.txt").write_text("x")),
            "read_outside": attempt(lambda: (base / "outside.txt").read_text()),
            "create_outside": attempt(lambda: stray.write_text("x")),
            "list_outside": attempt(lambda: os.listdir(base)),
        }

    return _evaluate(
        name,
        run_in_child(child),
        {
            "read_inside": "ok",
            "create_inside": "ok",
            "read_outside": "EACCES",
            "create_outside": "EACCES",
            "list_outside": "EACCES",
        },
        "confined child could use its directory and was denied outside it (EACCES)",
        external={"no_file_created_outside": not stray.exists()},
    )


def probe_landlock_refer(ctx: ProbeContext) -> ProbeResult:
    name = "landlock.refer"
    if (gated := _gate(ctx, name, 2)) is not None:
        return gated
    base = ctx.workdir / "refer"
    dirs = {key: base / key for key in ("a", "b", "c", "d")}
    for path in dirs.values():
        path.mkdir(parents=True)
    (dirs["a"] / "f").write_text("a")
    (dirs["c"] / "f").write_text("c")
    fs = _features(ctx).fs
    without_refer = fs & ~ll.AccessFs.REFER

    def child() -> dict[str, str]:
        ruleset = ll.Ruleset(fs=fs)
        ruleset.allow_path(dirs["a"], without_refer)
        ruleset.allow_path(dirs["b"], without_refer)
        ruleset.allow_path(dirs["c"], fs)
        ruleset.allow_path(dirs["d"], fs)
        _confine(ruleset)
        return {
            "rename_without_refer": attempt(lambda: os.rename(dirs["a"] / "f", dirs["b"] / "f")),
            "rename_with_refer": attempt(lambda: os.rename(dirs["c"] / "f", dirs["d"] / "f")),
        }

    return _evaluate(
        name,
        run_in_child(child),
        {"rename_without_refer": "EXDEV", "rename_with_refer": "ok"},
        "cross-directory rename needed REFER (EXDEV without it)",
        external={"source_file_kept": (dirs["a"] / "f").exists()},
    )


def probe_landlock_truncate(ctx: ProbeContext) -> ProbeResult:
    name = "landlock.truncate"
    if (gated := _gate(ctx, name, 3)) is not None:
        return gated
    base = ctx.workdir / "truncate"
    (base / "denied").mkdir(parents=True)
    (base / "allowed").mkdir(parents=True)
    protected = base / "denied" / "f"
    protected.write_text("data")
    (base / "allowed" / "f").write_text("data")
    fs = _features(ctx).fs

    def child() -> dict[str, str]:
        ruleset = ll.Ruleset(fs=fs)
        ruleset.allow_path(base / "denied", fs & ~ll.AccessFs.TRUNCATE)
        ruleset.allow_path(base / "allowed", fs)
        _confine(ruleset)
        return {
            "truncate_without_right": attempt(lambda: os.truncate(protected, 0)),
            "open_trunc_without_right": attempt(
                lambda: os.close(os.open(protected, os.O_WRONLY | os.O_TRUNC))
            ),
            "truncate_with_right": attempt(lambda: os.truncate(base / "allowed" / "f", 0)),
        }

    return _evaluate(
        name,
        run_in_child(child),
        {
            "truncate_without_right": "EACCES",
            "open_trunc_without_right": "EACCES",
            "truncate_with_right": "ok",
        },
        "truncation needed TRUNCATE (EACCES without it)",
        external={"protected_file_intact": protected.read_text() == "data"},
    )


def _free_ports(count: int) -> list[int]:
    """``count`` different free ports.

    Every port stays bound until all are chosen. Picked one after another, each released
    before the next, the kernel can hand out the same port twice.
    """
    held: list[socket.socket] = []
    try:
        for _ in range(count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(s)
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in held]
    finally:
        for s in held:
            s.close()


def probe_landlock_net_tcp(ctx: ProbeContext) -> ProbeResult:
    name = "landlock.net_tcp"
    if (gated := _gate(ctx, name, 4)) is not None:
        return gated
    allowed_listener = socket.create_server(("127.0.0.1", 0))
    denied_listener = socket.create_server(("127.0.0.1", 0))
    denied_listener.setblocking(False)
    allowed_port = allowed_listener.getsockname()[1]
    denied_port = denied_listener.getsockname()[1]
    bind_ok_port, bind_denied_port = _free_ports(2)
    tcp = ll.AccessNet.BIND_TCP | ll.AccessNet.CONNECT_TCP

    def connect(port: int) -> None:
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass

    def bind(port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))

    def child() -> dict[str, str]:
        ruleset = ll.Ruleset(net=tcp)
        ruleset.allow_port(allowed_port, ll.AccessNet.CONNECT_TCP)
        ruleset.allow_port(bind_ok_port, ll.AccessNet.BIND_TCP)
        _confine(ruleset)
        return {
            "connect_allowed_port": attempt(lambda: connect(allowed_port)),
            "connect_other_port": attempt(lambda: connect(denied_port)),
            "bind_allowed_port": attempt(lambda: bind(bind_ok_port)),
            "bind_other_port": attempt(lambda: bind(bind_denied_port)),
        }

    try:
        outcome = run_in_child(child)
        try:
            denied_listener.accept()[0].close()
            reached = True
        except BlockingIOError:
            reached = False
    finally:
        allowed_listener.close()
        denied_listener.close()
    if "EADDRINUSE" in outcome.result.values():
        # The free ports were picked by binding and releasing them; another process took
        # one in between. That says nothing about Landlock, so do not report a failure.
        return ProbeResult(
            name,
            ProbeStatus.ERROR,
            "a probe port was taken by another process during the test; run doctor again",
            observed=dict(outcome.result),
        )
    return _evaluate(
        name,
        outcome,
        {
            "connect_allowed_port": "ok",
            "connect_other_port": "EACCES",
            "bind_allowed_port": "ok",
            "bind_other_port": "EACCES",
        },
        "TCP connect and bind were limited to the allowed ports (EACCES otherwise)",
        external={"denied_listener_saw_no_connection": not reached},
    )


def probe_landlock_ioctl_dev(ctx: ProbeContext) -> ProbeResult:
    name = "landlock.ioctl_dev"
    if (gated := _gate(ctx, name, 5)) is not None:
        return gated
    read_write = ll.AccessFs.READ_FILE | ll.AccessFs.WRITE_FILE
    fs = _features(ctx).fs

    def tcgets(path: str) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.ioctl(fd, termios.TCGETS, bytes(64))
        finally:
            os.close(fd)

    def child() -> dict[str, str]:
        ruleset = ll.Ruleset(fs=fs)
        ruleset.allow_path("/dev/null", read_write | ll.AccessFs.IOCTL_DEV)
        ruleset.allow_path("/dev/zero", read_write)
        _confine(ruleset)
        return {
            # /dev/null is not a terminal, so an allowed TCGETS reaches the driver: ENOTTY.
            "ioctl_with_right": attempt(lambda: tcgets("/dev/null")),
            "ioctl_without_right": attempt(lambda: tcgets("/dev/zero")),
        }

    return _evaluate(
        name,
        run_in_child(child),
        {"ioctl_with_right": "ENOTTY", "ioctl_without_right": "EACCES"},
        "device ioctl needed IOCTL_DEV (EACCES without it)",
    )


def probe_landlock_scope_signal(ctx: ProbeContext) -> ProbeResult:
    name = "landlock.scope_signal"
    if (gated := _gate(ctx, name, 6)) is not None:
        return gated
    parent = ctx.parent_pid

    def child() -> dict[str, str]:
        _confine(ll.Ruleset(scope=ll.Scope.SIGNAL))
        return {
            "signal_self": attempt(lambda: os.kill(os.getpid(), 0)),
            "signal_outside_process": attempt(lambda: os.kill(parent, 0)),
        }

    return _evaluate(
        name,
        run_in_child(child),
        {"signal_self": "ok", "signal_outside_process": "EPERM"},
        "signals to processes outside the sandbox were denied (EPERM)",
    )


def probe_landlock_scope_abstract_unix(ctx: ProbeContext) -> ProbeResult:
    name = "landlock.scope_abstract_unix"
    if (gated := _gate(ctx, name, 6)) is not None:
        return gated
    tag = uuid.uuid4().hex
    outside_address = f"\0convergence-probe-{tag}"
    inside_address = f"\0convergence-probe-{tag}-inner"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(outside_address)
    listener.listen(1)
    listener.setblocking(False)

    def connect(address: str) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(address)

    def connect_own() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(inside_address)
            server.listen(1)
            connect(inside_address)

    def child() -> dict[str, str]:
        _confine(ll.Ruleset(scope=ll.Scope.ABSTRACT_UNIX_SOCKET))
        return {
            "connect_own_socket": attempt(connect_own),
            "connect_outside_socket": attempt(lambda: connect(outside_address)),
        }

    try:
        outcome = run_in_child(child)
        try:
            listener.accept()[0].close()
            reached = True
        except BlockingIOError:
            reached = False
    finally:
        listener.close()
    return _evaluate(
        name,
        outcome,
        {"connect_own_socket": "ok", "connect_outside_socket": "EPERM"},
        "connections to abstract unix sockets outside the sandbox were denied (EPERM)",
        external={"outside_listener_saw_no_connection": not reached},
    )


# --- seccomp, no_new_privs, rlimits, tracing ---------------------------------------------


def probe_seccomp_filter(ctx: ProbeContext) -> ProbeResult:
    name = "seccomp.filter"
    if ctx.facts.seccomp_mode is None:
        return ProbeResult(
            name, ProbeStatus.UNAVAILABLE, "kernel reports no seccomp support in /proc/self/status"
        )
    try:
        library = sc.library()
        with library.new_filter(sc.ACT_ALLOW) as flt:
            flt.add_rule(
                sc.act_errno(errno.EPERM),
                "socket",
                sc.ArgCmp(0, sc.Compare.EQ, socket.AF_INET, 0),
            )
            program = flt.export_bpf()
    except (sc.SeccompUnavailable, OSError, KeyError) as exc:
        return ProbeResult(name, ProbeStatus.UNAVAILABLE, f"cannot build a filter: {exc}")

    def open_socket(family: int) -> None:
        socket.socket(family, socket.SOCK_STREAM).close()

    def child() -> dict[str, str]:
        _libc.set_no_new_privs()
        sc.install_program(program)
        with open("/proc/self/status") as f:
            mode = parse_status(f.read()).get("Seccomp", "?")
        return {
            "denied_argument_value": attempt(lambda: open_socket(socket.AF_INET)),
            "other_argument_value": attempt(lambda: open_socket(socket.AF_UNIX)),
            "seccomp_mode": mode,
        }

    return _evaluate(
        name,
        run_in_child(child),
        {"denied_argument_value": "EPERM", "other_argument_value": "ok", "seccomp_mode": "2"},
        "a filter denied socket(AF_INET) by argument (EPERM) and allowed socket(AF_UNIX)",
    )


def probe_no_new_privs(ctx: ProbeContext) -> ProbeResult:
    name = "no_new_privs"

    def child() -> dict[str, str]:
        _libc.set_no_new_privs()
        with open("/proc/self/status") as f:
            status = parse_status(f.read())
        return {
            "prctl_reports_set": str(_libc.get_no_new_privs()),
            "status_reports_set": status.get("NoNewPrivs", "?"),
        }

    return _evaluate(
        name,
        run_in_child(child),
        {"prctl_reports_set": "True", "status_reports_set": "1"},
        "PR_SET_NO_NEW_PRIVS took effect",
    )


def probe_rlimits(ctx: ProbeContext) -> ProbeResult:
    name = "rlimits"
    target = ctx.workdir / "fsize"
    limit = 1024

    def child() -> dict[str, str]:
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        settable = []
        for res in (resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_NOFILE):
            soft, hard = resource.getrlimit(res)
            resource.setrlimit(res, (soft, hard))
            settable.append(res)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            first = os.write(fd, b"x" * (2 * limit))
            second = attempt(lambda: os.write(fd, b"x"))
        finally:
            os.close(fd)
        return {
            "first_write_bytes": str(first),
            "write_past_limit": second,
            "other_limits_settable": str(len(settable) == 3),
        }

    outcome = run_in_child(child)
    size = target.stat().st_size if target.exists() else -1
    return _evaluate(
        name,
        outcome,
        {
            "first_write_bytes": str(limit),
            "write_past_limit": "EFBIG",
            "other_limits_settable": "True",
        },
        "RLIMIT_FSIZE stopped a write at the limit (EFBIG)",
        external={"file_size_at_limit": size == limit},
    )


def probe_strace(ctx: ProbeContext) -> ProbeResult:
    name = "ptrace.strace"
    path = ctx.facts.strace_path
    if path is None:
        return ProbeResult(name, ProbeStatus.UNAVAILABLE, "strace is not installed")
    true_bin = "/bin/true" if Path("/bin/true").exists() else "/usr/bin/true"
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv
            [path, "-f", "-qq", "-o", "/dev/null", "--", true_bin],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ProbeResult(name, ProbeStatus.ERROR, f"could not run strace: {exc}")
    expected = {"strace_exit_status": "0"}
    observed = {"strace_exit_status": str(result.returncode)}
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        return ProbeResult(
            name,
            ProbeStatus.FAILED,
            f"strace could not trace a child (exit {result.returncode}): "
            + (detail[-1] if detail else "no output"),
            expected=expected,
            observed=observed,
        )
    return ProbeResult(
        name,
        ProbeStatus.VERIFIED,
        f"{ctx.facts.strace_version or 'strace'} traced a child",
        expected=expected,
        observed=observed,
    )


ALL_PROBES: tuple[Callable[[ProbeContext], ProbeResult], ...] = (
    probe_landlock_fs,
    probe_landlock_refer,
    probe_landlock_truncate,
    probe_landlock_net_tcp,
    probe_landlock_ioctl_dev,
    probe_landlock_scope_signal,
    probe_landlock_scope_abstract_unix,
    probe_seccomp_filter,
    probe_no_new_privs,
    probe_rlimits,
    probe_strace,
)


def run_all(ctx: ProbeContext) -> list[ProbeResult]:
    results = []
    for probe in ALL_PROBES:
        try:
            results.append(probe(ctx))
        except Exception as exc:  # a broken probe must be reported, never crash doctor
            results.append(
                ProbeResult(probe.__name__, ProbeStatus.ERROR, f"{type(exc).__name__}: {exc}")
            )
    return results
