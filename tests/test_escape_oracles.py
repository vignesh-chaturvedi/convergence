"""Each oracle detects its effect from harness-owned ground truth, and nothing else.

These tests act out the effect against the oracle's own state (connect to its sink, signal
its sentinel, change its sentinel file) or hand it synthetic run evidence. They contain no
attack payloads; those live in escape/cases/.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from convergence.policy.load import parse_policy
from escape.launchers import Exit, Output
from escape.oracles import CaseDirs, Evidence, Oracle, OracleConfigError, Setup, create, execution
from escape.oracles.base import scan_outputs
from escape.procs import Peak, Sampler, SamplerOptions, StatLine
from escape.schema import OracleSpec

pytestmark = pytest.mark.kernel


def make(type_name: str, **config: Any) -> Oracle:
    return create(OracleSpec.model_validate({"type": type_name, **config}))


def evidence(
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    peaks: list[Peak] | None = None,
    max_concurrent: int = 1,
    survivors: list[StatLine] | None = None,
    elapsed: float = 1.0,
    policy: str = "version: 1\n",
) -> Evidence:
    return Evidence(
        exit=Exit(0, None, elapsed, False),
        output=Output(
            stdout=stdout, stderr=stderr, stdout_total=len(stdout), stderr_total=len(stderr)
        ),
        peaks=peaks or [],
        max_concurrent=max_concurrent,
        survivors=survivors or [],
        overhead_processes=0,
        policy=parse_policy(policy),
    )


@pytest.fixture
def dirs(tmp_path: Path) -> CaseDirs:
    return CaseDirs.create(tmp_path / "case")


def secret_of(setup: Setup, oracle: Oracle) -> str:
    value: str = oracle.secret  # type: ignore[attr-defined]
    return value


# --- output scanning ---------------------------------------------------------------------


def test_scan_finds_stdout_stderr_and_files(dirs: CaseDirs) -> None:
    out = Output(stdout=b"x needle y")
    assert scan_outputs("needle", out, dirs.out) == "stdout"
    assert scan_outputs("needle", Output(stderr=b"needle"), dirs.out) == "stderr"
    (dirs.out / "sub").mkdir()
    (dirs.out / "sub" / "f.txt").write_text("..needle..")
    assert scan_outputs("needle", Output(), dirs.out) == "out/sub/f.txt"


def test_scan_never_follows_symlinks(dirs: CaseDirs) -> None:
    # A payload could plant a symlink to a host file; the harness must not read through it.
    (dirs.outside / "secret.txt").write_text("needle")
    (dirs.out / "link.txt").symlink_to(dirs.outside / "secret.txt")
    (dirs.out / "linkdir").symlink_to(dirs.outside)
    assert scan_outputs("needle", Output(), dirs.out) is None


def test_files_only_ignores_stdout(dirs: CaseDirs) -> None:
    assert scan_outputs("needle", Output(stdout=b"needle"), dirs.out, files_only=True) is None


# --- filesystem oracles ------------------------------------------------------------------


def test_canary_file_read(dirs: CaseDirs) -> None:
    oracle = make("canary-file-read")
    setup = oracle.setup(dirs)
    path = Path(str(setup.variables["CANARY_FILE"]))
    assert path.parent == dirs.outside
    secret = path.read_text().strip()
    assert oracle.check(dirs, evidence(stdout=secret.encode())).observed
    assert not oracle.check(dirs, evidence(stdout=b"nothing")).observed


def test_canary_file_write(dirs: CaseDirs) -> None:
    oracle = make("canary-file-write")
    setup = oracle.setup(dirs)
    assert not oracle.check(dirs, evidence()).observed
    Path(str(setup.variables["FORBIDDEN_PATH"])).write_text("x")
    assert oracle.check(dirs, evidence()).observed

    oracle = make("canary-file-write")
    setup = oracle.setup(dirs := CaseDirs.create(dirs.root.parent / "second"))
    Path(str(setup.variables["SENTINEL_FILE"])).write_text("changed")
    assert oracle.check(dirs, evidence()).observed


def test_canary_delete(dirs: CaseDirs) -> None:
    oracle = make("canary-delete")
    setup = oracle.setup(dirs)
    sentinel = Path(str(setup.variables["SENTINEL_FILE"]))
    assert not oracle.check(dirs, evidence()).observed
    content = sentinel.read_text()
    sentinel.unlink()
    assert oracle.check(dirs, evidence()).observed
    sentinel.write_text(content)  # same content at the same path: still a replacement
    assert oracle.check(dirs, evidence()).observed
    oracle.teardown()

    oracle = make("canary-delete")
    setup = oracle.setup(dirs := CaseDirs.create(dirs.root.parent / "moved"))
    sentinel = Path(str(setup.variables["SENTINEL_FILE"]))
    sentinel.rename(dirs.outside / "elsewhere.txt")
    assert "moved away" in oracle.check(dirs, evidence()).evidence
    oracle.teardown()


def test_workload_output_files(dirs: CaseDirs) -> None:
    oracle = make("workload-output", require_file=True)
    setup = oracle.setup(dirs)
    secret = secret_of(setup, oracle)
    assert Path(str(setup.variables["INPUT_FILE"])).read_text().count(secret) == 1
    # Only stdout is not enough when the control must write a file.
    assert not oracle.check(dirs, evidence(stdout=secret.encode())).observed
    (dirs.out / "result.txt").write_text(secret)
    assert oracle.check(dirs, evidence()).observed


def test_workload_output_archive(dirs: CaseDirs) -> None:
    oracle = make("workload-output", check="archive")
    oracle.setup(dirs)
    assert not oracle.check(dirs, evidence()).observed
    with tarfile.open(dirs.out / "work.tar.gz", "w:gz") as archive:
        archive.add(dirs.work, arcname=".")
    assert oracle.check(dirs, evidence()).observed


def test_workload_output_git_fixture(dirs: CaseDirs) -> None:
    oracle = make("workload-output", fixture="git-repo")
    setup = oracle.setup(dirs)
    repo = Path(str(setup.variables["REPO"]))
    log = subprocess.run(
        ["/usr/bin/git", "-C", str(repo), "log", "--format=%s"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert secret_of(setup, oracle) in log.stdout


# --- network oracles ---------------------------------------------------------------------


def test_tcp_sink_sees_any_connection_and_answers_http(dirs: CaseDirs) -> None:
    oracle = make("network-sink")
    setup = oracle.setup(dirs)
    try:
        assert not oracle.check(dirs, evidence()).observed
        port = int(setup.variables["SINK_PORT"])
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall(b"GET / HTTP/1.0\r\n\r\n")
            assert conn.recv(1024).startswith(b"HTTP/1.0 200 OK")
        assert oracle.check(dirs, evidence()).observed
    finally:
        oracle.teardown()


def test_sink_require_nonce(dirs: CaseDirs) -> None:
    oracle = make("network-sink", require_nonce=True)
    setup = oracle.setup(dirs)
    port = int(setup.variables["SINK_PORT"])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall(b"something else")
        assert not oracle.check(dirs, evidence()).observed
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall(str(setup.variables["SINK_NONCE"]).encode())
        assert oracle.check(dirs, evidence()).observed
    finally:
        oracle.teardown()


def test_udp_sink(dirs: CaseDirs) -> None:
    oracle = make("network-sink", protocol="udp")
    setup = oracle.setup(dirs)
    try:
        assert not oracle.check(dirs, evidence()).observed
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"hello", ("127.0.0.1", int(setup.variables["SINK_PORT"])))
        assert oracle.check(dirs, evidence()).observed
    finally:
        oracle.teardown()


def test_server_reachable(dirs: CaseDirs) -> None:
    oracle = make("server-reachable")
    setup = oracle.setup(dirs)
    port, secret = int(setup.variables["SERVE_PORT"]), str(setup.variables["SERVE_NONCE"])

    def serve() -> None:
        with socket.create_server(("127.0.0.1", port)) as server:
            server.settimeout(10)
            conn, _ = server.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n" + secret.encode())

    thread = threading.Thread(target=serve, daemon=True)
    try:
        assert not oracle.check(dirs, evidence()).observed
        thread.start()
        thread.join(timeout=15)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not oracle.check(dirs, evidence()).observed:
            time.sleep(0.05)
        assert oracle.check(dirs, evidence()).observed
    finally:
        oracle.teardown()


# --- process oracles ---------------------------------------------------------------------


def test_process_read_sentinel_holds_the_secret_in_memory_only(dirs: CaseDirs) -> None:
    oracle = make("process-read")
    setup = oracle.setup(dirs)
    try:
        pid = int(setup.variables["SENTINEL_PID"])
        assert setup.exclude_pids == {pid}
        secret = secret_of(setup, oracle)
        assert secret not in Path(f"/proc/{pid}/cmdline").read_text()
        assert secret not in Path(f"/proc/{pid}/environ").read_bytes().decode(errors="replace")
        assert not oracle.check(dirs, evidence()).observed
        assert oracle.check(dirs, evidence(stdout=secret.encode())).observed
    finally:
        oracle.teardown()
    assert (
        not Path(f"/proc/{pid}").exists() or Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z"
    )


def test_process_signal(dirs: CaseDirs) -> None:
    oracle = make("process-signal")
    setup = oracle.setup(dirs)
    pid = int(setup.variables["SENTINEL_PID"])
    try:
        assert not oracle.check(dirs, evidence()).observed
        os.kill(pid, signal.SIGUSR1)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not oracle.check(dirs, evidence()).observed:
            time.sleep(0.05)
        assert oracle.check(dirs, evidence()).observed
    finally:
        oracle.teardown()


def test_process_signal_counts_stopping_the_sentinel(dirs: CaseDirs) -> None:
    oracle = make("process-signal")
    setup = oracle.setup(dirs)
    pid = int(setup.variables["SENTINEL_PID"])
    try:
        os.kill(pid, signal.SIGSTOP)
        time.sleep(0.2)
        assert "stopped" in oracle.check(dirs, evidence()).evidence
    finally:
        oracle.teardown()


def test_privilege_gain() -> None:
    oracle = make("privilege-gain")
    assert oracle.setup(CaseDirs(Path("/"), Path("/"), Path("/"), Path("/"))).sampler.status
    me = os.geteuid()
    same = Peak(pid=1, euids={me})
    assert not oracle.check(Path("/"), evidence(peaks=[same])).observed  # type: ignore[arg-type]
    other = Peak(pid=2, euids={me, 0})
    assert oracle.check(Path("/"), evidence(peaks=[same, other])).observed  # type: ignore[arg-type]
    caps = Peak(pid=3, euids={me}, cap_eff_nonzero=True)
    assert oracle.check(Path("/"), evidence(peaks=[caps])).observed  # type: ignore[arg-type]


def test_persist(dirs: CaseDirs) -> None:
    oracle = make("persist")
    assert oracle.setup(dirs).settle_seconds >= 1.0
    assert not oracle.check(dirs, evidence()).observed
    survivor = StatLine(os.getpid(), "S", 1, 1, 1, 0, 0, 0)
    assert oracle.check(dirs, evidence(survivors=[survivor])).observed


# --- leaks -------------------------------------------------------------------------------


def test_env_leak(dirs: CaseDirs) -> None:
    oracle = make("env-leak")
    setup = oracle.setup(dirs)
    ((name, secret),) = setup.supervisor_env.items()
    assert setup.variables["ENV_CANARY_NAME"] == name
    assert secret not in str(setup.variables)  # the case is told the name, never the value
    assert oracle.check(dirs, evidence(stdout=f"{name}={secret}".encode())).observed
    assert not oracle.check(dirs, evidence()).observed


def test_fd_leak(dirs: CaseDirs) -> None:
    oracle = make("fd-leak")
    setup = oracle.setup(dirs)
    try:
        fd = int(setup.variables["INHERITED_FD"])
        assert setup.inherit_fds == (fd,)
        secret = os.pread(fd, 200, 0).decode().strip()
        assert oracle.check(dirs, evidence(stdout=secret.encode())).observed
        assert not oracle.check(dirs, evidence()).observed
    finally:
        oracle.teardown()
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(fd)


# --- resources ---------------------------------------------------------------------------

LIMITED = """\
version: 1
resources:
  wall_clock_seconds: 5
  cpu_seconds: 2
  memory_mb: 64
  max_processes: 8
  max_file_size_mb: 1
  max_open_files: 32
"""


@pytest.mark.parametrize(
    ("measure", "within", "beyond"),
    [
        ("processes", {"max_concurrent": 9}, {"max_concurrent": 10}),
        ("memory", {"peaks": [Peak(1, rss_kb=60 * 1024)]}, {"peaks": [Peak(1, rss_kb=70 * 1024)]}),
        ("cpu", {"peaks": [Peak(1, cpu_seconds=1.5)]}, {"peaks": [Peak(1, cpu_seconds=3.0)]}),
        ("open-files", {"peaks": [Peak(1, fds=32)]}, {"peaks": [Peak(1, fds=40)]}),
        ("wall-clock", {"elapsed": 6.0}, {"elapsed": 8.0}),
    ],
)
def test_resource_measures(
    dirs: CaseDirs, measure: str, within: dict[str, Any], beyond: dict[str, Any]
) -> None:
    oracle = make("resource-dos", measure=measure)
    oracle.setup(dirs)
    assert not oracle.check(dirs, evidence(policy=LIMITED, **within)).observed
    assert oracle.check(dirs, evidence(policy=LIMITED, **beyond)).observed


def test_resource_file_size(dirs: CaseDirs) -> None:
    oracle = make("resource-dos", measure="file-size")
    oracle.setup(dirs)
    (dirs.out / "small").write_bytes(b"x" * 1024)
    assert not oracle.check(dirs, evidence(policy=LIMITED)).observed
    with (dirs.out / "big").open("wb") as f:
        f.truncate(2 * 1024 * 1024)
    assert oracle.check(dirs, evidence(policy=LIMITED)).observed


def test_resource_measure_needs_its_limit(dirs: CaseDirs) -> None:
    oracle = make("resource-dos", measure="memory")
    oracle.setup(dirs)
    with pytest.raises(ValueError, match=r"resources\.memory_mb"):
        oracle.check(dirs, evidence(policy="version: 1\nresources: {memory_mb: null}\n"))


# --- execution ---------------------------------------------------------------------------


def test_exec_probe_elf_marker_is_seen_mapped_executable(dirs: CaseDirs) -> None:
    oracle = make("exec-probe")
    setup = oracle.setup(dirs)
    marker = Path(str(setup.variables["MARKER"]))
    assert marker.parent == dirs.outside
    assert setup.sampler.marker is not None
    process = subprocess.Popen([str(marker), "1"], start_new_session=True)
    sampler = Sampler(process.pid, setup.sampler, exclude=set())
    sampler.start()
    process.wait()
    sampler.stop()
    observation = oracle.check(dirs, evidence(peaks=sampler.peaks()))
    assert observation.observed, observation.evidence


def test_exec_probe_elf_marker_is_seen_through_the_loader(dirs: CaseDirs) -> None:
    # The loader maps the marker itself; the kernel only executes ld.so. Ubuntu 26.04's
    # uutils sleep refuses this, so the oracle must have picked a sleep that does not.
    loader = execution.find_loader()
    if loader is None:
        pytest.skip("no known dynamic loader on this host")
    oracle = make("exec-probe")
    setup = oracle.setup(dirs)
    marker = str(setup.variables["MARKER"])
    process = subprocess.Popen([loader, marker, "1"], start_new_session=True)
    sampler = Sampler(process.pid, setup.sampler, exclude=set())
    sampler.start()
    assert process.wait() == 0
    sampler.stop()
    observation = oracle.check(dirs, evidence(peaks=sampler.peaks()))
    assert observation.observed, observation.evidence


def test_exec_marker_falls_back_to_the_next_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refuses = tmp_path / "refuses"
    refuses.write_text("#!/bin/sh\necho 'not this name' >&2\nexit 3\n")
    refuses.chmod(0o755)
    real = next(p for p in ("/usr/bin/sleep", "/bin/sleep") if os.path.exists(p))
    monkeypatch.setattr(execution, "SLEEP_CANDIDATES", (str(refuses), real, "/no/such/sleep"))
    monkeypatch.setattr(execution, "find_loader", lambda: None)  # the direct check only
    dest = tmp_path / "sleep"
    assert execution.plant_sleep(dest) == Path(real).resolve()
    assert subprocess.run([str(dest), "0"], check=False).returncode == 0


def test_exec_marker_setup_fails_loudly_when_nothing_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refuses = tmp_path / "refuses"
    refuses.write_text("#!/bin/sh\necho 'not this name' >&2\nexit 3\n")
    refuses.chmod(0o755)
    monkeypatch.setattr(execution, "SLEEP_CANDIDATES", (str(refuses),))
    with pytest.raises(RuntimeError, match=r"exits 3 when run directly: not this name"):
        execution.plant_sleep(tmp_path / "sleep")
    assert not (tmp_path / "sleep").exists()
    monkeypatch.setattr(execution, "SLEEP_CANDIDATES", ("/no/such/sleep",))
    with pytest.raises(RuntimeError, match="none of /no/such/sleep exists"):
        execution.plant_sleep(tmp_path / "sleep")


def test_exec_probe_elf_not_run(dirs: CaseDirs) -> None:
    oracle = make("exec-probe")
    oracle.setup(dirs)
    process = subprocess.Popen(["/bin/sleep", "0.3"], start_new_session=True)
    sampler = Sampler(process.pid, SamplerOptions(marker=oracle.identity), exclude=set())  # type: ignore[attr-defined]
    sampler.start()
    process.wait()
    sampler.stop()
    assert not oracle.check(dirs, evidence(peaks=sampler.peaks())).observed


def test_exec_probe_script_marker(dirs: CaseDirs) -> None:
    oracle = make("exec-probe", marker="script")
    setup = oracle.setup(dirs)
    run = subprocess.run([str(setup.variables["MARKER"])], capture_output=True, check=True)
    assert oracle.check(dirs, evidence(stdout=run.stdout)).observed
    assert not oracle.check(dirs, evidence()).observed


# --- the sampler -------------------------------------------------------------------------


def test_sampler_counts_a_runs_processes() -> None:
    process = subprocess.Popen(
        ["/bin/sh", "-c", "sleep 0.5 & sleep 0.5 & wait"], start_new_session=True
    )
    sampler = Sampler(process.pid, SamplerOptions(fds=True, status=True), exclude=set())
    sampler.start()
    process.wait()
    sampler.stop()
    assert sampler.max_concurrent >= 3  # the shell and both sleeps
    assert all(os.geteuid() in p.euids for p in sampler.peaks())
    assert max(p.fds for p in sampler.peaks()) >= 3


def test_sink_waits_for_an_http_body_sent_separately(dirs: CaseDirs) -> None:
    # Headers and body in separate segments: the sink must still record the body.
    oracle = make("network-sink", require_nonce=True)
    setup = oracle.setup(dirs)
    secret = str(setup.variables["SINK_NONCE"]).encode()
    try:
        with socket.create_connection(
            ("127.0.0.1", int(setup.variables["SINK_PORT"])), timeout=5
        ) as conn:
            conn.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(secret))
            time.sleep(0.2)
            conn.sendall(secret)
            assert conn.recv(1024).startswith(b"HTTP/1.0 200 OK")
        assert oracle.check(dirs, evidence()).observed
    finally:
        oracle.teardown()


# --- unix-socket sinks -------------------------------------------------------------------


@pytest.fixture
def short_dirs() -> Iterator[CaseDirs]:
    # sun_path is 108 bytes; keep the case directory short so the sink path fits.
    root = Path(tempfile.mkdtemp(prefix="cv-", dir="/tmp"))
    try:
        yield CaseDirs.create(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_unix_stream_sink(short_dirs: CaseDirs) -> None:
    oracle = make("network-sink", family="unix", protocol="stream")
    setup = oracle.setup(short_dirs)
    try:
        path = str(setup.variables["SINK_PATH"])
        assert Path(path).parent == short_dirs.outside
        assert not oracle.check(short_dirs, evidence()).observed
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(path)
            conn.sendall(b"hello")
        observation = oracle.check(short_dirs, evidence())
        assert observation.observed
        assert "unix" in observation.evidence
    finally:
        oracle.teardown()


def test_unix_datagram_sink(short_dirs: CaseDirs) -> None:
    oracle = make("network-sink", family="unix", protocol="datagram")
    setup = oracle.setup(short_dirs)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"hello", str(setup.variables["SINK_PATH"]))
        assert oracle.check(short_dirs, evidence()).observed
    finally:
        oracle.teardown()


def test_abstract_unix_sink(short_dirs: CaseDirs) -> None:
    oracle = make("network-sink", family="unix-abstract", protocol="stream")
    setup = oracle.setup(short_dirs)
    try:
        name = str(setup.variables["SINK_ABSTRACT"])
        assert "\0" not in name  # the case adds the leading NUL itself
        assert not oracle.check(short_dirs, evidence()).observed
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect("\0" + name)
        assert oracle.check(short_dirs, evidence()).observed
    finally:
        oracle.teardown()


@pytest.mark.parametrize(
    ("family", "protocol"),
    [("unix", "tcp"), ("unix-abstract", "udp"), ("ipv4", "stream"), ("ipv6", "datagram")],
)
def test_sink_family_and_protocol_must_match(family: str, protocol: str) -> None:
    with pytest.raises(OracleConfigError, match="takes protocol"):
        make("network-sink", family=family, protocol=protocol)


def test_unix_sink_refuses_a_path_too_long_for_sun_path(tmp_path: Path) -> None:
    deep = tmp_path / ("d" * 100)
    oracle = make("network-sink", family="unix", protocol="stream")
    with pytest.raises(RuntimeError, match="too long"):
        oracle.setup(CaseDirs.create(deep))
