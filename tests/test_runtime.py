"""``convergence run`` on a real kernel: enforcement, supervision, records, exit codes.

Every test starts the real CLI in a subprocess and checks the effect from outside. Tools are
small Python scripts run by the system interpreter, which the policies grant.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from convergence.kernel import landlock as ll
from convergence.kernel import seccomp as sc
from convergence.policy.load import parse_policy
from convergence.runtime.filters import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
    SOCK_DGRAM,
    SOCK_STREAM,
    FilterError,
    SocketGrants,
    build_programs,
)
from escape.oracles.execution import find_loader

pytestmark = pytest.mark.kernel

PYTHON = str(Path(shutil.which("python3", path="/usr/bin:/bin") or "/usr/bin/python3").resolve())
LOADER = find_loader()


@pytest.fixture
def area(tmp_path: Path) -> dict[str, Path]:
    dirs = {name: tmp_path / name for name in ("work", "out", "outside", "state")}
    for path in dirs.values():
        path.mkdir()
    return dirs


def policy(area: dict[str, Path], **overrides: Any) -> dict[str, Any]:
    execute: list[Any] = [PYTHON]
    if LOADER:
        execute.append({"path": LOADER, "optional": True})
    data: dict[str, Any] = {
        "version": 1,
        "filesystem": {
            "read": ["/usr", "/etc/ld.so.cache", str(area["work"])],
            "write": ["${SCRATCH}", "/dev/null", str(area["out"])],
            "execute": execute,
        },
        "resources": {"wall_clock_seconds": 20},
        "environment": {"set": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **value}
        else:
            data[key] = value
    return data


def run(
    area: dict[str, Path],
    command: list[str],
    pol: dict[str, Any] | None = None,
    *,
    extra: tuple[str, ...] = ("--no-record",),
    env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    policy_path = area["work"].parent / "policy.json"
    policy_path.write_text(json.dumps(pol or policy(area)))
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "convergence",
            "run",
            *extra,
            "--policy",
            str(policy_path),
            "--",
            *command,
        ],
        cwd=area["work"],
        env=env if env is not None else dict(os.environ),
        capture_output=True,
        text=True,
        timeout=timeout,
        pass_fds=pass_fds,
        check=False,
    )


def py(code: str) -> list[str]:
    return [PYTHON, "-I", "-c", code]


def errno_of(statement: str) -> str:
    """Python source that runs ``statement`` and prints the errno name it fails with."""
    return f"try:\n    {statement}\nexcept OSError as e:\n    print(errno.errorcode[e.errno])\n"


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    try:
        return stat.read_text().split(") ")[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def wait_gone(pid: int, seconds: float = 3.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


# --- running and passing output through ---------------------------------------------------


def test_output_and_exit_status_pass_through(area: dict[str, Path]) -> None:
    result = run(
        area, py("import sys; print('hello'); print('oops', file=sys.stderr); sys.exit(3)")
    )
    assert result.returncode == 3
    assert result.stdout == "hello\n"
    assert "oops" in result.stderr


def test_a_signal_ending_the_tool_is_128_plus_n(area: dict[str, Path]) -> None:
    result = run(area, py("import os, signal; os.kill(os.getpid(), signal.SIGABRT)"))
    assert result.returncode == 128 + signal.SIGABRT


# --- filesystem ---------------------------------------------------------------------------


def test_reads_outside_the_grants_are_denied(area: dict[str, Path]) -> None:
    secret = area["outside"] / "secret.txt"
    secret.write_text("top secret")
    (area["work"] / "ok.txt").write_text("fine")
    code = "import errno, sys\nprint(open('ok.txt').read())\n" + errno_of(
        f"open({str(secret)!r}).read()"
    )
    result = run(area, py(code))
    assert result.stdout.split() == ["fine", "EACCES"]


def test_writes_only_where_granted(area: dict[str, Path]) -> None:
    code = f"import errno\nopen({str(area['out'] / 'a.txt')!r}, 'w').write('ok')\n" + errno_of(
        "open('b.txt', 'w')"
    )
    result = run(area, py(code))
    assert result.stdout.strip() == "EACCES"
    assert (area["out"] / "a.txt").read_text() == "ok"
    assert not (area["work"] / "b.txt").exists()


def test_scratch_is_fresh_writable_and_removed(area: dict[str, Path]) -> None:
    code = (
        "import os, sys; d = sys.argv[1]; print(d, os.listdir(d)); open(d + '/f', 'w').write('x')"
    )
    result = run(area, [*py(code), "${SCRATCH}"])
    assert result.returncode == 0, result.stderr
    scratch, listing = result.stdout.split(maxsplit=1)
    assert listing.strip() == "[]"
    assert not Path(scratch).exists()


def test_proc_self_is_resolved_in_the_sandboxed_process(area: dict[str, Path]) -> None:
    pol = policy(area)
    pol["filesystem"]["read"].append("/proc/self/status")
    code = (
        "import errno\n"
        "print(open('/proc/self/status').read().splitlines()[0].split()[0])\n"
        + errno_of("open('/proc/1/status').read()")
    )
    result = run(area, py(code), pol)
    assert result.stdout.split() == ["Name:", "EACCES"], result.stderr


# --- environment and descriptors ----------------------------------------------------------


def test_the_environment_comes_only_from_the_policy(area: dict[str, Path]) -> None:
    # LANG is set so the tool's interpreter does not add LC_CTYPE itself (PEP 538).
    values = {"PATH": "/usr/bin", "HOME": "${SCRATCH}", "LANG": "C.UTF-8"}
    pol = policy(area, environment={"pass": ["FOO"], "set": values})
    env = dict(os.environ, FOO="passed", API_TOKEN="must-not-leak")  # noqa: S106 - a test value
    result = run(area, py("import os, json; print(json.dumps(dict(os.environ)))"), pol, env=env)
    seen = json.loads(result.stdout)
    assert set(seen) == {"FOO", "PATH", "HOME", "LANG"}
    assert seen["FOO"] == "passed"
    assert seen["HOME"].startswith("/")
    assert "${" not in seen["HOME"]


def test_inherited_descriptors_are_closed(area: dict[str, Path]) -> None:
    held = area["outside"] / "held.txt"
    held.write_text("inherited secret")
    fd = os.open(held, os.O_RDONLY)
    try:
        code = (
            "import os, sys, errno\n"
            "try:\n    os.fstat(int(sys.argv[1])); print('open')\n"
            "except OSError as e:\n    print(errno.errorcode[e.errno])\n"
        )
        result = run(area, [*py(code), str(fd)], pass_fds=(fd,))
    finally:
        os.close(fd)
    assert result.stdout.strip() == "EBADF"


# --- supervision --------------------------------------------------------------------------


DAEMON = """
import os, sys, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        open(sys.argv[1], 'w').write(str(os.getpid()))
        time.sleep(60)
    os._exit(0)
time.sleep(0.5)
"""


def test_processes_left_behind_are_killed(area: dict[str, Path]) -> None:
    pidfile = area["out"] / "daemon.pid"
    result = run(area, [*py(DAEMON), str(pidfile)])
    assert result.returncode == 0, result.stderr
    assert "left running" in result.stderr
    assert wait_gone(int(pidfile.read_text()))


def test_the_wall_clock_kills_everything(area: dict[str, Path]) -> None:
    pidfile = area["out"] / "daemon.pid"
    pol = policy(area, resources={"wall_clock_seconds": 2})
    started = time.monotonic()
    result = run(area, [*py(DAEMON + "time.sleep(60)\n"), str(pidfile)], pol)
    assert result.returncode == 124
    assert time.monotonic() - started < 10
    assert wait_gone(int(pidfile.read_text()))


def _start_and_wait_for_pid(area: dict[str, Path], pidfile: Path) -> subprocess.Popen[bytes]:
    policy_path = area["work"].parent / "policy.json"
    policy_path.write_text(json.dumps(policy(area)))
    code = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "convergence",
            "run",
            "--no-record",
            "--policy",
            str(policy_path),
            "--",
            *py(code),
            str(pidfile),
        ],
        cwd=area["work"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    end = time.monotonic() + 20
    while not (pidfile.exists() and pidfile.read_text()) and time.monotonic() < end:
        time.sleep(0.05)
    return proc


def test_stopping_the_supervisor_kills_the_tool(area: dict[str, Path]) -> None:
    pidfile = area["out"] / "tool.pid"
    proc = _start_and_wait_for_pid(area, pidfile)
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=10) == 128 + signal.SIGTERM
    assert wait_gone(int(pidfile.read_text()))


def test_the_tool_dies_with_a_killed_supervisor(area: dict[str, Path]) -> None:
    pidfile = area["out"] / "tool.pid"
    proc = _start_and_wait_for_pid(area, pidfile)
    proc.kill()
    proc.wait(timeout=10)
    assert wait_gone(int(pidfile.read_text()))


# --- resource limits ----------------------------------------------------------------------


def test_a_data_limit_below_the_supervisors_own_size_still_starts(area: dict[str, Path]) -> None:
    pol = policy(area, resources={"wall_clock_seconds": 20, "memory_mb": 8})
    pol["filesystem"]["execute"].append("/usr/bin/true")
    result = run(area, ["/usr/bin/true"], pol)
    assert result.returncode == 0, result.stderr


def test_the_data_limit_applies_to_the_tool(area: dict[str, Path]) -> None:
    pol = policy(area, resources={"wall_clock_seconds": 20, "memory_mb": 64})
    code = (
        "try:\n    b = bytearray(256 * 1024 * 1024)\n    print('allocated')\n"
        "except MemoryError:\n    print('denied')\n"
    )
    result = run(area, py(code), pol)
    assert result.stdout.strip() == "denied", result.stderr


def test_the_process_limit_applies_to_the_tool(area: dict[str, Path]) -> None:
    pol = policy(area, resources={"wall_clock_seconds": 20, "max_processes": 2})
    code = (
        "import os, time\nmade = failed = 0\n"
        "for _ in range(10):\n"
        "    try:\n        pid = os.fork()\n"
        "    except BlockingIOError:\n        failed += 1\n        continue\n"
        "    if pid == 0:\n        time.sleep(2)\n        os._exit(0)\n    made += 1\n"
        "print(made, failed)\n"
    )
    result = run(area, py(code), pol)
    made, failed = map(int, result.stdout.split())
    assert failed >= 1
    assert made <= 4  # 2, plus slack for other processes of this user exiting meanwhile


# --- syscall filter -----------------------------------------------------------------------


SYSCALLS = """
import ctypes, errno, json, socket, sys
nums = json.loads(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def call(name, *args):
    r = libc.syscall(ctypes.c_long(nums[name]), *[ctypes.c_long(a) for a in args])
    return 'ok' if r >= 0 else errno.errorcode[ctypes.get_errno()]
def sock(*args):
    try:
        socket.socket(*args).close()
        return 'ok'
    except OSError as e:
        return errno.errorcode[e.errno]
out = {
    'unshare_user': call('unshare', 0x10000000),
    'clone3': call('clone3', 0, 0),
    'io_uring_setup': call('io_uring_setup', 1, 0),
    'personality_query': call('personality', 0xFFFFFFFF),
    'personality_no_aslr': call('personality', 0x0040000),
    'netlink': sock(socket.AF_NETLINK, socket.SOCK_RAW, 0),
    'tcp': sock(socket.AF_INET, socket.SOCK_STREAM),
    'tcp_sctp': sock(socket.AF_INET, socket.SOCK_STREAM, 132),
    'udp': sock(socket.AF_INET, socket.SOCK_DGRAM),
    'unix': sock(socket.AF_UNIX, socket.SOCK_STREAM),
    'family_high_bits': call('socket', (1 << 32) | 2, 1, 0),
}
print(json.dumps(out))
"""


def test_the_baseline_syscall_filter(area: dict[str, Path]) -> None:
    lib = sc.library()
    names = ["unshare", "clone3", "io_uring_setup", "personality", "socket"]
    nums = json.dumps({n: lib.resolve_syscall(n) for n in names})
    pol = policy(area, network={"tcp_connect": [9]})
    result = run(area, [*py(SYSCALLS), nums], pol)
    seen = json.loads(result.stdout)
    unix_expected = "ok" if ll.abi_version() >= 9 else "EPERM"
    assert seen == {
        "unshare_user": "EPERM",
        "clone3": "ENOSYS",
        "io_uring_setup": "EPERM",
        "personality_query": "ok",
        "personality_no_aslr": "EPERM",
        "netlink": "EPERM",
        "tcp": "ok",
        "tcp_sctp": "EPERM",
        "udp": "EPERM",
        "unix": unix_expected,
        "family_high_bits": "EPERM",
    }, result.stderr


ALLOW_LIST = [
    "execve",
    "brk",
    "arch_prctl",
    "mmap",
    "munmap",
    "mprotect",
    "access",
    "faccessat",
    "faccessat2",
    "openat",
    "open",
    "newfstatat",
    "fstat",
    "close",
    "read",
    "pread64",
    "write",
    "set_tid_address",
    "set_robust_list",
    "rseq",
    "prlimit64",
    "getrandom",
    "exit_group",
]


def _known(names: list[str]) -> list[str]:
    lib = sc.library()
    return [n for n in names if lib.lookup(n).kind is not sc.SyscallKind.UNKNOWN]


def test_allow_list_mode(area: dict[str, Path]) -> None:
    pol = policy(area, syscalls={"mode": "allow-list", "allow": _known(ALLOW_LIST)})
    pol["filesystem"]["execute"].append("/usr/bin/true")
    assert run(area, ["/usr/bin/true"], pol).returncode == 0
    pol["syscalls"]["allow"] = [n for n in pol["syscalls"]["allow"] if n != "mmap"]
    assert run(area, ["/usr/bin/true"], pol).returncode != 0


def test_socket_grants_follow_the_policy() -> None:
    none = parse_policy("version: 1\n")
    assert SocketGrants.from_policy(none, 4) == SocketGrants(frozenset(), frozenset())
    assert AF_UNIX in SocketGrants.from_policy(none, 9).families
    tcp = parse_policy("version: 1\nnetwork: {tcp_connect: [443]}\n")
    grants = SocketGrants.from_policy(tcp, 4)
    assert grants.families == {AF_INET, AF_INET6}
    assert grants.inet_types == {SOCK_STREAM}
    udp = parse_policy("version: 1\nnetwork: {udp_send: any, unix_sockets: allow}\n")
    grants = SocketGrants.from_policy(udp, 4)
    assert grants.families == {AF_UNIX, AF_INET, AF_INET6}
    assert grants.inet_types == {SOCK_DGRAM}


def test_programs_follow_the_mode() -> None:
    lib = sc.library()
    deny = build_programs(parse_policy("version: 1\nsyscalls: {deny: [chmod]}\n"), 4, lib)
    assert deny.allow_list is None
    assert deny.baseline
    allow = build_programs(
        parse_policy("version: 1\nsyscalls: {mode: allow-list, allow: [read]}\n"), 4, lib
    )
    assert allow.allow_list
    with pytest.raises(FilterError, match="does not know"):
        build_programs(parse_policy("version: 1\nsyscalls: {deny: [not_a_syscall]}\n"), 4, lib)


# --- records and failures -----------------------------------------------------------------


def test_json_prints_the_record(area: dict[str, Path]) -> None:
    result = run(area, py("print('captured')"), extra=("--no-record", "--json"))
    record = json.loads(result.stdout)
    assert record["schema"] == "convergence.run/1"
    assert record["outcome"]["status"] == "exited"
    assert record["outcome"]["convergence_exit_code"] == 0
    assert record["stdout"] == {
        "total_bytes": 9,
        "kept": "captured\n",
        "truncated": False,
        "passed_through": False,
    }
    assert record["enforcement"]["landlock"]["abi"] == ll.abi_version()
    assert record["enforcement"]["seccomp"]["baseline"] > 0


def test_the_record_is_saved_privately(area: dict[str, Path]) -> None:
    env = dict(os.environ, XDG_STATE_HOME=str(area["state"]))
    result = run(area, py("print(1)"), extra=(), env=env)
    assert result.returncode == 0
    saved = list((area["state"] / "convergence" / "runs").glob("*.json"))
    assert len(saved) == 1
    assert saved[0].stat().st_mode & 0o077 == 0
    assert json.loads(saved[0].read_text())["outcome"]["exit_code"] == 0


def test_output_beyond_the_kept_bytes_is_marked_truncated(area: dict[str, Path]) -> None:
    result = run(
        area, py("print('x' * 100)"), extra=("--no-record", "--json", "--max-output", "10")
    )
    stdout = json.loads(result.stdout)["stdout"]
    assert stdout["total_bytes"] == 101
    assert stdout["truncated"]
    assert len(stdout["kept"]) == 10


def test_exit_codes_when_the_tool_does_not_run(area: dict[str, Path]) -> None:
    assert run(area, ["no-such-tool"]).returncode == 127
    denied = run(area, ["/usr/bin/true"])  # exists, but not granted execute
    assert denied.returncode == 126
    assert "filesystem.execute" in denied.stderr
    bad = policy(area)
    bad["resources"] = {"wall_clock_seconds": "soon"}
    invalid = run(area, ["/usr/bin/true"], bad)
    assert invalid.returncode == 125
    assert "invalid policy" in invalid.stderr


def test_an_unenforceable_policy_is_refused_unless_degraded_is_allowed(
    area: dict[str, Path],
) -> None:
    pol = policy(area)
    pol["filesystem"]["read"].append(str(area["outside"] / "missing"))
    refused = run(area, py("print('ran')"), pol)
    assert refused.returncode == 125
    assert "--allow-degraded" in refused.stderr
    allowed = run(area, py("print('ran')"), pol, extra=("--no-record", "--allow-degraded"))
    assert allowed.returncode == 0
    assert allowed.stdout.strip() == "ran"
    assert "degraded (unenforceable)" in allowed.stderr
