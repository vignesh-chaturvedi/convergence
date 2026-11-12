"""``convergence run`` on a real kernel: enforcement, supervision, records, exit codes.

Every test starts the real CLI in a subprocess and checks the effect from outside. Tools are
small Python scripts run by the system interpreter, which the policies grant.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import resource
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from convergence.kernel import landlock as ll
from convergence.kernel import seccomp as sc
from convergence.policy.load import parse_policy
from convergence.runtime.denials import Context, attribute_line
from convergence.runtime.filters import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
    MSG_FASTOPEN,
    SOCK_DGRAM,
    SOCK_STREAM,
    FilterError,
    SocketGrants,
    build_programs,
)
from convergence.runtime.plan import GrantRedirected, open_grant, writable_directories
from convergence.runtime.tracer import find_strace
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


def test_a_grant_inside_a_writable_directory_cannot_be_redirected(
    area: dict[str, Path],
) -> None:
    secret = area["outside"] / "secret.txt"
    secret.write_text("outside every grant")
    tools = area["out"] / "tools"  # granted for reading, inside a directory granted for writing
    tools.mkdir()
    pol = policy(area)
    pol["filesystem"]["read"].append(str(tools))
    code = f"print(open({str(secret)!r}).read())"
    assert run(area, py(code), pol).returncode != 0  # the grant itself does not reach it

    # What an earlier run under this policy could have left behind.
    tools.rmdir()
    tools.symlink_to(area["outside"])
    result = run(area, py(code), pol)
    assert result.returncode == 125, result.stdout
    assert "symbolic link" in result.stderr
    assert "outside every grant" not in result.stdout

    # A link that stays inside the writable directory changes nothing, so it is followed.
    tools.unlink()
    (area["out"] / "real").mkdir()
    tools.symlink_to(area["out"] / "real")
    assert run(area, py("print('ran')"), pol).stdout.strip() == "ran"


def test_a_grant_through_a_writable_directory_must_end_in_one(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    for directory in (root / "sub", outside / "deep"):
        directory.mkdir(parents=True)
    (root / "escape").symlink_to(outside)
    (root / "dotdot").symlink_to("../outside")
    (root / "inside").symlink_to("sub")
    (root / "inside-absolute").symlink_to(root / "sub")
    (root / "out-and-back").symlink_to(outside / "back")
    (outside / "back").symlink_to(root / "sub")
    (tmp_path / "into-root").symlink_to(root / "escape" / "deep")  # a trusted link into the root
    every, trusted = writable_directories([str(root)])
    assert every == trusted == [str(root)]

    def opened(path: Path, writable: list[str] = every, safe: list[str] = trusted) -> str:
        fd = open_grant(str(path), writable, safe)
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        finally:
            os.close(fd)

    assert opened(root) == str(root)
    for inside in ("sub", "inside", "inside-absolute", "out-and-back"):
        assert opened(root / inside) == str(root / "sub"), inside
    for redirected in (
        root / "escape",
        root / "escape" / "deep",
        root / "dotdot",
        tmp_path / "into-root",
    ):
        with pytest.raises(GrantRedirected):
            opened(redirected)
    # Outside any writable directory, links are followed as before.
    assert opened(root / "escape" / "deep", [], []) == str(outside / "deep")
    assert opened(tmp_path / "into-root", [], []) == str(outside / "deep")
    with pytest.raises(FileNotFoundError):
        opened(root / "missing")


def test_a_redirected_write_grant_is_not_trusted(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "build").symlink_to(outside)  # a second write grant, pointed elsewhere by the tool
    every, trusted = writable_directories([str(root), str(root / "build")])
    assert every == sorted([str(root), str(outside)])
    assert trusted == [str(root)]
    with pytest.raises(GrantRedirected):
        open_grant(str(root / "build"), every, trusted)


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


STORM = """
import os, sys
marker = sys.argv[1]
while True:
    try:
        if os.fork() == 0:
            os.setsid()  # leave the process group: only a per-process kill reaches it now
    except OSError:
        pass
"""


def _running_with(marker: str) -> list[int]:
    found = []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            command = Path(entry.path, "cmdline").read_bytes()
        except OSError:
            continue
        if marker.encode() in command and alive(int(entry.name)):
            found.append(int(entry.name))
    return found


def test_a_fork_storm_that_leaves_the_group_is_killed(area: dict[str, Path]) -> None:
    marker = f"storm-{os.getpid()}-{time.monotonic_ns()}"
    pol = policy(area, resources={"wall_clock_seconds": 2, "max_processes": 12})
    started = time.monotonic()
    result = run(area, [*py(STORM), marker], pol, extra=("--no-record", "--json"))
    took = time.monotonic() - started
    outcome = json.loads(result.stdout)["outcome"]
    try:
        assert result.returncode == 124, result.stderr
        assert took < 15, took
        assert outcome["left_running"] == 0
        assert outcome["descendants_killed"] >= 1
        assert _running_with(marker) == []
    finally:
        for pid in _running_with(marker):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


GIVE_UP = """
import json, os, sys, time
from convergence.kernel._libc import PR_SET_CHILD_SUBREAPER, prctl
from convergence.runtime.supervisor import kill_everything
prctl(PR_SET_CHILD_SUBREAPER, 1)
pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork() == 0:
        os.setsid()
    time.sleep(60)
    os._exit(0)
time.sleep(0.3)
impatient = kill_everything(pid, patience=0.0)
thorough = kill_everything(pid)
print(json.dumps({
    "impatient_left_running": impatient.left_running,
    "killed": len(impatient.killed),
    "thorough_left_running": thorough.left_running,
    "reaped": len(impatient.statuses) + len(thorough.statuses),
}))
"""


def test_the_sweep_says_what_it_could_not_kill() -> None:
    result = subprocess.run(
        [sys.executable, "-c", GIVE_UP], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "impatient_left_running": 2,  # out of patience after one sweep: both are reported
        "killed": 2,
        "thorough_left_running": 0,
        "reaped": 2,
    }


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
import ctypes, errno, json, os, socket, sys
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
def on_tcp(action):
    try:
        action(socket.socket())
        return 'ok'
    except OSError as e:
        return errno.errorcode[e.errno]
FASTOPEN, CLOSED = 0x20000000, ('127.0.0.1', 9)
out = {
    'unshare_user': call('unshare', 0x10000000),
    'clone3': call('clone3', 0, 0),
    'io_uring_setup': call('io_uring_setup', 1, 0),
    'personality_query': call('personality', 0xFFFFFFFF),
    'personality_no_aslr': call('personality', 0x0040000),
    'personality_no_aslr_bit_31': call('personality', 0x80040000),
    'personality_bit_31': call('personality', 0x80000000),
    'prlimit_self': call('prlimit64', 0, 7, 0, 0),
    'prlimit_supervisor': call('prlimit64', os.getppid(), 7, 0, 0),
    'listen_unbound': on_tcp(lambda s: s.listen(1)),
    'fastopen_sendto': on_tcp(lambda s: s.sendto(b'x', FASTOPEN, CLOSED)),
    'fastopen_sendmsg': on_tcp(lambda s: s.sendmsg([b'x'], [], FASTOPEN, CLOSED)),
    'fastopen_sendmmsg': call('sendmmsg', -1, 0, 0, FASTOPEN),
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
    names += ["prlimit64", "sendmmsg"]
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
        "personality_no_aslr_bit_31": "EPERM",
        "personality_bit_31": "EPERM",
        "prlimit_self": "ok",
        "prlimit_supervisor": "EPERM",
        # A unix server needs listen(), so it stays allowed where unix sockets can be made.
        "listen_unbound": unix_expected,
        "fastopen_sendto": "EPERM",
        "fastopen_sendmsg": "EPERM",
        "fastopen_sendmmsg": "EPERM",
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


def test_fast_open_and_listen_follow_the_network_policy() -> None:
    lib = sc.library()

    def size(text: str, abi: int = 4) -> int:
        return len(build_programs(parse_policy(text), abi, lib).baseline)

    restricted = size("version: 1\nnetwork: {tcp_connect: [443]}\n")
    # 'any' has no port rule to get around, so sending with MSG_FASTOPEN stays allowed.
    assert size("version: 1\nnetwork: {tcp_connect: any}\n") < restricted
    # A granted bind port, or creatable unix sockets, need listen().
    assert size("version: 1\nnetwork: {tcp_connect: [443], tcp_bind: [8080]}\n") < restricted
    assert MSG_FASTOPEN == 0x20000000  # include/linux/socket.h


def test_tcp_fast_open_cannot_reach_a_port_that_is_not_granted(area: dict[str, Path]) -> None:
    code = (
        "import socket, sys\n"
        "s = socket.socket()\n"
        "try:\n"
        "    s.sendto(b'leak', 0x20000000, ('127.0.0.1', int(sys.argv[1])))\n"
        "    print('sent')\n"
        "except OSError as e:\n"
        "    print(e.errno)\n"
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1.5)
        port = listener.getsockname()[1]
        granted = port - 1 if port > 1024 else port + 1
        pol = policy(area, network={"tcp_connect": [granted]})
        result = run(area, [*py(code), str(port)], pol)
        with pytest.raises(TimeoutError):
            listener.accept()
    assert result.stdout.strip() == str(errno.EPERM), result.stderr


def test_the_tool_cannot_change_another_processs_limits(area: dict[str, Path]) -> None:
    victim = subprocess.Popen(["/usr/bin/sleep", "30"])
    try:
        before = resource.prlimit(victim.pid, resource.RLIMIT_CPU)
        code = (
            "import resource, sys\n"
            "try:\n"
            "    resource.prlimit(int(sys.argv[1]), resource.RLIMIT_CPU, (1, 1))\n"
            "    print('changed')\n"
            "except OSError as e:\n"
            "    print(e.errno)\n"
        )
        result = run(area, [*py(code), str(victim.pid)])
        assert result.stdout.strip() == str(errno.EPERM), result.stderr
        assert resource.prlimit(victim.pid, resource.RLIMIT_CPU) == before
    finally:
        victim.kill()
        victim.wait()


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


# --- denial capture (ADR 0007) ------------------------------------------------------------

needs_strace = pytest.mark.skipif(find_strace() is None, reason="strace is not installed")

DENIED = """
import os, socket, time
try:
    open(os.environ['OUTSIDE'])
except OSError:
    pass
s = socket.socket()
try:
    s.connect(('127.0.0.1', 80))
except OSError:
    pass
try:
    os.unshare(os.CLONE_NEWUSER)
except OSError:
    pass
for _ in range(6):
    try:
        if os.fork() == 0:
            time.sleep(1)
            os._exit(0)
    except OSError:
        pass
print('done')
"""


@needs_strace
def test_trace_attributes_each_denial(area: dict[str, Path]) -> None:
    outside = area["outside"] / "secret.txt"
    outside.write_text("x")
    pol = policy(area, network={"tcp_connect": [9]})
    pol["resources"]["max_processes"] = 2
    pol["environment"]["set"]["OUTSIDE"] = str(outside)
    result = run(area, py(DENIED), pol, extra=("--no-record", "--json", "--trace"))
    record = json.loads(result.stdout)
    assert record["tracing"] == {"requested": True, "active": True, "detail": ""}
    assert record["stdout"]["kept"] == "done\n"
    seen = {(d["mechanism"], d["syscall"], d["rule"], d["target"]) for d in record["denials"]}
    assert ("landlock-filesystem", "openat", "filesystem.read", str(outside)) in seen
    assert ("landlock-network", "connect", "network.tcp_connect", "port 80") in seen
    assert ("seccomp", "unshare", "syscalls (deny list)", "") in seen
    assert any(m == "rlimit" and r == "resources.max_processes" for m, _, r, _ in seen)


@needs_strace
def test_tracing_does_not_change_what_the_tool_can_do(area: dict[str, Path]) -> None:
    outside = area["outside"] / "secret.txt"
    outside.write_text("x")
    code = f"import errno\n{errno_of(f'open({str(outside)!r})')}"
    plain = run(area, py("import errno\n" + errno_of(f"open({str(outside)!r})")))
    traced = run(area, py(code), extra=("--no-record", "--trace"))
    assert plain.stdout == traced.stdout == "EACCES\n"
    assert traced.returncode == plain.returncode == 0


def test_without_strace_the_run_goes_on_untraced(
    area: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from convergence.runtime import tracer

    monkeypatch.setattr(tracer, "STRACE_CANDIDATES", ("/no/such/strace",))
    assert tracer.Tracer.prepare() == (None, "strace is not installed")


CONTEXT = Context(
    denied_syscalls=frozenset({"unshare", "ptrace"}),
    argument_rules=frozenset({"socket", "clone"}),
    allow_list=None,
    grants={"read": ("/usr",), "write": ("/work/out",), "execute": ("/usr/bin/python3",)},
    limits=frozenset({"max_processes", "max_open_files", "cpu_seconds", "memory_mb"}),
)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            'openat(AT_FDCWD</work>, "/home/u/.ssh/id_rsa", O_RDONLY) = -1 EACCES (Permission denied)',  # noqa: E501 - strace's line, verbatim
            ("landlock-filesystem", "filesystem.read", "/home/u/.ssh/id_rsa"),
        ),
        (
            'openat(AT_FDCWD</work/out>, "f.txt", O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission denied)',  # noqa: E501 - strace's line, verbatim
            ("unattributed", "filesystem.write", "/work/out/f.txt"),
        ),
        (
            'execve("/usr/bin/curl", ["curl"], 0x7ffd /* 3 vars */) = -1 EACCES (Permission denied)',  # noqa: E501 - strace's line, verbatim
            ("landlock-filesystem", "filesystem.execute", "/usr/bin/curl"),
        ),
        (
            "connect(3<TCP:[123]>, {sa_family=AF_INET, sin_port=htons(443), "
            'sin_addr=inet_addr("1.2.3.4")}, 16) = -1 EACCES (Permission denied)',
            ("landlock-network", "network.tcp_connect", "port 443"),
        ),
        (
            "bind(3<UDP:[9]>, {sa_family=AF_INET6, sin6_port=htons(53)}, 28) = -1 EACCES (Permission denied)",  # noqa: E501 - strace's line, verbatim
            ("landlock-network", "network.udp_bind", "port 53"),
        ),
        (
            "unshare(CLONE_NEWUSER) = -1 EPERM (Operation not permitted)",
            ("seccomp", "syscalls (deny list)", ""),
        ),
        (
            "socket(AF_NETLINK, SOCK_RAW, 0) = -1 EPERM (Operation not permitted)",
            ("seccomp", "syscalls (argument rule on socket)", ""),
        ),
        ("setuid(0) = -1 EPERM (Operation not permitted)", ("unattributed", "", "")),
        (
            "clone(child_stack=NULL, flags=SIGCHLD) = -1 EAGAIN (Resource temporarily unavailable)",
            ("rlimit", "resources.max_processes", ""),
        ),
        (
            'openat(AT_FDCWD, "x", O_RDONLY) = -1 EMFILE (Too many open files)',
            ("rlimit", "resources.max_open_files", ""),
        ),
        (
            "mmap(NULL, 268439552, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 ENOMEM (Cannot allocate memory)",  # noqa: E501 - strace's line, verbatim
            ("rlimit", "resources.memory_mb", ""),
        ),
        (
            "--- SIGXCPU {si_signo=SIGXCPU, si_code=SI_KERNEL} ---",
            ("rlimit", "resources.cpu_seconds", ""),
        ),
    ],
)
def test_attribution(line: str, expected: tuple[str, str, str]) -> None:
    denial = attribute_line(line, 7, CONTEXT)
    assert denial is not None
    assert (denial.mechanism, denial.rule, denial.target) == expected


@pytest.mark.parametrize(
    "line",
    [
        'openat(AT_FDCWD, "/nope", O_RDONLY) = -1 ENOENT (No such file or directory)',
        "read(3<pipe:[1]>, 0x7f, 4096) = -1 EAGAIN (Resource temporarily unavailable)",
        'faccessat2(AT_FDCWD, "/etc/shadow", R_OK, 0) = -1 EACCES (Permission denied)',
        "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---",
        "openat(AT_FDCWD, ...) = 3</usr/lib/libc.so.6>",
    ],
)
def test_ordinary_failures_are_not_denials(line: str) -> None:
    assert attribute_line(line, 7, CONTEXT) is None


def test_allow_list_denials_are_attributed() -> None:
    context = Context(
        denied_syscalls=frozenset(),
        argument_rules=frozenset(),
        allow_list=frozenset({"read", "write"}),
        grants={},
        limits=frozenset(),
    )
    denial = attribute_line("getpid() = -1 EPERM (Operation not permitted)", 1, context)
    assert denial is not None
    assert (denial.mechanism, denial.rule) == ("seccomp", "syscalls.allow")
