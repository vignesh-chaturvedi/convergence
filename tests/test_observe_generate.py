"""Observe mode and policy generation (ADR 0008, ADR 0009).

Parser and generator rules are checked on recorded strace lines and synthetic observations.
The end-to-end tests observe a real tool, generate its policy, and run the tool under it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from convergence.generate.elf import elf_interpreter, shebang_interpreter
from convergence.generate.policy import collapse_candidate, generate, render
from convergence.observe.model import Event, Observation
from convergence.observe.trace import Collector, parse_line
from convergence.policy.load import parse_policy
from convergence.runtime.tracer import find_strace

PYTHON = str(Path(shutil.which("python3", path="/usr/bin:/bin") or "/usr/bin/python3").resolve())


def collect(*lines: str) -> list[Event]:
    collector = Collector()
    for line in lines:
        call = parse_line(line, 100)
        assert call is not None, line
        collector.call(call)
    return collector.events


# --- parsing ------------------------------------------------------------------------------


def test_opens_are_classified_by_flags() -> None:
    events = collect(
        'openat(AT_FDCWD</w>, "in.txt", O_RDONLY|O_CLOEXEC) = 3</w/in.txt>',
        'openat(AT_FDCWD</w>, "out/n.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</w/out/n.txt>',
        'openat(AT_FDCWD</w>, "log", O_WRONLY|O_APPEND) = 4</w/log>',
        'openat(AT_FDCWD</w>, ".", O_RDONLY|O_DIRECTORY) = 3</w>',
        'openat(AT_FDCWD</w>, "gone", O_RDONLY) = -1 ENOENT (No such file or directory)',
        'openat(AT_FDCWD</w>, "p", O_PATH) = 5</w/p>',
    )
    seen = [(e.op, e.path, e.result) for e in events]
    assert seen == [
        ("read", "/w/in.txt", "ok"),
        ("create", "/w/out/n.txt", "ok"),
        ("write", "/w/log", "ok"),
        ("readdir", "/w", "ok"),
        ("read", "/w/gone", "ENOENT"),
    ]


def test_identical_events_are_merged_and_counted() -> None:
    line = 'openat(AT_FDCWD</w>, "a", O_RDONLY) = 3</w/a>'
    events = collect(line, line, line)
    assert len(events) == 1
    assert events[0].count == 3
    assert events[0].id == "e1"


def test_directory_changes_exec_and_listing() -> None:
    events = collect(
        'renameat(AT_FDCWD</w>, "a", AT_FDCWD</w>, "sub/b") = 0',
        'unlinkat(AT_FDCWD</w>, "c", 0) = 0',
        'mkdir("/w/d", 0777) = 0',
        "getdents64(3</usr/lib/x>, 0x1 /* 9 entries */, 32768) = 300",
        'execve("/usr/bin/true", ["/usr/bin/true"], 0x7 /* 3 vars */) = 0',
    )
    seen = [(e.kind, e.op, e.path) for e in events]
    assert seen == [
        ("file", "rename-from", "/w/a"),
        ("file", "rename-to", "/w/sub/b"),
        ("file", "delete", "/w/c"),
        ("file", "create", "/w/d"),
        ("file", "readdir", "/usr/lib/x"),
        ("exec", "exec", "/usr/bin/true"),
    ]


def test_network_events() -> None:
    events = collect(
        "connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(9), "
        'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)',
        'sendto(4<UDP:[2]>, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("1.1.1.1")}, 16) = 1',
        "bind(5<TCPv6:[3]>, {sa_family=AF_INET6, sin6_port=htons(0)}, 28) = 0",
        'connect(6<UNIX-STREAM:[4]>, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 110) = 0',
    )
    seen = [(e.op, e.protocol, e.port, e.address, e.result) for e in events]
    assert seen == [
        ("connect", "tcp", 9, "127.0.0.1", "ECONNREFUSED"),
        ("send", "udp", 53, "1.1.1.1", "ok"),
        ("bind", "tcp", 0, None, "ok"),
        ("connect", "unix", None, "/run/x.sock", "ok"),
    ]


# --- generation ---------------------------------------------------------------------------


def observation(events: list[Event], tmp: Path, **extra: object) -> Observation:
    return Observation(
        id="test",
        created_at="2026-11-12T00:00:00Z",
        source="strace",
        command=["tool"],
        cwd=str(tmp / "work"),
        home=str(tmp / "home"),
        complete=True,
        events=events,
        processes=[100, 101],
        environment_names=["PATH", "HOME", "SECRET_TOKEN"],
        **extra,  # type: ignore[arg-type]
    )


def ev(n: int, op: str, path: str | None = None, **fields: object) -> Event:
    kind = "exec" if op == "exec" else "net" if op in ("connect", "send", "bind") else "file"
    return Event(id=f"e{n}", kind=kind, op=op, path=path, **fields)  # type: ignore[arg-type]


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for sub in ("work/out", "home/.ssh", "home/proj", "lib"):
        (tmp_path / sub).mkdir(parents=True)
    (tmp_path / "work" / "in.txt").write_text("x")
    (tmp_path / "home" / ".ssh" / "id_rsa").write_text("key")
    return tmp_path


def test_exact_grants_variables_and_parent_dirs(tree: Path) -> None:
    events = [
        ev(1, "read", str(tree / "work/in.txt")),
        ev(2, "create", str(tree / "work/out/result.json")),
        ev(3, "read", str(tree / "home/.ssh/id_rsa")),
        ev(4, "read", str(tree / "work/missing.txt"), result="ENOENT"),
        ev(5, "read", "/etc/shadow", result="EACCES"),
        ev(6, "read", "/proc/101/status"),
        ev(7, "read", "/proc/1/environ"),
        ev(8, "read", "/proc/100/status", requested="/proc/self/status"),
    ]
    generated = generate(observation(events, tree))
    fs = generated.policy["filesystem"]
    assert sorted(fs["read"]) == ["${CWD}/in.txt", "/proc/self/status"]
    assert fs["write"] == ["${CWD}/out"]
    text = "\n".join(generated.warnings)
    assert "credential location" in text
    assert "/proc/1/environ" in text
    assert "a child process read its own /proc/101/status" in text
    assert "/etc/shadow was refused" in text
    assert generated.policy["environment"]["pass"] == ["PATH", "HOME"]
    parse_policy(render(generated))


def test_runtime_trees_collapse_with_a_count(tree: Path) -> None:
    files = [f"/usr/lib/python3.12/mod{i}.py" for i in range(6)]
    events = [ev(i + 1, "read", f) for i, f in enumerate(files)]
    events.append(ev(20, "read", "/usr/share/zoneinfo/UTC"))
    generated = generate(observation(events, tree))
    assert generated.policy["filesystem"]["read"] == [
        "/usr/lib/python3.12",
        "/usr/share/zoneinfo/UTC",
    ]
    reason = next(r for r in generated.reasons if r.value == "/usr/lib/python3.12")
    assert reason.why == "6 files read under /usr/lib/python3.12"
    assert reason.events == ["e1", "e2", "e3", "e4", "e5", "e6"]


@pytest.mark.parametrize(
    ("path", "candidate"),
    [
        ("/usr/lib/python3.12/json/decoder.py", "/usr/lib/python3.12"),
        ("/usr/lib/aarch64-linux-gnu/libc.so.6", "/usr/lib/aarch64-linux-gnu"),
        (
            "/home/u/p/.venv/lib/python3.12/site-packages/x/y.py",
            "/home/u/p/.venv/lib/python3.12/site-packages",
        ),
        ("/srv/app/node_modules/a/index.js", "/srv/app/node_modules"),
        ("/usr/lib/libz.so", None),
        ("/etc/passwd", None),
        ("/home/u/notes.txt", None),
    ],
)
def test_collapse_candidates(path: str, candidate: str | None) -> None:
    assert collapse_candidate(path) == candidate


def test_never_collapses_onto_home(tree: Path) -> None:
    # A home directory that happens to be a collapse candidate is still never collapsed.
    home = tree / "env" / "site-packages"
    home.mkdir(parents=True)
    files = [str(home / f"m{i}.py") for i in range(6)]
    for f in files:
        Path(f).write_text("")
    obs = observation([ev(i + 1, "read", f) for i, f in enumerate(files)], tree)
    obs.home = str(home)
    read = generate(obs).policy["filesystem"]["read"]
    assert read == [f"${{HOME}}/m{i}.py" for i in range(6)]


def test_a_collapse_beside_home_is_allowed(tree: Path) -> None:
    files = [str(tree / "home" / "node_modules" / f"m{i}.js") for i in range(6)]
    for f in files:
        Path(f).parent.mkdir(parents=True, exist_ok=True)
        Path(f).write_text("")
    generated = generate(observation([ev(i + 1, "read", f) for i, f in enumerate(files)], tree))
    assert generated.policy["filesystem"]["read"] == ["${HOME}/node_modules"]


def test_network_ports_and_unix_sockets(tree: Path) -> None:
    events = [
        ev(1, "connect", protocol="tcp", port=443, result="ok"),
        ev(2, "connect", protocol="tcp", port=9, result="ECONNREFUSED"),
        ev(3, "connect", protocol="tcp", port=25, result="EACCES"),
        ev(4, "send", protocol="udp", port=53),
        ev(5, "bind", protocol="tcp", port=0),
        ev(6, "connect", protocol="unix", address="/run/docker.sock"),
    ]
    generated = generate(observation(events, tree))
    assert generated.policy["network"] == {
        "tcp_connect": [9, 443],
        "udp_send": [53],
        "tcp_bind": [0],
    }
    assert any("docker.sock" in w for w in generated.warnings)


def test_exec_adds_the_elf_interpreter(tree: Path) -> None:
    generated = generate(observation([ev(1, "exec", PYTHON)], tree))
    execute = generated.policy["filesystem"]["execute"]
    interpreter = elf_interpreter(PYTHON)
    assert interpreter is not None
    assert execute == sorted([PYTHON, os.path.realpath(interpreter)])


def test_interpreters(tmp_path: Path) -> None:
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh -e\necho hi\n")
    assert shebang_interpreter(script) == "/bin/sh"
    assert elf_interpreter(script) is None
    loader = elf_interpreter(PYTHON)
    assert loader is not None
    assert "ld-linux" in loader


def test_an_incomplete_observation_says_so(tree: Path) -> None:
    obs = observation([], tree)
    obs.complete = False
    obs.limitations = ["the command was stopped at the 5 s timeout"]
    text = render(generate(obs))
    assert "INCOMPLETE" in text
    assert "5 s timeout" in text


# --- end to end ---------------------------------------------------------------------------

TOOL = """
import os, json, subprocess
rows = [open(os.path.join('data', n)).read().strip() for n in sorted(os.listdir('data'))]
with open('out/result.json', 'w') as f:
    json.dump(rows, f)
print(subprocess.run(['/usr/bin/wc', '-c', 'out/result.json'], capture_output=True,
                     text=True).stdout.split()[0])
"""


def cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "convergence", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.kernel
@pytest.mark.skipif(find_strace() is None, reason="strace is not installed")
def test_observe_generate_run(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "data").mkdir(parents=True)
    (work / "out").mkdir()
    for i in range(3):
        (work / "data" / f"in{i}.txt").write_text(f"row {i}")
    (work / "tool.py").write_text(TOOL)

    observed = cli("observe", "--out", "obs.json", "--", PYTHON, "-I", "tool.py", cwd=work)
    assert observed.returncode == 0, observed.stderr
    assert "NOT a sandbox" in observed.stderr
    obs = json.loads((work / "obs.json").read_text())
    assert obs["schema"] == "convergence.observation/1"
    assert obs["complete"] is True
    assert obs["exit"] == {"status": "exited", "exit_code": 0, "signal": None}
    assert len(obs["processes"]) == 2
    assert "execve" in obs["syscalls"]

    made = cli(
        "generate", "--from", "obs.json", "--out", "p.yaml", "--rationale", "r.json", cwd=work
    )
    assert made.returncode == 0, made.stderr
    text = (work / "p.yaml").read_text()
    assert '"${CWD}/out"' in text
    assert "/usr/bin/wc" in text
    assert json.loads((work / "r.json").read_text())["schema"] == "convergence.rationale/1"

    (work / "out" / "result.json").unlink()
    same = cli("run", "--no-record", "--policy", "p.yaml", "--", PYTHON, "-I", "tool.py", cwd=work)
    assert same.returncode == 0, same.stderr
    assert same.stdout.strip() == observed.stdout.strip()

    # A different input: a file the observation never saw is denied (fail closed).
    (work / "extra.txt").write_text("not observed")
    other = cli(
        "run", "--no-record", "--policy", "p.yaml", "--", PYTHON, "-I", "-c",
        "open('/etc/hostname').read()", cwd=work,
    )  # fmt: skip
    assert other.returncode != 0
    assert "Permission denied" in other.stderr
