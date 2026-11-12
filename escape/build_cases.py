"""Generate the development attack cases from one explicit table.

Each entry in ``VARIANTS`` is one technique: its description, payload body, oracle, policy
changes, and host preconditions. Run ``python -m escape.build_cases`` to regenerate
``escape/cases/dev/``.

Rules this generator enforces, because each one was a real defect in an earlier corpus:

- **Development cases only.** The holdout must be authored separately and never derived
  from these templates; a holdout generated from them is a copy of the development set.
- **No duplicates.** Two entries with the same payload, oracle, and policy are an error.
- **Only its own files.** It deletes and rewrites only the files listed in
  ``cases/dev/.generated``; hand-written cases next to them are never touched.
- **Setup before the marker.** A payload calls ``reached()`` immediately before its attempt,
  after any setup, and setup writes only to ``${OUT_DIR}``. Otherwise a setup step the policy
  denies would stop the payload early and be scored as a containment.
"""

from __future__ import annotations

import copy
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEV = ROOT / "cases" / "dev"
MANIFEST = DEV / ".generated"

# Every payload starts with this. `reached()` prints the runner's ${REACHED} token, flushed.
BASE = """#!/usr/bin/env python3
import os, sys


def reached():
    print("${REACHED}", flush=True)


"""

# The tightest policy a Python payload can start under: the interpreter, its libraries, the
# working directory read-only, and only ${OUT_DIR} writable. Entries add to it.
BASE_POLICY: dict[str, Any] = {
    "version": 1,
    "filesystem": {
        "read": ["/usr", "/etc/ld.so.cache", "${WORKDIR}"],
        "write": ["${OUT_DIR}", "/dev/null"],
        "execute": ["${PYTHON}", {"path": "${LOADER}", "optional": True}],
    },
    "network": {},
    "resources": {"wall_clock_seconds": 30},
    "environment": {"set": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}},
}

# The expected mechanism and the Landlock ABI it needs, per category.
ABI: dict[str, tuple[str, int]] = {
    "filesystem-read": ("landlock-fs", 1),
    "filesystem-write": ("landlock-fs", 1),
    "filesystem-delete": ("landlock-fs", 1),
    "traversal-symlink": ("landlock-fs", 1),
    "traversal-hardlink": ("landlock-fs", 1),
    "traversal-dotdot": ("landlock-fs", 1),
    "traversal-rename-refer": ("landlock-fs", 1),
    "proc-self": ("landlock-fs", 1),
    "proc-other-pid": ("landlock-fs + ptrace-domain", 1),
    "exec-disallowed": ("landlock-fs", 1),
    "exec-via-interpreter": ("landlock-fs", 1),
    "exec-via-loader": ("landlock-fs", 1),
    "setuid-no-new-privs": ("no_new_privs", 0),
    "net-tcp-connect": ("landlock-net", 4),
    "net-tcp-bind": ("landlock-net", 4),
    "net-udp": ("seccomp (socket type)", 0),
    "net-raw-socket": ("seccomp", 0),
    "unix-socket-host": ("landlock (ABI 9) / seccomp", 0),
    "ptrace": ("seccomp", 0),
    "process-vm-readv": ("seccomp", 0),
    "mount-namespace": ("seccomp", 0),
    "clone3-bypass": ("seccomp (ENOSYS)", 0),
    "io-uring-bypass": ("seccomp", 0),
    "bpf-perf-keyctl-userfaultfd": ("seccomp", 0),
    "tiocsti-injection": ("seccomp (ioctl arg)", 0),
    "signal-outside": ("landlock-signal-scope", 6),
    "resource-fork-bomb": ("rlimit + supervisor", 0),
    "resource-memory": ("rlimit", 0),
    "resource-cpu": ("rlimit + supervisor", 0),
    "resource-file-size": ("rlimit", 0),
    "resource-fd-exhaustion": ("rlimit", 0),
    "persist-setsid-doublefork": ("supervisor", 0),
    "env-leak": ("supervisor", 0),
    "fd-leak": ("supervisor", 0),
}

# A port no case's sink can use: sinks bind ephemeral ports, which start far above it.
# Granting it lets TCP sockets exist, so Landlock's port filter, not seccomp, decides.
OTHER_PORT = 9

# The canary's path relative to ${WORKDIR}, derived from the runner's variables rather than
# from the harness's directory layout.
RELPATH = "os.path.relpath('${CANARY_FILE}', '${WORKDIR}')"

PROCESS_VM_READ = """import ctypes, re
pid = int("${SENTINEL_PID}")
libc = ctypes.CDLL(None, use_errno=True)


class IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def scan():
    for line in open(f"/proc/{pid}/maps"):
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) r", line)
        if not m:
            continue
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        for addr in range(lo, min(hi, lo + 8 * 1024 * 1024), 65536):
            buf = ctypes.create_string_buffer(min(65536, hi - addr))
            local, remote = IOV(ctypes.addressof(buf), len(buf)), IOV(addr, len(buf))
            n = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
            if n > 0 and b"convergence-canary-" in buf.raw[:n]:
                print(buf.raw[:n].decode("latin1"), end="")
                return


"""


@dataclass(frozen=True)
class Variant:
    category: str
    description: str
    body: str
    oracle: dict[str, Any]
    policy: dict[str, Any] = field(default_factory=dict)  # merged into BASE_POLICY
    requires: tuple[str, ...] = ()


VARIANTS: tuple[Variant, ...] = (
    # --- filesystem ----------------------------------------------------------------------
    Variant(
        "filesystem-read",
        "Reads the secret at ${CANARY_FILE}, outside every grant, and prints it.",
        "reached()\nprint(open('${CANARY_FILE}').read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "filesystem-read",
        "Builds the secret's path from its directory rather than using it directly.",
        "path = os.path.join('${CANARY_DIR}', os.path.basename('${CANARY_FILE}'))\n"
        "reached()\nprint(open(path).read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "filesystem-read",
        "Opens the secret with openat2 and reads it through the returned descriptor.",
        """import ctypes
class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
path = os.fsencode('${CANARY_FILE}')
how = OpenHow(flags=os.O_RDONLY)
reached()
fd = libc.syscall(437, -100, ctypes.c_char_p(path), ctypes.byref(how), ctypes.sizeof(how))
if fd < 0:
    raise OSError(ctypes.get_errno(), 'openat2 failed')
print(os.read(fd, 4096).decode(), end='')
""",
        {"type": "canary-file-read"},
    ),
    Variant(
        "filesystem-write",
        "Creates ${FORBIDDEN_PATH}, outside the write grants.",
        "reached()\nopen('${FORBIDDEN_PATH}', 'w').write('escaped')\n",
        {"type": "canary-file-write"},
    ),
    Variant(
        "filesystem-write",
        "Writes through a symlink, made in ${OUT_DIR}, that points outside the write grants.",
        "link = os.path.join('${OUT_DIR}', 'outside-link')\n"
        "os.symlink('${CANARY_DIR}', link)\n"
        "reached()\n"
        "open(os.path.join(link, os.path.basename('${FORBIDDEN_PATH}')), 'w').write('escaped')\n",
        {"type": "canary-file-write"},
    ),
    Variant(
        "filesystem-write",
        "Creates a symlink at ${FORBIDDEN_PATH} to a file in ${OUT_DIR}.",
        "target = os.path.join('${OUT_DIR}', 'link-target')\n"
        "open(target, 'w').write('marker')\n"
        "reached()\n"
        "os.symlink(target, '${FORBIDDEN_PATH}')\n",
        {"type": "canary-file-write"},
    ),
    Variant(
        "filesystem-delete",
        "Unlinks ${SENTINEL_FILE}, outside the write grants.",
        "reached()\nos.unlink('${SENTINEL_FILE}')\n",
        {"type": "canary-delete"},
    ),
    Variant(
        "filesystem-delete",
        "Renames ${SENTINEL_FILE} into the writable ${OUT_DIR}.",
        "reached()\nos.rename('${SENTINEL_FILE}', os.path.join('${OUT_DIR}', 'moved'))\n",
        {"type": "canary-delete"},
    ),
    # --- traversal -----------------------------------------------------------------------
    Variant(
        "traversal-symlink",
        "Reads the secret through a symlink to it, made in the writable ${OUT_DIR}.",
        "link = os.path.join('${OUT_DIR}', 'link')\n"
        "os.symlink('${CANARY_FILE}', link)\n"
        "reached()\nprint(open(link).read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "traversal-symlink",
        "Reads the secret through a symlink to /proc/self/cwd plus a relative path.",
        "link = os.path.join('${OUT_DIR}', 'proc-link')\n"
        f"os.symlink(os.path.join('/proc/self/cwd', {RELPATH}), link)\n"
        "reached()\nprint(open(link).read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "traversal-hardlink",
        "Hard-links the secret into the writable ${OUT_DIR}, then reads the link.",
        "link = os.path.join('${OUT_DIR}', 'hardlink')\n"
        "reached()\nos.link('${CANARY_FILE}', link)\nprint(open(link).read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "traversal-dotdot",
        "Reads the secret by a '..' path from the working directory.",
        f"path = os.path.join(os.getcwd(), {RELPATH})\n"
        "reached()\nprint(open(path).read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "traversal-rename-refer",
        "Creates a file in ${OUT_DIR}, then renames it to ${FORBIDDEN_PATH}, outside the grants.",
        "source = os.path.join('${OUT_DIR}', 'move-me')\n"
        "open(source, 'w').write('marker')\n"
        "reached()\nos.rename(source, '${FORBIDDEN_PATH}')\n",
        {"type": "canary-file-write"},
    ),
    Variant(
        "proc-self",
        "Reads the secret through /proc/self/cwd and a relative path.",
        f"path = os.path.join('/proc/self/cwd', {RELPATH})\n"
        "reached()\nprint(open(path).read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "proc-self",
        "Reads the secret through /proc/thread-self/cwd and a relative path.",
        f"path = os.path.join('/proc/thread-self/cwd', {RELPATH})\n"
        "reached()\nprint(open(path).read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "proc-self",
        "Reads the secret through /proc/self/root.",
        "reached()\nprint(open('/proc/self/root${CANARY_FILE}').read(), end='')\n",
        {"type": "canary-file-read"},
    ),
    Variant(
        "proc-other-pid",
        "Reads the sentinel's secret through /proc/<pid>/mem after opening its maps file.",
        """import re
pid = int('${SENTINEL_PID}')
reached()
maps = open(f'/proc/{pid}/maps').read().splitlines()
mem = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
for line in maps:
    match = re.match(r'([0-9a-f]+)-([0-9a-f]+) r', line)
    if not match:
        continue
    lo, hi = (int(value, 16) for value in match.groups())
    limit = min(hi, lo + 8 * 1024 * 1024)
    offset = lo
    while offset < limit:
        try:
            data = os.pread(mem, min(65536, hi - offset), offset)
        except OSError:
            offset += 65536
            continue
        if b'convergence-canary-' in data:
            print(data.decode('latin1'), end='')
            raise SystemExit(0)
        if not data:
            break
        offset += max(1, len(data) - 128)
""",
        {"type": "process-read", "allow_ptrace": True},
        policy={"filesystem": {"read": ["/proc"]}},
    ),
    Variant(
        "proc-other-pid",
        "Reads the sentinel's secret from /proc/<pid>/environ.",
        """pid = int('${SENTINEL_PID}')
reached()
for item in open(f'/proc/{pid}/environ', 'rb').read().split(b'\\0'):
    name, separator, value = item.partition(b'=')
    if separator and name == b'CONVERGENCE_SENTINEL_SECRET':
        print(value.decode(), end='')
        break
""",
        {"type": "process-read", "allow_ptrace": True, "secret_in_environment": True},
        policy={"filesystem": {"read": ["/proc"]}},
    ),
    # --- other processes -----------------------------------------------------------------
    Variant(
        "process-vm-readv",
        "Reads the sentinel's memory with process_vm_readv, guided by /proc/<pid>/maps.",
        PROCESS_VM_READ + "reached()\nscan()\n",
        {"type": "process-read", "allow_ptrace": True},
    ),
    Variant(
        "ptrace",
        "Attaches to the sentinel with PTRACE_ATTACH, then reads its memory.",
        PROCESS_VM_READ + "reached()\nlibc.ptrace(16, pid, 0, 0)\nos.waitpid(pid, 0)\nscan()\n"
        "libc.ptrace(17, pid, 0, 0)\n",
        {"type": "process-read", "allow_ptrace": True},
    ),
    Variant(
        "signal-outside",
        "Sends SIGUSR1 to the sentinel, a process outside the sandbox.",
        "reached()\nos.kill(int('${SENTINEL_PID}'), 10)\n",
        {"type": "process-signal"},
    ),
    Variant(
        "tiocsti-injection",
        "Injects input into a terminal with TIOCSTI to make a reader signal the sentinel.",
        """import fcntl, pty, termios
sentinel = int('${SENTINEL_PID}')
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
pid = os.fork()
if pid == 0:
    try:
        os.read(slave, 2)
        os.kill(sentinel, 10)
    finally:
        os._exit(0)
reached()
fcntl.ioctl(slave, termios.TIOCSTI, b'X')
fcntl.ioctl(slave, termios.TIOCSTI, b'\\n')
os.waitpid(pid, 0)
""",
        {"type": "process-signal"},
        requires=("legacy-tiocsti",),
    ),
    # --- execution -----------------------------------------------------------------------
    Variant(
        "exec-disallowed",
        "Executes ${MARKER}, a binary outside every grant.",
        "reached()\nos.execv('${MARKER}', ['${MARKER}', '1'])\n",
        {"type": "exec-probe", "marker": "elf"},
    ),
    Variant(
        "exec-disallowed",
        "Executes a readable, non-executable marker with execveat on its open descriptor.",
        "fd = os.open('${MARKER}', os.O_RDONLY)\n"
        "reached()\n"
        "os.execve(fd, ['sleep', '1'], os.environ.copy())\n",
        {"type": "exec-probe", "marker": "elf"},
        policy={"filesystem": {"read": ["${MARKER_DIR}"]}},
    ),
    Variant(
        "exec-via-interpreter",
        "Runs the script ${MARKER}, outside every grant, through an allowed /bin/sh.",
        "reached()\nos.execv('/bin/sh', ['/bin/sh', '${MARKER}'])\n",
        {"type": "exec-probe", "marker": "script"},
        policy={"filesystem": {"execute": ["/bin/sh"]}},
    ),
    Variant(
        "exec-via-loader",
        "Runs ${MARKER}, readable but not executable, through the dynamic loader.",
        "reached()\nos.execv('${LOADER}', ['${LOADER}', '${MARKER}', '1'])\n",
        {"type": "exec-probe", "marker": "elf"},
        policy={"filesystem": {"read": ["${MARKER_DIR}"]}},
    ),
    Variant(
        "setuid-no-new-privs",
        "Runs the setuid-root passwd, which the policy lets it execute, on a pseudo-terminal.",
        """import pty, subprocess, time
master, slave = pty.openpty()
reached()
proc = subprocess.Popen(['/usr/bin/passwd'], stdin=slave, stdout=slave, stderr=slave,
                        start_new_session=True)
os.close(slave)
time.sleep(0.5)
if proc.poll() is None:
    proc.kill()
""",
        {"type": "privilege-gain"},
        # The pseudo-terminal is setup, not the attempt, so its devices are granted.
        policy={"filesystem": {"write": ["/dev/ptmx", "/dev/pts"], "execute": ["/usr/bin/passwd"]}},
        requires=("setuid-executable",),
    ),
    # --- network -------------------------------------------------------------------------
    Variant(
        "net-tcp-connect",
        "Connects over IPv4 to a TCP port the policy does not grant (another port is granted).",
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "reached()\ns.connect(('${SINK_HOST}', int('${SINK_PORT}')))\ns.sendall(b'probe')\n",
        {"type": "network-sink", "family": "ipv4", "protocol": "tcp"},
        policy={"network": {"tcp_connect": [OTHER_PORT]}},
    ),
    Variant(
        "net-tcp-connect",
        "Connects over IPv6 to a TCP port the policy does not grant (another port is granted).",
        "import socket\ns = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n"
        "reached()\ns.connect(('::1', int('${SINK_PORT}')))\ns.sendall(b'probe')\n",
        {"type": "network-sink", "family": "ipv6", "protocol": "tcp"},
        policy={"network": {"tcp_connect": [OTHER_PORT]}},
    ),
    Variant(
        "net-tcp-bind",
        "Serves on a TCP port the policy does not grant (another port is granted for binding).",
        """import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
reached()
s.bind(('127.0.0.1', int('${SERVE_PORT}')))
s.listen(1)
s.settimeout(10)
c, _ = s.accept()
c.recv(1024)
c.sendall(b'HTTP/1.0 200 OK\\r\\n\\r\\n${SERVE_NONCE}')
""",
        {"type": "server-reachable"},
        policy={"network": {"tcp_bind": [OTHER_PORT]}},
    ),
    Variant(
        "net-udp",
        "Sends a UDP datagram although the policy grants no UDP at all.",
        # Creating the socket is the attempt: seccomp denies UDP sockets when no UDP is granted.
        "import socket\nreached()\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.sendto(b'probe', ('${SINK_HOST}', int('${SINK_PORT}')))\n",
        {"type": "network-sink", "protocol": "udp"},
    ),
    Variant(
        "net-raw-socket",
        "Sends a hand-built UDP packet through a raw IPv4 socket.",
        """import socket, struct
port = int('${SINK_PORT}')
packet = struct.pack('!HHHH', 40000, port, 8 + 5, 0) + b'probe'
reached()
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
s.sendto(packet, ('${SINK_HOST}', port))
""",
        {"type": "network-sink", "protocol": "udp"},
        requires=("raw-socket",),
    ),
    Variant(
        "unix-socket-host",
        "Connects to a pathname unix socket outside the sandbox, standing in for a host service.",
        # Creating the socket is part of the attempt: below Landlock ABI 9, seccomp denies it.
        "import socket\nreached()\ns = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "s.connect('${SINK_PATH}')\ns.sendall(b'probe')\n",
        {"type": "network-sink", "family": "unix", "protocol": "stream"},
    ),
    # --- syscall filter ------------------------------------------------------------------
    Variant(
        "mount-namespace",
        "Creates a user namespace and then a mount namespace with unshare().",
        """import time
uid, gid = os.getuid(), os.getgid()
reached()
os.unshare(os.CLONE_NEWUSER)
time.sleep(0.5)
open('/proc/self/setgroups', 'w').write('deny')
open('/proc/self/uid_map', 'w').write(f'0 {uid} 1')
open('/proc/self/gid_map', 'w').write(f'0 {gid} 1')
os.unshare(os.CLONE_NEWNS)
time.sleep(0.5)
""",
        {"type": "namespace-change", "types": ["user", "mnt"]},
        requires=("userns-create",),
    ),
    Variant(
        "mount-namespace",
        "Creates a user namespace in a child with the legacy clone() interface.",
        """import ctypes, mmap, os
libc = ctypes.CDLL(None, use_errno=True)
libc.usleep.argtypes = [ctypes.c_uint]
libc.usleep.restype = ctypes.c_int
libc.clone.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
libc.clone.restype = ctypes.c_int
stack = mmap.mmap(-1, 1024 * 1024)
stack_top = ctypes.addressof(ctypes.c_char.from_buffer(stack)) + len(stack)
child_fn = ctypes.cast(libc.usleep, ctypes.c_void_p)
reached()
pid = libc.clone(child_fn, stack_top, 0x10000000 | 17, ctypes.c_void_p(500000))
if pid < 0:
    raise OSError(ctypes.get_errno(), 'clone(CLONE_NEWUSER) failed')
os.waitpid(pid, 0)
""",
        {"type": "namespace-change", "types": ["user"]},
        requires=("userns-create",),
    ),
    Variant(
        "clone3-bypass",
        "Creates a user namespace with clone3(), whose flags seccomp cannot inspect.",
        """import ctypes, time
names = ('flags', 'pidfd', 'child_tid', 'parent_tid', 'exit_signal', 'stack', 'stack_size',
         'tls', 'set_tid', 'set_tid_size', 'cgroup')


class Args(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in names]


args = Args(flags=0x10000000, exit_signal=17)  # CLONE_NEWUSER, SIGCHLD
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
reached()
pid = libc.syscall(435, ctypes.byref(args), ctypes.sizeof(args))  # clone3 on x86_64 and arm64
if pid == 0:
    time.sleep(0.5)
    os._exit(0)
if pid > 0:
    os.waitpid(pid, 0)
""",
        {"type": "namespace-change", "types": ["user"]},
        requires=("userns-create",),
    ),
    Variant(
        "io-uring-bypass",
        "Creates an io_uring, whose operations seccomp cannot see.",
        """import ctypes, time
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
params = ctypes.create_string_buffer(120)  # struct io_uring_params, zeroed
reached()
fd = libc.syscall(425, ctypes.c_uint(4), params)  # io_uring_setup on x86_64 and arm64
if fd >= 0:
    time.sleep(0.5)
""",
        {"type": "fd-kind", "kinds": ["io_uring"]},
        requires=("io-uring",),
    ),
    Variant(
        "bpf-perf-keyctl-userfaultfd",
        "Creates a user-mode-only userfaultfd.",
        """import ctypes, time
NUMBERS = {'x86_64': 323, 'aarch64': 282}  # userfaultfd
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
reached()
fd = libc.syscall(NUMBERS[os.uname().machine], ctypes.c_int(os.O_CLOEXEC | 1))
if fd >= 0:
    time.sleep(0.5)
""",
        {"type": "fd-kind", "kinds": ["userfaultfd"]},
        requires=("userfaultfd",),
    ),
    # --- resources -----------------------------------------------------------------------
    Variant(
        "resource-fork-bomb",
        "Forks six children when the policy allows two.",
        """import time
children = []
reached()
for _ in range(6):
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        time.sleep(2)
        os._exit(0)
    children.append(pid)
for pid in children:
    os.waitpid(pid, 0)
""",
        {"type": "resource-dos", "measure": "processes"},
        policy={"resources": {"max_processes": 2, "wall_clock_seconds": 15}},
    ),
    Variant(
        "resource-memory",
        "Touches 96 MiB of memory when the policy allows 32 MiB.",
        "reached()\nblob = bytearray(96 * 1024 * 1024)\n"
        "blob[::4096] = b'X' * (len(blob) // 4096)\n",
        {"type": "resource-dos", "measure": "memory"},
        policy={"resources": {"memory_mb": 32, "wall_clock_seconds": 15}},
    ),
    Variant(
        "resource-cpu",
        "Spins for 2.5 s of CPU time when the policy allows 1 s.",
        "import time\nreached()\nend = time.process_time() + 2.5\nx = 1\n"
        "while time.process_time() < end:\n    x = (x * 3) % 1000000007\n",
        {"type": "resource-dos", "measure": "cpu"},
        policy={"resources": {"cpu_seconds": 1, "wall_clock_seconds": 15}},
    ),
    Variant(
        "resource-file-size",
        "Writes a 2 MiB file when the policy allows 1 MiB.",
        "reached()\nwith open(os.path.join('${OUT_DIR}', 'large.bin'), 'wb') as f:\n"
        "    f.write(b'X' * (2 * 1024 * 1024))\n",
        {"type": "resource-dos", "measure": "file-size"},
        policy={"resources": {"max_file_size_mb": 1, "wall_clock_seconds": 15}},
    ),
    Variant(
        "resource-fd-exhaustion",
        "Holds 24 extra descriptors when the policy allows 8 in total.",
        "import time\nreached()\nfds = [os.dup(1) for _ in range(24)]\ntime.sleep(0.5)\n",
        {"type": "resource-dos", "measure": "open-files"},
        policy={"resources": {"max_open_files": 8, "wall_clock_seconds": 15}},
    ),
    # --- persistence and leaks -----------------------------------------------------------
    Variant(
        "persist-setsid-doublefork",
        "Leaves a daemon behind with setsid() and a double fork, outliving the tool by 3 s.",
        """import time
reached()
pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork():
        os._exit(0)
    time.sleep(3)
    os._exit(0)
os.waitpid(pid, 0)
""",
        {"type": "persist"},
    ),
    Variant(
        "persist-setsid-doublefork",
        "Leaves one ordinary child running after the tool exits, without setsid or a second fork.",
        """import time
reached()
pid = os.fork()
if pid == 0:
    time.sleep(3)
    os._exit(0)
os._exit(0)
""",
        {"type": "persist"},
    ),
    Variant(
        "env-leak",
        "Reads a secret from the supervisor's environment, which no policy passes on.",
        "reached()\nprint(os.environ['${ENV_CANARY_NAME}'])\n",
        {"type": "env-leak"},
    ),
    Variant(
        "fd-leak",
        "Reads a secret through a descriptor the supervisor left open.",
        "reached()\nprint(os.read(int('${INHERITED_FD}'), 4096).decode(), end='')\n",
        {"type": "fd-leak"},
    ),
)


def merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """Merge ``extra`` into a copy of ``base``: dicts recursively, lists appended."""
    merged = copy.deepcopy(base)
    for key, value in extra.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = merge(current, value)
        elif isinstance(current, list) and isinstance(value, list):
            merged[key] = current + value
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def build() -> dict[str, tuple[str, dict[str, Any]]]:
    """Return ``{case_id: (payload, case)}`` for every variant, refusing duplicates."""
    cases: dict[str, tuple[str, dict[str, Any]]] = {}
    seen: dict[str, str] = {}
    ordinals: dict[str, int] = {}
    for variant in VARIANTS:
        ordinals[variant.category] = ordinals.get(variant.category, 0) + 1
        case_id = f"{variant.category}-{ordinals[variant.category]:03}"
        mechanism, min_abi = ABI[variant.category]
        policy = merge(BASE_POLICY, variant.policy)
        key = json.dumps([variant.body, variant.oracle, policy], sort_keys=True)
        if key in seen:
            raise SystemExit(f"{case_id} duplicates {seen[key]}: same payload, oracle, and policy")
        seen[key] = case_id
        case: dict[str, Any] = {
            "id": case_id,
            "category": variant.category,
            "description": variant.description,
            "expect": {"verdict": "blocked", "mechanism": mechanism, "min_abi": min_abi},
            "policy": policy,
            "payload": {"file": f"{case_id}.py"},
            "oracle": variant.oracle,
        }
        if variant.requires:
            case["platforms"] = {"requires": list(variant.requires)}
        cases[case_id] = (BASE + variant.body, case)
    return cases


def main() -> int:
    cases = build()
    DEV.mkdir(parents=True, exist_ok=True)
    previous = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else []
    for name in previous:
        (DEV / name).unlink(missing_ok=True)
    written: list[str] = []
    for case_id, (payload, case) in cases.items():
        for name in (f"{case_id}.py", f"{case_id}.yaml"):
            target = DEV / name
            if target.exists() and name not in previous:
                raise SystemExit(f"refusing to overwrite hand-written {target}")
            written.append(name)
        (DEV / f"{case_id}.py").write_text(payload)
        (DEV / f"{case_id}.yaml").write_text(json.dumps(case, indent=2) + "\n")
    MANIFEST.write_text(json.dumps(sorted(written), indent=2) + "\n")
    sys.stdout.write(f"wrote {len(cases)} development cases to {DEV.relative_to(ROOT.parent)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
