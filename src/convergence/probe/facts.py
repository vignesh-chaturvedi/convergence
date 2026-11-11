"""Static facts about the host and the calling process. Nothing here is a live test."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _read_int(path: str) -> int | None:
    value = _read(path)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def parse_status(text: str) -> dict[str, str]:
    """Parse ``/proc/<pid>/status`` into a field -> value mapping."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def _os_pretty_name() -> str | None:
    text = _read("/etc/os-release")
    if text is None:
        return None
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def _container_hints() -> list[str]:
    hints: list[str] = []
    if Path("/.dockerenv").exists():
        hints.append("/.dockerenv exists")
    if Path("/run/.containerenv").exists():
        hints.append("/run/.containerenv exists")
    # systemd's container interface uses the lowercase variable name `container`.
    container = os.environ.get("container")  # noqa: SIM112
    if container:
        hints.append(f"container={container} in the environment")
    cgroup = _read("/proc/1/cgroup") or ""
    for marker in ("docker", "kubepods", "containerd", "lxc", "libpod"):
        if marker in cgroup:
            hints.append(f"/proc/1/cgroup mentions {marker}")
            break
    return hints


def _strace() -> tuple[str | None, str | None]:
    path = shutil.which("strace")
    if path is None:
        return None, None
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, resolved binary
            [path, "-V"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return path, None
    first = out.splitlines()[0].strip() if out else None
    return path, first


@dataclass(slots=True)
class HostFacts:
    platform: str
    system: str
    kernel_release: str
    kernel_version: str
    machine: str
    os_pretty_name: str | None
    lsm: list[str] | None
    uid: int
    euid: int
    gid: int
    effective_capabilities: str | None
    seccomp_mode: int | None
    seccomp_filters: int | None
    no_new_privs: bool | None
    yama_ptrace_scope: int | None
    unprivileged_userns_clone: int | None
    apparmor_restrict_unprivileged_userns: int | None
    python: str
    strace_path: str | None
    strace_version: str | None
    container_hints: list[str] = field(default_factory=list)

    @property
    def is_linux(self) -> bool:
        return self.platform == "linux"

    @property
    def has_effective_capabilities(self) -> bool:
        if self.effective_capabilities is None:
            return False
        try:
            return int(self.effective_capabilities, 16) != 0
        except ValueError:
            return False


def collect() -> HostFacts:
    uname = os.uname()
    status = parse_status(_read("/proc/self/status") or "")

    def status_int(key: str) -> int | None:
        try:
            return int(status[key])
        except (KeyError, ValueError):
            return None

    nnp = status_int("NoNewPrivs")
    lsm_text = _read("/sys/kernel/security/lsm")
    strace_path, strace_version = _strace()
    return HostFacts(
        platform=sys.platform,
        system=uname.sysname,
        kernel_release=uname.release,
        kernel_version=uname.version,
        machine=platform.machine(),
        os_pretty_name=_os_pretty_name(),
        lsm=[item for item in lsm_text.split(",") if item] if lsm_text else None,
        uid=os.getuid(),
        euid=os.geteuid(),
        gid=os.getgid(),
        effective_capabilities=status.get("CapEff"),
        seccomp_mode=status_int("Seccomp"),
        seccomp_filters=status_int("Seccomp_filters"),
        no_new_privs=None if nnp is None else nnp == 1,
        yama_ptrace_scope=_read_int("/proc/sys/kernel/yama/ptrace_scope"),
        unprivileged_userns_clone=_read_int("/proc/sys/kernel/unprivileged_userns_clone"),
        apparmor_restrict_unprivileged_userns=_read_int(
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
        ),
        python=platform.python_version(),
        strace_path=strace_path,
        strace_version=strace_version,
        container_hints=_container_hints(),
    )
