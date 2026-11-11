"""Host checks and risky-grant warnings. Uses real temporary files; syscall checks use the
real libseccomp and so are marked ``kernel``."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from convergence.policy.load import parse_policy
from convergence.policy.paths import PathKind, Variables, resolve_all
from convergence.policy.validate import Severity, validate_file, validate_policy


def check(text: str, tmp_path: Path, home: Path | None = None) -> list[tuple[str, str, str]]:
    variables = Variables(home=str(home or tmp_path / "home"), cwd=str(tmp_path))
    report = validate_policy(parse_policy(text), "test", variables)
    return [(f.severity.value, f.location, f.message) for f in report.findings]


def has(findings: list[tuple[str, str, str]], severity: str, location: str, fragment: str) -> bool:
    return any(s == severity and loc == location and fragment in m for s, loc, m in findings)


def test_missing_required_path_is_an_error(tmp_path: Path) -> None:
    findings = check(f"version: 1\nfilesystem:\n  read: [{tmp_path}/nope]\n", tmp_path)
    assert has(findings, "error", "filesystem.read.0", "does not exist")


def test_missing_write_path_explains_landlock_needs_existing_paths(tmp_path: Path) -> None:
    findings = check(f"version: 1\nfilesystem:\n  write: [{tmp_path}/out.txt]\n", tmp_path)
    assert has(findings, "error", "filesystem.write.0", "grant write on its parent directory")


def test_missing_optional_path_is_a_note(tmp_path: Path) -> None:
    text = f"version: 1\nfilesystem:\n  read: [{{path: {tmp_path}/nope, optional: true}}]\n"
    findings = check(text, tmp_path)
    assert has(findings, "note", "filesystem.read.0", "skipped (optional)")
    assert not any(s == "error" for s, _, _ in findings)


def test_symlink_target_is_reported(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    findings = check(f"version: 1\nfilesystem:\n  read: [{tmp_path}/link]\n", tmp_path)
    assert has(findings, "note", "filesystem.read.0", f"applies to {tmp_path}/real")


def test_whole_filesystem_grant_warns() -> None:
    report = validate_policy(parse_policy("version: 1\nfilesystem:\n  read: [/]\n"), "t")
    assert any("entire filesystem" in f.message for f in report.warnings)


def test_home_and_credentials_warn(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / "project").mkdir()
    findings = check(f"version: 1\nfilesystem:\n  read: [{home}]\n", tmp_path, home)
    assert has(findings, "warning", "filesystem.read.0", "includes your home directory")
    findings = check(f"version: 1\nfilesystem:\n  read: [{home}/.ssh]\n", tmp_path, home)
    assert has(findings, "warning", "filesystem.read.0", "credentials")
    findings = check(f"version: 1\nfilesystem:\n  read: [{home}/project]\n", tmp_path, home)
    assert not any(s == "warning" for s, _, _ in findings)


def test_credential_warning_only_for_credentials_that_exist(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "work").mkdir(parents=True)
    findings = check(f"version: 1\nfilesystem:\n  read: [{home}/work]\n", tmp_path, home)
    assert not any("credentials" in m for _, _, m in findings)


def test_proc_warns_but_proc_self_is_a_note(tmp_path: Path) -> None:
    findings = check("version: 1\nfilesystem:\n  read: [/proc]\n", tmp_path)
    assert has(findings, "warning", "filesystem.read.0", "other processes' command lines")
    findings = check("version: 1\nfilesystem:\n  read: [/proc/self]\n", tmp_path)
    assert has(findings, "note", "filesystem.read.0", "covers that process only")
    assert not any(s == "warning" for s, _, _ in findings)


def test_whole_dev_warns(tmp_path: Path) -> None:
    findings = check("version: 1\nfilesystem:\n  write: [/dev]\n", tmp_path)
    assert has(findings, "warning", "filesystem.write.0", "every device in /dev")


def test_scratch_subpaths_are_errors(tmp_path: Path) -> None:
    findings = check("version: 1\nfilesystem:\n  write: ['${SCRATCH}/out']\n", tmp_path)
    assert has(findings, "error", "filesystem.write.0", "only ${SCRATCH} itself")
    ok = check("version: 1\nfilesystem:\n  write: ['${SCRATCH}']\n", tmp_path)
    assert not any(s == "error" for s, _, _ in ok)


def test_variables_expand(tmp_path: Path) -> None:
    (tmp_path / "home" / "data").mkdir(parents=True)
    policy = parse_policy("version: 1\nfilesystem:\n  read: ['${HOME}/data', '${CWD}']\n")
    paths = resolve_all(policy, Variables(home=str(tmp_path / "home"), cwd=str(tmp_path)))
    assert [p.real for p in paths] == [str(tmp_path / "home" / "data"), str(tmp_path)]
    assert all(p.kind is PathKind.DIRECTORY for p in paths)


def test_unknown_home_is_an_error(tmp_path: Path) -> None:
    policy = parse_policy("version: 1\nfilesystem:\n  read: ['${HOME}']\n")
    report = validate_policy(policy, "t", Variables(home=None, cwd=str(tmp_path)))
    assert any("${HOME} is not known here" in f.message for f in report.errors)


def test_duplicates_warn(tmp_path: Path) -> None:
    findings = check(f"version: 1\nfilesystem:\n  read: [{tmp_path}, {tmp_path}]\n", tmp_path)
    assert has(findings, "warning", "filesystem.read.1", "duplicate of filesystem.read.0")


def test_network_warnings_and_notes(tmp_path: Path) -> None:
    findings = check("version: 1\nnetwork:\n  tcp_connect: any\n  unix_sockets: allow\n", tmp_path)
    assert has(findings, "warning", "network.tcp_connect", "any port on any host")
    assert has(findings, "warning", "network.unix_sockets", "host services")
    findings = check("version: 1\nnetwork:\n  tcp_connect: [443]\n", tmp_path)
    assert has(findings, "note", "network.tcp_connect", "not by host or IP address")


def test_environment_findings(tmp_path: Path) -> None:
    findings = check(
        "version: 1\nenvironment:\n  pass: [GITHUB_TOKEN]\n  set: {AWS_SECRET_ACCESS_KEY: x}\n",
        tmp_path,
    )
    assert has(findings, "warning", "environment.pass.0", "looks like a secret")
    assert has(findings, "warning", "environment.set.AWS_SECRET_ACCESS_KEY", "looks like a secret")
    assert has(findings, "note", "environment", "PATH is neither passed nor set")


def test_schema_errors_become_findings(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nnetwrok: {}\n")
    report = validate_file(bad)
    assert not report.valid
    assert [(f.severity, f.location) for f in report.findings] == [(Severity.ERROR, "netwrok")]


@pytest.mark.kernel
def test_syscall_names_are_checked_with_libseccomp(tmp_path: Path) -> None:
    findings = check("version: 1\nsyscalls:\n  deny: [openat, not_a_syscall]\n", tmp_path)
    assert has(findings, "error", "syscalls.deny.1", "does not know the syscall 'not_a_syscall'")
    assert not any(loc == "syscalls.deny.0" for _, loc, _ in findings)


@pytest.mark.kernel
def test_other_architecture_syscalls_are_notes(tmp_path: Path) -> None:
    other = "open" if os.uname().machine == "aarch64" else "arm_fadvise64_64"
    findings = check(f"version: 1\nsyscalls:\n  deny: [{other}]\n", tmp_path)
    assert has(findings, "note", "syscalls.deny.0", "does not exist on this architecture")


@pytest.mark.kernel
def test_allow_list_missing_essentials_warns(tmp_path: Path) -> None:
    findings = check(
        "version: 1\nsyscalls:\n  mode: allow-list\n  allow: [read, ptrace]\n", tmp_path
    )
    assert has(findings, "warning", "syscalls.allow", "cannot start or exit")
    assert has(findings, "note", "syscalls.allow.1", "always denied by the built-in deny list")
