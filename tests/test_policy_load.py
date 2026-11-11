"""Parsing policies: strict schema, no coercion, no YAML surprises (pure logic)."""

from __future__ import annotations

from pathlib import Path

import pytest

from convergence.policy.load import (
    MAX_POLICY_BYTES,
    PolicyError,
    dump_policy,
    load_policy,
    parse_policy,
)
from convergence.policy.model import PathRule, Policy

EXAMPLES = sorted(Path(__file__).parent.parent.joinpath("examples", "policies").glob("*.yaml"))


def issues(text: str) -> list[str]:
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    return [str(i) for i in exc.value.issues]


def test_minimal_policy_denies_everything_by_default() -> None:
    policy = parse_policy("version: 1\n")
    assert policy.filesystem.read == ()
    assert policy.filesystem.write == ()
    assert policy.filesystem.execute == ()
    assert not policy.network.any_ip
    assert policy.network.unix_sockets == "deny"
    assert policy.syscalls.mode == "deny-list"
    assert policy.environment.pass_ == ()
    assert policy.environment.set == {}


def test_path_entries_accept_strings_and_objects() -> None:
    policy = parse_policy(
        "version: 1\nfilesystem:\n  read: [/usr, {path: /opt/tool, optional: true}]\n"
    )
    assert policy.filesystem.rules("read") == (
        PathRule(path="/usr"),
        PathRule(path="/opt/tool", optional=True),
    )


def test_json_is_accepted() -> None:
    policy = parse_policy('{"version": 1, "network": {"tcp_connect": [443]}}')
    assert policy.network.tcp_connect == (443,)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("version: 1\nfilesystem:\n  write: [/tmp]\nfilesystem:\n  write: [/]\n", "duplicate key"),
        ("version: 1\nx: &a [1]\ny: *a\n", "not allowed in policies"),
        ("version: 1\nx: &a [1]\n", "anchors are not allowed"),
        ("version: 1\nnetwork:\n  tcp_connect: ['443']\n", "valid integer"),
        ("version: 1\nnetwork:\n  tcp_connect: [true]\n", "valid integer"),
        ("version: 1\nnetwork:\n  tcp_connect: [443.0]\n", "valid integer"),
        ("version: 1\nnetwork:\n  tcp_connect: [70000]\n", "less than or equal to 65535"),
        ("version: 1\nnetwork:\n  tcp_connect: [0]\n", "port 0 is not a valid remote port"),
        ("version: 1\nnetwork:\n  tcp_connect: all\n", "'any'"),
        ("version: 1\nnetwork:\n  unix_sockets: yes\n", "'deny' or 'allow'"),
        ("version: true\n", "valid integer"),
        ("version: 2\n", "unsupported policy version 2"),
        ("name: x\n", "version: Field required"),
        ("version: 1\nnetwrok: {}\n", "netwrok: unknown key"),
        ("version: 1\nfilesystem:\n  read: [{path: /x, opt: true}]\n", "opt: unknown key"),
        ("version: 1\nfilesystem:\n  read: [usr/lib]\n", "must be absolute"),
        ("version: 1\nfilesystem:\n  read: [/usr/../etc]\n", "must not contain '..'"),
        ("version: 1\nfilesystem:\n  read: ['${USER}/x']\n", "unknown variable ${USER}"),
        ("version: 1\nfilesystem:\n  read: ['/x/${HOME}']\n", "only appear at the start"),
        ("version: 1\nfilesystem:\n  read: ['${HOME}x']\n", "must continue with /"),
        ("version: 1\nsyscalls:\n  mode: allow-list\n", "non-empty 'allow' list"),
        ("version: 1\nsyscalls:\n  allow: [read]\n", "only used with mode: allow-list"),
        ("version: 1\nsyscalls:\n  deny: [Bad-Name]\n", "not a syscall name"),
        ("version: 1\nenvironment:\n  pass: [PATH]\n  set: {PATH: /bin}\n", "both passed and set"),
        ("version: 1\nenvironment:\n  pass: ['1BAD']\n", "not an environment variable name"),
        ("version: 1\nresources:\n  wall_clock_seconds: 0\n", "greater than 0"),
        ("version: 1\nresources:\n  cpu_seconds: .nan\n", "not plain data"),
        ("version: 1\nname: 2026-01-01\n", "not plain data"),
        ("- 1\n", "must be a mapping"),
        ("", "policy is empty"),
        ("version: [1\n", "not valid YAML/JSON"),
    ],
)
def test_rejected(text: str, fragment: str) -> None:
    found = issues(text)
    assert any(fragment in issue for issue in found), found


def test_errors_point_at_the_offending_entry() -> None:
    found = issues("version: 1\nfilesystem:\n  read: [/ok, rel, {path: also-rel}]\n")
    assert found[0].startswith("filesystem.read.1:")
    assert found[1].startswith("filesystem.read.2.path:")
    # No noise from the other branch of the "string or object" union.
    assert len(found) == 2


def test_every_problem_is_reported_at_once() -> None:
    found = issues("version: 1\nnetwork:\n  tcp_connect: [0]\nresources:\n  cpu_seconds: -1\n")
    assert len(found) == 2


def test_oversized_policy_is_refused() -> None:
    assert any("larger than" in i for i in issues("version: 1\n#" + "x" * MAX_POLICY_BYTES))


def test_load_policy_reports_unreadable_and_non_utf8_files(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read policy"):
        load_policy(tmp_path / "missing.yaml")
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"version: 1\nname: \xff\n")
    with pytest.raises(PolicyError, match="not UTF-8"):
        load_policy(binary)


def test_dump_round_trips_with_defaults_made_explicit() -> None:
    policy = parse_policy(
        "version: 1\nnetwork:\n  tcp_connect: [443]\nenvironment:\n  pass: [LANG]\n"
    )
    text = dump_policy(policy)
    assert "wall_clock_seconds: 60" in text
    assert "pass:" in text
    assert parse_policy(text) == policy


def test_policy_is_immutable() -> None:
    policy = parse_policy("version: 1\n")
    with pytest.raises(Exception, match="frozen"):
        policy.version = 2


@pytest.mark.parametrize("example", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_examples_parse(example: Path) -> None:
    assert isinstance(load_policy(example), Policy)
