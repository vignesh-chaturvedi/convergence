"""Enforceability of policy rules at every Landlock ABI level (pure logic), plus the doctor
mapping. Live-kernel checks are in test_policy_cli.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from convergence.kernel import landlock as ll
from convergence.policy import enforce
from convergence.policy.enforce import Capabilities, Proof, Status
from convergence.policy.load import parse_policy
from convergence.policy.paths import Variables, resolve_all

ALL_ABIS = range(0, ll.KNOWN_MAX_ABI + 2)


def assess(text: str, abi: int, tmp_path: Path) -> enforce.Assessment:
    policy = parse_policy(text)
    paths = resolve_all(policy, Variables(home=str(tmp_path), cwd=str(tmp_path)))
    caps = (
        Capabilities.assumed(abi)
        if abi > 0
        else Capabilities(
            "none",
            None,
            {
                "seccomp_filter": Proof.ASSUMED,
                "no_new_privs": Proof.ASSUMED,
                "rlimits": Proof.ASSUMED,
            },
        )
    )
    return enforce.assess(policy, paths, caps)


def status(assessment: enforce.Assessment, rule_id: str) -> Status:
    found = [r for r in assessment.rules + assessment.baseline if r.id == rule_id]
    assert len(found) == 1, rule_id
    return found[0].status


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_filesystem_baseline(abi: int, tmp_path: Path) -> None:
    result = assess("version: 1\n", abi, tmp_path)
    assert status(result, "baseline.filesystem") is (
        Status.ENFORCED if abi >= 1 else Status.UNENFORCEABLE
    )
    assert status(result, "baseline.truncate") is (
        Status.ENFORCED if abi >= 3 else Status.UNENFORCEABLE
    )
    expected_refer = (
        Status.ENFORCED if abi >= 2 else Status.CAVEAT if abi == 1 else Status.UNENFORCEABLE
    )
    assert status(result, "baseline.refer") is expected_refer
    # A policy that grants nothing is still only fully enforceable from ABI 3 on.
    assert result.would_run is (abi >= 3)


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_signal_scoping_is_reported_but_never_blocks(abi: int, tmp_path: Path) -> None:
    result = assess("version: 1\n", abi, tmp_path)
    expected = Status.ENFORCED if abi >= 6 else Status.NOT_AVAILABLE
    assert status(result, "baseline.signals") is expected
    assert all(r.id != "baseline.signals" for r in result.blocking)


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_tcp_ports_need_abi_4(abi: int, tmp_path: Path) -> None:
    result = assess("version: 1\nnetwork:\n  tcp_connect: [443]\n", abi, tmp_path)
    expected = Status.ENFORCED if abi >= 4 else Status.UNENFORCEABLE
    assert status(result, "network.tcp_connect") is expected
    # Binding nothing while connecting is allowed also needs Landlock to tell them apart.
    assert status(result, "network.tcp_bind") is expected
    # UDP is not granted at all, so seccomp denies UDP sockets on any kernel.
    assert status(result, "network.udp_send") is Status.ENFORCED


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_udp_ports_need_abi_10(abi: int, tmp_path: Path) -> None:
    result = assess("version: 1\nnetwork:\n  udp_send: [53]\n", abi, tmp_path)
    expected = Status.ENFORCED if abi >= 10 else Status.UNENFORCEABLE
    assert status(result, "network.udp_send") is expected
    assert status(result, "network.tcp_connect") is Status.ENFORCED


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_no_network_is_enforced_by_seccomp_on_any_abi(abi: int, tmp_path: Path) -> None:
    result = assess("version: 1\n", abi, tmp_path)
    for rule in ("network.tcp_connect", "network.tcp_bind", "network.udp_send", "network.udp_bind"):
        assert status(result, rule) is Status.ENFORCED, rule


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_any_port_is_unrestricted_everywhere(abi: int, tmp_path: Path) -> None:
    result = assess("version: 1\nnetwork:\n  tcp_connect: any\n  tcp_bind: any\n", abi, tmp_path)
    assert status(result, "network.tcp_connect") is Status.ENFORCED
    assert status(result, "network.tcp_bind") is Status.ENFORCED


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_unix_socket_denial(abi: int, tmp_path: Path) -> None:
    result = assess("version: 1\n", abi, tmp_path)
    rule = next(r for r in result.rules if r.id == "network.unix_sockets")
    if abi >= 9:
        assert rule.status is Status.ENFORCED
        assert "RESOLVE_UNIX" in rule.mechanism
    else:
        # Falls back to denying unix socket creation: stricter than asked, never looser.
        assert rule.status is Status.CAVEAT
        assert "stricter than asked" in rule.detail


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_reading_devices_needs_abi_5_for_ioctl(abi: int, tmp_path: Path) -> None:
    result = assess(
        "version: 1\nfilesystem:\n  read: [/dev/null]\n  write: [/dev/zero]\n", abi, tmp_path
    )
    if abi == 0:
        assert status(result, "filesystem.read.0") is Status.UNENFORCEABLE
        return
    assert status(result, "filesystem.read.0") is (Status.ENFORCED if abi >= 5 else Status.PARTIAL)
    # Write grants include device ioctl, so nothing is missing for them on any ABI.
    assert status(result, "filesystem.write.0") is Status.ENFORCED


def test_rights_shown_match_the_kernel_abi(tmp_path: Path) -> None:
    (tmp_path / "work").mkdir()
    text = f"version: 1\nfilesystem:\n  write: [{tmp_path}/work]\n"
    old = next(r for r in assess(text, 1, tmp_path).rules if r.id == "filesystem.write.0")
    new = next(r for r in assess(text, 6, tmp_path).rules if r.id == "filesystem.write.0")
    for right in ("REFER", "TRUNCATE"):
        assert right not in old.detail
    for right in ("REFER", "TRUNCATE", "IOCTL_DEV"):
        assert right in new.detail
    for right in ("MAKE_CHAR", "RESOLVE_UNIX"):
        assert right not in new.detail


def test_file_rules_get_only_file_rights(tmp_path: Path) -> None:
    (tmp_path / "f").write_text("x")
    result = assess(f"version: 1\nfilesystem:\n  write: [{tmp_path}/f]\n", 6, tmp_path)
    rule = next(r for r in result.rules if r.id == "filesystem.write.0")
    assert "READ_DIR" not in rule.detail
    assert "MAKE_REG" not in rule.detail
    assert "WRITE_FILE" in rule.detail


def test_missing_paths(tmp_path: Path) -> None:
    text = (
        f"version: 1\nfilesystem:\n  read: [{tmp_path}/gone, "
        f"{{path: {tmp_path}/also-gone, optional: true}}]\n"
    )
    result = assess(text, 4, tmp_path)
    assert status(result, "filesystem.read.0") is Status.UNENFORCEABLE
    assert status(result, "filesystem.read.1") is Status.SKIPPED
    assert [r.id for r in result.blocking] == ["filesystem.read.0"]


def test_process_limit_carries_its_caveat(tmp_path: Path) -> None:
    result = assess("version: 1\n", 4, tmp_path)
    assert status(result, "resources.max_processes") is Status.CAVEAT
    assert status(result, "resources.cpu_seconds") is Status.ENFORCED
    result = assess("version: 1\nresources:\n  max_processes: null\n", 4, tmp_path)
    assert status(result, "resources.max_processes") is Status.ENFORCED


def test_without_seccomp_syscall_rules_are_unenforceable(tmp_path: Path) -> None:
    policy = parse_policy("version: 1\nsyscalls:\n  deny: [ptrace]\n")
    caps = Capabilities("test", 4, {"fs_access": Proof.VERIFIED, "fs_truncate": Proof.VERIFIED})
    result = enforce.assess(policy, [], caps)
    assert status(result, "syscalls.deny.0") is Status.UNENFORCEABLE
    assert status(result, "baseline.syscalls") is Status.UNENFORCEABLE
    assert not result.would_run


def test_abi_only_features_are_caveats_not_claims(tmp_path: Path) -> None:
    policy = parse_policy("version: 1\nnetwork:\n  udp_send: [53]\n")
    caps = Capabilities.assumed(10)
    features = dict(caps.features)
    features["net_udp"] = Proof.ABI_ONLY
    result = enforce.assess(policy, [], Capabilities("test", 10, features))
    rule = next(r for r in result.rules if r.id == "network.udp_send")
    assert rule.status is Status.CAVEAT
    assert "no live probe" in rule.detail


def test_json_lists_the_blocking_rules(tmp_path: Path) -> None:
    result = assess("version: 1\nnetwork:\n  udp_send: [53]\n", 4, tmp_path)
    data = json.loads(result.to_json())
    assert data["schema"] == "convergence.enforceability/1"
    assert data["runtime_implemented"] is True
    assert data["would_run_without_allow_degraded"] is False
    assert data["blocking_rules"] == ["network.udp_send", "network.udp_bind"]


def test_text_says_run_would_refuse(tmp_path: Path) -> None:
    text = enforce.render_text(assess("version: 1\nnetwork:\n  udp_send: [53]\n", 4, tmp_path))
    assert "--allow-degraded" in text
    assert "How `convergence run` enforces" in text


@pytest.mark.parametrize("abi", ALL_ABIS)
def test_metadata_gaps_are_reported_on_every_kernel(abi: int, tmp_path: Path) -> None:
    # Landlock cannot control stat/chmod/chown/setxattr/utime on any ABI; explain must say so.
    result = assess("version: 1\n", abi, tmp_path)
    for rule_id in ("baseline.metadata_reads", "baseline.metadata_changes"):
        assert status(result, rule_id) is Status.NOT_AVAILABLE
        assert all(r.id != rule_id for r in result.blocking)
