"""validate and explain end to end, on the real kernel."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from convergence.kernel import landlock as ll

pytestmark = pytest.mark.kernel

EXAMPLES = Path(__file__).parent.parent / "examples" / "policies"


def cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "convergence", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_validate_examples() -> None:
    for example in sorted(EXAMPLES.glob("*.yaml")):
        result = cli("validate", str(example))
        assert result.returncode == 0, result.stdout + result.stderr
        assert ": valid" in result.stdout


def test_validate_invalid_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nfilesystem:\n  read: [relative]\n")
    result = cli("validate", str(bad), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["valid"] is False
    assert data["findings"][0]["location"] == "filesystem.read.0"


def test_explain_offline_policy_is_fully_enforceable_here() -> None:
    result = cli("explain", "--policy", str(EXAMPLES / "python-offline.yaml"), "--json")
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data["capabilities"].startswith("live probes")
    assert data["landlock_abi"] == ll.abi_version()
    assert data["would_run_without_allow_degraded"] is True


def test_explain_udp_ports_depend_on_the_kernel() -> None:
    result = cli("explain", "--policy", str(EXAMPLES / "https-client.yaml"), "--json")
    data = json.loads(result.stdout)
    udp = next(r for r in data["rules"] if r["id"] == "network.udp_send")
    if ll.abi_version() >= 10:
        assert udp["status"] in ("enforced", "enforced-with-caveat")
    else:
        assert udp["status"] == "unenforceable"
        assert result.returncode == 3
        assert "network.udp_send" in data["blocking_rules"]


def test_explain_assume_abi() -> None:
    policy = str(EXAMPLES / "https-client.yaml")
    old = json.loads(cli("explain", "--policy", policy, "--assume-abi", "4", "--json").stdout)
    new = cli("explain", "--policy", policy, "--assume-abi", "10", "--json")
    assert old["would_run_without_allow_degraded"] is False
    assert new.returncode == 0
    assert "not checked on a real kernel" in json.loads(new.stdout)["capabilities"]


def test_explain_invalid_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n")
    result = cli("explain", "--policy", str(bad))
    assert result.returncode == 1
    assert "unsupported policy version 2" in result.stderr


def test_explain_run_is_not_implemented_yet() -> None:
    result = cli("explain", "--run", "abc")
    assert result.returncode == 2
    assert "Phase 5" in result.stderr
