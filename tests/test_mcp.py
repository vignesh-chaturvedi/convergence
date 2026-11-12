"""``convergence mcp`` (ADR 0010): in memory, over stdio, and on a subset of the escape matrix."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

from convergence.mcp.server import Config, Tools, build_server
from escape.launchers import MCPLauncher
from escape.oracles.execution import find_loader
from escape.runner import SETS, Runner
from escape.schema import load_case
from escape.score import Result

PYTHON = str(Path(shutil.which("python3", path="/usr/bin:/bin") or "/usr/bin/python3").resolve())


def policy_text(work: Path) -> str:
    execute: list[Any] = [PYTHON]
    loader = find_loader()
    if loader:
        execute.append(loader)
    return json.dumps(
        {
            "version": 1,
            "filesystem": {
                "read": ["/usr", "/etc/ld.so.cache", str(work)],
                "write": ["${SCRATCH}", "/dev/null"],
                "execute": execute,
            },
            "resources": {"wall_clock_seconds": 20},
            "environment": {"set": {"PATH": "/usr/bin", "LANG": "C.UTF-8"}},
        }
    )


@pytest.fixture
def setup(tmp_path: Path) -> tuple[Path, Path, Path]:
    policies, work = tmp_path / "policies", tmp_path / "work"
    policies.mkdir()
    work.mkdir()
    (work / "in.txt").write_text("hello")
    (tmp_path / "outside.txt").write_text("secret")
    (policies / "py.json").write_text(policy_text(work))
    return policies, work, tmp_path / "outside.txt"


async def call(tools: Tools, name: str, arguments: dict[str, Any]) -> Any:
    async with Client(build_server(tools)) as client:
        return await client.call_tool(name, arguments)


def test_the_server_needs_a_policy_source() -> None:
    assert Config().problems()
    assert not Config(allow_inline_policy=True).problems()


def test_observe_is_only_listed_when_allowed(setup: tuple[Path, Path, Path]) -> None:
    async def names(config: Config) -> list[str]:
        async with Client(build_server(Tools(config))) as client:
            return [t.name for t in (await client.list_tools()).tools]

    policies = setup[0]
    base = ["run_sandboxed", "check_policy", "generate_policy", "explain_denials"]
    assert anyio.run(names, Config(policies=policies)) == base
    assert anyio.run(names, Config(policies=policies, allow_observe=True)) == [*base, "observe"]


def test_refusals_reach_the_client(setup: tuple[Path, Path, Path]) -> None:
    policies, work, _ = setup
    tools = Tools(Config(policies=policies, cwd=work))
    true = ["/bin/true"]
    cases: list[tuple[str, dict[str, Any], str]] = [
        (
            "run_sandboxed",
            {"command": true, "policy": "nope"},
            "no policy named 'nope'; available: py",
        ),
        (
            "run_sandboxed",
            {"command": true, "policy": "version: 1\n"},
            "does not accept policy text",
        ),
        ("run_sandboxed", {"command": [], "policy": "py"}, "non-empty list of strings"),
        ("run_sandboxed", {"command": true, "policy": "py", "cwd": "rel"}, "absolute directory"),
        ("generate_policy", {"observation": "/etc/passwd"}, "observation JSON or the id"),
        ("explain_denials", {"run_id": "../../x"}, "not a run id"),
    ]
    for name, arguments, message in cases:
        result = anyio.run(call, tools, name, arguments)
        assert result.is_error, (name, arguments)
        assert message in result.content[0].text


@pytest.mark.kernel
def test_run_and_check_in_memory(setup: tuple[Path, Path, Path]) -> None:
    policies, work, outside = setup
    tools = Tools(Config(policies=policies, cwd=work))
    try:
        ok = anyio.run(
            call,
            tools,
            "run_sandboxed",
            {"command": [PYTHON, "-c", "print(open('in.txt').read())"], "policy": "py"},
        )
        assert ok.structured_content["exit_code"] == 0
        assert ok.structured_content["stdout"] == "hello\n"
        denied = anyio.run(
            call,
            tools,
            "run_sandboxed",
            {"command": [PYTHON, "-c", f"open({str(outside)!r}).read()"], "policy": "py"},
        )
        assert denied.structured_content["exit_code"] == 1
        assert "Permission denied" in denied.structured_content["stderr"]
        checked = anyio.run(call, tools, "check_policy", {"policy": "py"})
        assert checked.structured_content["would_run_without_allow_degraded"] is True
    finally:
        tools.close()


def test_generate_policy_from_observation_json(tmp_path: Path) -> None:
    observation = {
        "id": "o1",
        "created_at": "2026-11-12T00:00:00Z",
        "source": "strace",
        "command": ["tool"],
        "cwd": str(tmp_path),
        "home": None,
        "complete": True,
        "events": [{"id": "e1", "kind": "file", "op": "read", "path": "/etc/hostname"}],
    }
    tools = Tools(Config(allow_inline_policy=True))
    result = anyio.run(call, tools, "generate_policy", {"observation": json.dumps(observation)})
    assert '- "/etc/hostname"' in result.structured_content["policy"]
    assert result.structured_content["rationale"]["schema"] == "convergence.rationale/1"


@pytest.mark.kernel
def test_stdio_end_to_end_with_trace_and_explain(setup: tuple[Path, Path, Path]) -> None:
    policies, work, outside = setup

    async def main() -> tuple[Any, Any]:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "convergence", "mcp", "--policies", str(policies)],
            cwd=str(work),
        )
        async with Client(params) as client:
            run = await client.call_tool(
                "run_sandboxed",
                {
                    "command": [PYTHON, "-c", f"open({str(outside)!r})"],
                    "policy": "py",
                    "trace": True,
                },
            )
            explained = await client.call_tool(
                "explain_denials", {"run_id": run.structured_content["run_id"]}
            )
        return run, explained

    run, explained = anyio.run(main)
    assert run.structured_content["exit_code"] == 1
    if run.structured_content["tracing"]["active"]:
        rules = [e["rule"] for e in explained.structured_content["explanations"]]
        assert f"no grant in filesystem.read covers {outside}" in rules


MCP_SUBSET = (
    "filesystem-read-001",
    "filesystem-write-001",
    "exec-disallowed-001",
    "net-tcp-connect-001",
    "mount-namespace-001",
    "persist-setsid-doublefork-001",
    "env-leak-001",
    "fd-leak-001",
)


@pytest.mark.kernel
@pytest.mark.parametrize("case_id", MCP_SUBSET)
def test_escape_subset_through_the_mcp_path(case_id: str) -> None:
    path = SETS["dev"] / f"{case_id}.yaml"
    result = Runner(MCPLauncher(), subreaper=False).run_case(path, load_case(path), "dev")
    assert result.result in (Result.PASS, Result.NOT_TESTABLE), (result.result, result.evidence)
