"""``convergence mcp``: Convergence's tools over the Model Context Protocol (ADR 0010).

Policies come from the operator: ``--policies DIR`` (the client names one), and only with
``--allow-inline-policy`` may the client send policy text. ``observe`` runs commands
unconfined and exists only with ``--allow-observe``. Every run goes through the
single-threaded spawn helper (``helper.py``), one at a time.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from convergence import __version__
from convergence.mcp.helper import Helper
from convergence.runtime.record import runs_dir

POLICY_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
RUN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
POLICY_SUFFIXES = ("", ".yaml", ".yml", ".json")
MAX_TIMEOUT = 24 * 60 * 60

INSTRUCTIONS = (
    "Run commands under a least-privilege Convergence policy chosen by the operator. "
    "run_sandboxed applies Landlock, seccomp, no_new_privs, and resource limits; commands "
    "are argv lists, never shell strings. check_policy shows how this kernel enforces a "
    "policy; explain_denials explains a traced run's denials and the smallest change that "
    "would permit each; generate_policy writes a policy from an observation."
)


@dataclass(slots=True)
class Config:
    policies: Path | None = None
    allow_inline_policy: bool = False
    allow_observe: bool = False
    allow_any_cwd: bool = False
    cwd: Path = field(default_factory=Path.cwd)

    def problems(self) -> list[str]:
        found = []
        if self.policies is None and not self.allow_inline_policy:
            found.append(
                "no policy source: pass --policies DIR, or --allow-inline-policy for trusted "
                "clients (no call may run without a policy)"
            )
        if self.policies is not None and not self.policies.is_dir():
            found.append(f"--policies {self.policies} is not a directory")
        return found


class Tools:
    """The tool implementations, separate from MCP so they are directly testable."""

    def __init__(self, config: Config, helper: Helper | None = None) -> None:
        self.config = config
        self._helper = helper
        self._lock = anyio.Lock()

    @property
    def helper(self) -> Helper:
        if self._helper is None:
            self._helper = Helper()
        return self._helper

    def close(self) -> None:
        if self._helper is not None:
            self._helper.close()

    # --- arguments ------------------------------------------------------------------------

    def policy_path(self, policy: str) -> Path:
        """A policy name from --policies, or (if allowed) policy text saved by its digest."""
        directory = self.config.policies
        if directory is not None and POLICY_NAME.fullmatch(policy):
            for suffix in POLICY_SUFFIXES:
                candidate = directory / f"{policy}{suffix}"
                if candidate.is_file():
                    return candidate
        looks_inline = "\n" in policy or policy.lstrip().startswith(("{", "version"))
        if looks_inline and self.config.allow_inline_policy:
            from convergence.policy.load import PolicyError, parse_policy

            try:
                parse_policy(policy, source="inline policy")
            except PolicyError as exc:
                raise ValueError(
                    "invalid policy: " + "; ".join(str(i) for i in exc.issues)
                ) from exc
            digest = hashlib.sha256(policy.encode()).hexdigest()
            target = runs_dir().parent / "policies" / f"{digest}.yaml"
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not target.exists():
                target.write_text(policy)
            return target
        if looks_inline:
            raise ValueError(
                "this server does not accept policy text (it was started without "
                "--allow-inline-policy); name a policy from its --policies directory"
            )
        names = self.policy_names()
        raise ValueError(
            f"no policy named {policy!r}" + (f"; available: {', '.join(names)}" if names else "")
        )

    def policy_names(self) -> list[str]:
        directory = self.config.policies
        if directory is None:
            return []
        return sorted(p.stem for p in directory.iterdir() if p.suffix in (".yaml", ".yml", ".json"))

    def cwd(self, cwd: str | None) -> str:
        """Where the command runs. ``${CWD}`` in a policy follows it.

        So a client that could name any directory could move the operator's ``${CWD}``
        grants onto it. Unless the operator allows that, the directory must be the server's
        own or one beneath it, after resolving symbolic links.
        """
        root = self.config.cwd.resolve()
        if cwd is None:
            return str(root)
        path = Path(cwd)
        if not path.is_absolute() or not path.is_dir():
            raise ValueError("cwd must be an existing absolute directory")
        resolved = path.resolve()
        if not self.config.allow_any_cwd and resolved != root and root not in resolved.parents:
            raise ValueError(
                f"cwd must be {root} or a directory beneath it: ${{CWD}} in a policy follows "
                "cwd, and this server was not started with --allow-any-cwd"
            )
        return str(resolved)

    @staticmethod
    def command(command: list[str]) -> list[str]:
        if not command or not all(isinstance(a, str) for a in command):
            raise ValueError("command must be a non-empty list of strings (argv, no shell)")
        return command

    @staticmethod
    def timeout(timeout_s: float | None) -> float | None:
        if timeout_s is None:
            return None
        if not 0 < timeout_s <= MAX_TIMEOUT:
            raise ValueError(f"timeout_s must be between 0 and {MAX_TIMEOUT}")
        return float(timeout_s)

    # --- tools ----------------------------------------------------------------------------

    async def run_sandboxed(
        self,
        command: list[str],
        policy: str,
        timeout_s: float | None = None,
        cwd: str | None = None,
        trace: bool = False,
    ) -> dict[str, Any]:
        request = {
            "op": "run",
            "command": self.command(command),
            "policy_path": str(self.policy_path(policy)),
            "cwd": self.cwd(cwd),
            "timeout": self.timeout(timeout_s),
            "trace": bool(trace),
        }
        async with self._lock:
            answer = await anyio.to_thread.run_sync(self.helper.call, request)
        record = answer["record"]
        outcome = record["outcome"]
        return {
            "run_id": record["id"],
            "status": outcome["status"],
            "exit_code": outcome["exit_code"],
            "signal": outcome["signal"],
            "convergence_exit_code": outcome["convergence_exit_code"],
            "left_running": outcome["left_running"],
            "error": outcome["error"],
            "stdout": record["stdout"]["kept"],
            "stdout_truncated": record["stdout"]["truncated"],
            "stderr": record["stderr"]["kept"],
            "stderr_truncated": record["stderr"]["truncated"],
            "denials": record["denials"],
            "tracing": record["tracing"],
            "degraded": record["degraded"],
            "duration_seconds": record["duration_seconds"],
        }

    def check_policy(self, policy: str) -> dict[str, Any]:
        from convergence.policy import enforce
        from convergence.policy.load import load_policy
        from convergence.policy.paths import Variables, resolve_all

        path = self.policy_path(policy)
        loaded = load_policy(path)
        assessment = enforce.assess(
            loaded,
            resolve_all(loaded, Variables.from_environment(str(self.config.cwd))),
            enforce.Capabilities.from_kernel(),
        )
        assessment.source = path.name
        result: dict[str, Any] = json.loads(assessment.to_json())
        return result

    def generate_policy(self, observation: str) -> dict[str, Any]:
        from convergence.generate.policy import generate, render
        from convergence.observe.model import adapter, load

        text = observation.strip()
        if text.startswith("{"):
            parsed = adapter().validate_json(text)
        elif RUN_ID.fullmatch(text):
            parsed = load(runs_dir().parent / "observations" / f"{text}.json")
        else:
            raise ValueError("observation must be observation JSON or the id of a saved one")
        generated = generate(parsed)
        return {
            "policy": render(generated),
            "rationale": json.loads(generated.rationale_json()),
            "warnings": generated.warnings,
        }

    def explain_denials(self, run_id: str) -> dict[str, Any]:
        from convergence.generate.explain import explain_run, find_record, load_record
        from convergence.policy.load import PolicyError, load_policy

        if not RUN_ID.fullmatch(run_id):
            raise ValueError("run_id is not a run id")
        record = load_record(find_record(run_id, runs_dir()))
        try:
            policy = load_policy(record.policy.path)
        except (OSError, PolicyError):
            policy = None
        explanations = explain_run(record, policy)
        return {
            "run_id": record.id,
            "traced": record.tracing.active,
            "explanations": [asdict(e) for e in explanations],
            "note": (
                ""
                if record.tracing.active
                else "this run was not traced; run it again with trace=true to see denials"
            ),
        }

    async def observe(
        self, command: list[str], cwd: str | None = None, timeout_s: float | None = None
    ) -> dict[str, Any]:
        if not self.config.allow_observe:
            raise ValueError("observe is disabled (start the server with --allow-observe)")
        request = {
            "op": "observe",
            "command": self.command(command),
            "cwd": self.cwd(cwd),
            "timeout": self.timeout(timeout_s) or 60.0,
        }
        async with self._lock:
            answer = await anyio.to_thread.run_sync(self.helper.call, request)
        observation = answer["observation"]
        return {
            "observation_id": observation["id"],
            "complete": observation["complete"],
            "events": len(observation["events"]),
            "exit_code": answer["exit_code"],
            "warning": "observe ran the command UNCONFINED, with the server's full access",
        }


class _Refused(ToolError):
    """A refusal the client should read: bad arguments, an unknown policy, a failed run."""


def _guard(error: Exception) -> ToolError:
    return _Refused(str(error))


def build_server(tools: Tools) -> MCPServer:
    server: MCPServer = MCPServer("convergence", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(
        description=(
            "Run a command under a Convergence policy. command is an argv list (no shell). "
            "policy names one of the server's policies (or is policy text, if the server "
            "allows it). Returns the exit status, captured output (64 KiB per stream), and, "
            "with trace=true, every denial and the rule behind it."
        )
    )
    async def run_sandboxed(
        command: list[str],
        policy: str,
        timeout_s: float | None = None,
        cwd: str | None = None,
        trace: bool = False,
    ) -> dict[str, Any]:
        try:
            return await tools.run_sandboxed(command, policy, timeout_s, cwd, trace)
        except (ValueError, RuntimeError, OSError) as exc:
            raise _guard(exc) from exc

    @server.tool(
        description=(
            "Show how this kernel enforces each rule of a policy, and whether run_sandboxed "
            "would refuse it as not fully enforceable."
        )
    )
    def check_policy(policy: str) -> dict[str, Any]:
        try:
            return tools.check_policy(policy)
        except (ValueError, OSError) as exc:
            raise _guard(exc) from exc

    @server.tool(
        description=(
            "Write the smallest policy for an observation (observation JSON, or the id of a "
            "saved observation), with the reason and events behind every rule."
        )
    )
    def generate_policy(observation: str) -> dict[str, Any]:
        try:
            return tools.generate_policy(observation)
        except (ValueError, OSError) as exc:
            raise _guard(exc) from exc

    @server.tool(
        description=(
            "For each denial of a traced run: the cause, the rule that blocked it, the "
            "smallest policy change that would permit it (a YAML diff), and its risk. "
            "Nothing is changed."
        )
    )
    def explain_denials(run_id: str) -> dict[str, Any]:
        try:
            return tools.explain_denials(run_id)
        except (ValueError, OSError) as exc:
            raise _guard(exc) from exc

    if tools.config.allow_observe:

        @server.tool(
            description=(
                "Run a command UNCONFINED under strace and save what it did, for "
                "generate_policy. Not a sandbox."
            )
        )
        async def observe(
            command: list[str], cwd: str | None = None, timeout_s: float | None = None
        ) -> dict[str, Any]:
            try:
                return await tools.observe(command, cwd, timeout_s)
            except (ValueError, RuntimeError, OSError) as exc:
                raise _guard(exc) from exc

    return server


def main(config: Config) -> int:
    import sys

    problems = config.problems()
    if problems:
        for problem in problems:
            sys.stderr.write(f"convergence mcp: {problem}\n")
        return 2
    if config.allow_inline_policy:
        sys.stderr.write(
            "convergence mcp: --allow-inline-policy: clients may send their own policies\n"
        )
    if config.allow_observe:
        sys.stderr.write("convergence mcp: --allow-observe: observe runs commands UNCONFINED\n")
    if config.allow_any_cwd:
        sys.stderr.write(
            "convergence mcp: --allow-any-cwd: clients choose the directory ${CWD} stands for\n"
        )
    tools = Tools(config, Helper())  # the helper starts before the event loop and its threads
    try:
        anyio.run(build_server(tools).run_stdio_async)
    finally:
        tools.close()
    return 0
