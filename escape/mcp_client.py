"""Run one escape case through ``convergence mcp`` (the MCP path of the escape matrix).

    python -m escape.mcp_client --policy FILE -- ARGV...

Starts ``convergence mcp --allow-inline-policy`` over stdio with the SDK client, calls
``run_sandboxed`` with the case's policy and argv in the current directory, then writes the
tool's captured output to its own stdout and stderr and exits with the tool's status. To
the escape runner it looks like any other launcher process.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import anyio
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters


async def _call(policy: str, command: list[str]) -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "convergence", "mcp", "--allow-inline-policy"],
        cwd=os.getcwd(),
    )
    async with Client(params) as client:
        result = await client.call_tool(
            "run_sandboxed", {"command": command, "policy": policy, "cwd": os.getcwd()}
        )
    if result.is_error or result.structured_content is None:
        sys.stderr.write(f"mcp_client: {result.content}\n")
        return 125
    data = result.structured_content
    sys.stdout.write(data["stdout"])
    sys.stderr.write(data["stderr"])
    sys.stdout.flush()
    if data["exit_code"] is not None:
        return int(data["exit_code"])
    return int(data["convergence_exit_code"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m escape.mcp_client")
    parser.add_argument("--policy", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    code: int = anyio.run(_call, Path(args.policy).read_text(), command)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
