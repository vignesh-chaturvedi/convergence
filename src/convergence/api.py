"""Running sandboxed commands from Python, in a warm process.

    from convergence.api import Sandbox

    with Sandbox() as sandbox:
        record = sandbox.run(["python3", "tool.py"], policy="policy.yaml", cwd="/work")
        print(record["outcome"]["exit_code"], record["stdout"]["kept"])

``Sandbox`` starts the single-threaded spawn helper once (ADR 0010). Each ``run`` forks a
worker from it, applies the policy, and supervises the command with its output captured.
So a call costs a fork and sandbox setup, not an interpreter startup. Calls are made one at
a time. The return value is the run record (``convergence.run/1``) as a dictionary, also
saved under ``$XDG_STATE_HOME/convergence/runs/``.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import TracebackType
from typing import Any

from convergence.mcp.helper import Helper


class Sandbox:
    def __init__(self) -> None:
        self._helper: Helper | None = Helper()

    def run(
        self,
        command: list[str],
        policy: str | os.PathLike[str],
        *,
        cwd: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
        trace: bool = False,
    ) -> dict[str, Any]:
        """Run ``command`` (an argv list, never a shell string) under the policy file."""
        if self._helper is None:
            raise RuntimeError("this Sandbox is closed")
        if not command or not all(isinstance(a, str) for a in command):
            raise ValueError("command must be a non-empty list of strings")
        policy_path = Path(policy).resolve()
        if not policy_path.is_file():
            raise FileNotFoundError(f"no policy file at {policy_path}")
        answer = self._helper.call(
            {
                "op": "run",
                "command": list(command),
                "policy_path": str(policy_path),
                "cwd": str(Path(cwd).resolve()) if cwd is not None else os.getcwd(),
                "timeout": timeout,
                "trace": trace,
            }
        )
        record: dict[str, Any] = answer["record"]
        return record

    def close(self) -> None:
        if self._helper is not None:
            self._helper.close()
            self._helper = None

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
