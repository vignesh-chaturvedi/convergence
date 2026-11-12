"""The spawn helper behind ``convergence mcp`` (ADR 0010).

A fresh, single-threaded interpreter started once with the server. It reads JSON requests,
one per line, on stdin and answers on stdout. For each request it forks a worker:
- the worker points its own stdin at /dev/null and its stdout at stderr, so neither a tool
  nor a stray print can reach the protocol;
- it applies the policy and supervises the tool with output captured (ADR 0006);
- it writes the run record back on a private pipe, then exits.

Each call costs a fork and the sandbox setup, not an interpreter startup.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import threading
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import IO, Any

KEEP = 64 * 1024  # bytes of each output stream returned to the client


def _run(request: dict[str, Any]) -> dict[str, Any]:
    from convergence.policy.load import PolicyError, load_policy
    from convergence.runtime.plan import EXIT_NOT_STARTED, RunError, prepare
    from convergence.runtime.record import save
    from convergence.runtime.supervisor import Options, not_started_record, supervise

    command = [str(a) for a in request["command"]]
    policy_path = Path(request["policy_path"])
    os.chdir(request["cwd"])
    options = Options(
        timeout=request.get("timeout"),
        capture_only=True,
        keep=KEEP,
        policy_path=str(policy_path),
        policy_text=policy_path.read_bytes(),
        trace=bool(request.get("trace", False)),
    )
    try:
        try:
            policy = load_policy(policy_path)
        except PolicyError as exc:
            raise RunError(
                "invalid policy", EXIT_NOT_STARTED, [str(i) for i in exc.issues]
            ) from exc
        options.policy_name = policy.name
        plan = prepare(policy, command, allow_degraded=False)
        try:
            record = supervise(plan, policy.resources.wall_clock_seconds, options)
        finally:
            plan.close()
            plan.remove_scratch()
    except RunError as exc:
        record = not_started_record(command, options, exc)
        if exc.details:
            record.outcome.error = f"{exc}: " + "; ".join(exc.details)
    save(record)
    return {"record": asdict(record)}


def _observe(request: dict[str, Any]) -> dict[str, Any]:
    from convergence.observe.driver import observe
    from convergence.runtime.record import runs_dir

    os.chdir(request["cwd"])
    observation, code = observe([str(a) for a in request["command"]], timeout=request["timeout"])
    target = runs_dir().parent / "observations" / f"{observation.id}.json"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(observation.to_json() + "\n")
    return {"observation": json.loads(observation.to_json()), "exit_code": code}


HANDLERS = {"run": _run, "observe": _observe}


def _work(request: dict[str, Any], out: int) -> None:
    """In the forked worker: keep the protocol out of reach, do the work, report, exit."""
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(2, 1)
    try:
        result = {"ok": True, **HANDLERS[request["op"]](request)}
    except BaseException as exc:
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        traceback.print_exc()
    data = json.dumps(result).encode()
    view = memoryview(data)
    while view:
        view = view[os.write(out, view) :]


def handle(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("op") not in HANDLERS:
        return {"ok": False, "error": f"unknown operation {request.get('op')!r}"}
    if threading.active_count() != 1:
        return {"ok": False, "error": "the helper must stay single-threaded (ADR 0006)"}
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        try:
            _work(request, write_end)
        finally:
            os._exit(0)
    os.close(write_end)
    chunks = []
    while chunk := os.read(read_end, 1 << 16):
        chunks.append(chunk)
    os.close(read_end)
    os.waitpid(pid, 0)
    if not chunks:
        return {"ok": False, "error": "the worker exited without an answer"}
    answer: dict[str, Any] = json.loads(b"".join(chunks))
    return answer


def serve(protocol_in: IO[bytes], protocol_out: IO[bytes]) -> None:
    for line in protocol_in:
        try:
            request = json.loads(line)
            answer = handle(request)
        except (ValueError, KeyError) as exc:
            answer = {"ok": False, "error": f"bad request: {exc}"}
        protocol_out.write(json.dumps(answer).encode() + b"\n")
        protocol_out.flush()


def _warm() -> None:
    """Import everything a run needs once, so each forked worker starts with it loaded."""
    from convergence.kernel import landlock, seccomp
    from convergence.observe import driver  # noqa: F401
    from convergence.policy import enforce, load  # noqa: F401
    from convergence.runtime import plan, record, supervisor  # noqa: F401

    # Load libseccomp and ask for the Landlock ABI now; a host without either finds out at
    # the first run, which refuses or reports it.
    with contextlib.suppress(Exception):
        seccomp.library()
        landlock.abi_version()


def main() -> None:
    _warm()
    # Keep private copies of the protocol pipes, then make fds 0 and 1 harmless.
    protocol_in = os.fdopen(os.dup(0), "rb")
    protocol_out = os.fdopen(os.dup(1), "wb")
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(2, 1)
    serve(protocol_in, protocol_out)


class Helper:
    """The server's handle on the helper process. Calls are made one at a time."""

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-m", "convergence.mcp.helper"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            close_fds=True,
        )

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        stdin, stdout = self.process.stdin, self.process.stdout
        if stdin is None or stdout is None or self.process.poll() is not None:
            raise RuntimeError("the spawn helper is not running")
        stdin.write(json.dumps(request).encode() + b"\n")
        stdin.flush()
        line = stdout.readline()
        if not line:
            raise RuntimeError("the spawn helper exited")
        answer: dict[str, Any] = json.loads(line)
        if not answer.get("ok"):
            raise RuntimeError(str(answer.get("error", "the spawn helper failed")))
        return answer

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


if __name__ == "__main__":
    main()
