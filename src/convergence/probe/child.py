"""Run a probe function in a throwaway forked child and collect its result.

A probe confines itself (Landlock, seccomp, rlimits), and those restrictions cannot be
undone, so they must never be applied to the process that called the probe. The child
reports back over a pipe as JSON and exits with ``os._exit`` so that no interpreter
shutdown work (atexit handlers, buffered output) runs in it.

Forking is only safe from a single-threaded process. ``doctor`` is single-threaded.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import select
import signal
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

ProbeFn = Callable[[], dict[str, str]]


@dataclass(frozen=True, slots=True)
class ChildOutcome:
    """What a forked probe child reported, and how it ended."""

    ok: bool
    result: dict[str, str]
    error: str | None
    exit_status: str


def attempt(action: Callable[[], object]) -> str:
    """Run ``action`` and describe the outcome: ``"ok"``, an errno name, or an exception.

    Probes compare these strings against what the kernel is expected to return.
    """
    try:
        action()
    except OSError as exc:
        if exc.errno is not None:
            return errno.errorcode.get(exc.errno, str(exc.errno))
        return type(exc).__name__
    return "ok"


def _describe_status(status: int) -> str:
    if os.WIFEXITED(status):
        return f"exited {os.WEXITSTATUS(status)}"
    if os.WIFSIGNALED(status):
        return f"killed by {signal.Signals(os.WTERMSIG(status)).name}"
    return f"status {status}"


def run_in_child(fn: ProbeFn, timeout: float = 10.0) -> ChildOutcome:
    """Fork, run ``fn`` in the child, and return what it reported."""
    sys.stdout.flush()
    sys.stderr.flush()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        code = 0
        try:
            os.close(read_fd)
            try:
                payload: dict[str, object] = {"ok": True, "result": fn()}
            except BaseException as exc:
                payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            view = memoryview(json.dumps(payload).encode())
            while view:
                view = view[os.write(write_fd, view) :]
        except BaseException:
            code = 1
        finally:
            os._exit(code)

    os.close(write_fd)
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready, _, _ = select.select([read_fd], [], [], remaining)
            if not ready:
                timed_out = True
                break
            chunk = os.read(read_fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(read_fd)
        if timed_out:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)

    exit_status = _describe_status(status)
    if timed_out:
        return ChildOutcome(False, {}, f"timed out after {timeout:.0f}s", exit_status)
    try:
        decoded: object = json.loads(b"".join(chunks) or b"null")
    except json.JSONDecodeError as exc:
        return ChildOutcome(False, {}, f"unreadable child report: {exc}", exit_status)
    if not isinstance(decoded, dict):
        return ChildOutcome(False, {}, "child reported nothing", exit_status)
    if not decoded.get("ok"):
        return ChildOutcome(False, {}, str(decoded.get("error")), exit_status)
    raw = decoded.get("result")
    result = {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
    return ChildOutcome(True, result, None, exit_status)
