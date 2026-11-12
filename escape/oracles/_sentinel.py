"""A harness-owned target process for the process oracles. Run as a script, stdlib only.

usage: python -I _sentinel.py {hold|signal} {allow_ptrace 0|1}
stdin, one line:  hold:   <secret>
                  signal: <secret> <report-path>

hold:   keeps <secret> in memory only (never in argv or the environment).
signal: on SIGUSR1, appends <secret> to <report-path>, a host file the oracle checks.

With allow_ptrace=1 the sentinel opts in to being traced by any process of the same user
(Yama's PR_SET_PTRACER_ANY). That removes Yama from the picture, so a validity run measures
whether *Convergence* stops the access, not whether Yama happens to.

Prints "ready <pid>" once set up, then sleeps until killed.
"""

import ctypes
import os
import signal
import sys

PR_SET_PTRACER = 0x59616D61
PR_SET_PTRACER_ANY = ctypes.c_ulong(-1).value


def main() -> None:
    mode, allow_ptrace = sys.argv[1], sys.argv[2] == "1"
    line = sys.stdin.readline().rstrip("\n")
    sys.stdin.close()

    if allow_ptrace:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        libc.prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)  # EINVAL without Yama: fine

    held = bytearray()
    if mode == "hold":
        held += line.encode()
    elif mode == "signal":
        secret, report = line.split(" ", 1)

        def on_usr1(signum: int, frame: object) -> None:
            fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.write(fd, secret.encode())
            os.close(fd)

        signal.signal(signal.SIGUSR1, on_usr1)
    else:
        sys.stderr.write(f"unknown mode {mode}\n")
        os._exit(2)

    sys.stdout.write(f"ready {os.getpid()}\n")
    sys.stdout.flush()
    while True:
        signal.pause()
        if held and held[0] == 0:  # keeps `held` alive and referenced
            break


if __name__ == "__main__":
    main()
