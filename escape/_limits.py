"""Apply harness safety limits, then exec the payload. Run as a script, stdlib only.

The unconfined launcher uses this so that a validity run (no sandbox) cannot take the host
down. The limits are deliberately *looser* than the case's policy, so an unconfined payload
can still be seen to exceed the policy, which is what proves the case is real.

usage: python -I _limits.py '<json {"RLIMIT_NAME": value}>' -- argv...
"""

import json
import os
import resource
import sys


def main() -> None:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        sys.stderr.write("usage: _limits.py LIMITS_JSON -- ARGV...\n")
        os._exit(2)
    limits = json.loads(sys.argv[1])
    argv = sys.argv[3:]
    for name, value in limits.items():
        which = getattr(resource, name)
        _, hard = resource.getrlimit(which)
        if hard != resource.RLIM_INFINITY:
            value = min(int(value), hard)
        resource.setrlimit(which, (int(value), int(value)))
    try:
        os.execvp(argv[0], argv)  # noqa: S606 - replacing this process with the payload is the point
    except OSError as exc:
        sys.stderr.write(f"_limits.py: cannot execute {argv[0]}: {exc}\n")
        os._exit(127)


if __name__ == "__main__":
    main()
