"""Host preconditions: behaviour the host itself must allow for a case to be testable.

Some attacks are already prevented by the host before Convergence is involved. On Ubuntu
24.04, for example, AppArmor refuses unprivileged user namespaces, and the kernel refuses
TIOCSTI without CAP_SYS_ADMIN (``dev.tty.legacy_tiocsti = 0``). Such a case cannot escape
even unconfined, so it can say nothing about Convergence. A case lists what it needs in
``requires``; where the host lacks it, the case is reported ``not-testable`` and never
counted as blocked.

Each probe tests the behaviour itself in a throwaway child where it can, rather than
trusting a setting.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from convergence.probe.child import attempt, run_in_child

Precondition = Literal["unprivileged-userns", "legacy-tiocsti"]
PRECONDITIONS: tuple[Precondition, ...] = ("unprivileged-userns", "legacy-tiocsti")


@dataclass(frozen=True, slots=True)
class Availability:
    available: bool
    detail: str


def _unprivileged_userns() -> Availability:
    """Can an unprivileged process create a user namespace and use its capabilities there?

    Creating the namespace is not enough: with AppArmor's userns restriction the namespace is
    created but its capabilities are unusable. So the child also maps its ids and creates a
    mount namespace inside, which needs CAP_SYS_ADMIN in the user namespace.
    """
    uid, gid = os.getuid(), os.getgid()

    def child() -> dict[str, str]:
        result = {"unshare_user": attempt(lambda: os.unshare(os.CLONE_NEWUSER))}
        if result["unshare_user"] != "ok":
            return result
        result["map_ids"] = attempt(
            lambda: (
                Path("/proc/self/setgroups").write_text("deny"),
                Path("/proc/self/uid_map").write_text(f"0 {uid} 1"),
                Path("/proc/self/gid_map").write_text(f"0 {gid} 1"),
            )
        )
        if result["map_ids"] == "ok":
            result["unshare_mount"] = attempt(lambda: os.unshare(os.CLONE_NEWNS))
        return result

    outcome = run_in_child(child)
    if not outcome.ok:
        return Availability(False, f"probe failed: {outcome.error}")
    steps = outcome.result
    if all(steps.get(k) == "ok" for k in ("unshare_user", "map_ids", "unshare_mount")):
        return Availability(True, "unprivileged user namespaces with usable capabilities")
    failed = next(f"{k}: {v}" for k, v in steps.items() if v != "ok")
    return Availability(False, f"unprivileged user namespaces are refused here ({failed})")


def _legacy_tiocsti() -> Availability:
    path = Path("/proc/sys/dev/tty/legacy_tiocsti")
    try:
        value = path.read_text().strip()
    except FileNotFoundError:
        return Availability(
            True, "the kernel predates dev.tty.legacy_tiocsti: TIOCSTI is unrestricted"
        )
    except OSError as exc:
        return Availability(False, f"cannot read {path}: {exc}")
    if value == "1":
        return Availability(True, "dev.tty.legacy_tiocsti = 1")
    return Availability(
        False, f"dev.tty.legacy_tiocsti = {value}: TIOCSTI already needs CAP_SYS_ADMIN"
    )


PROBES: dict[Precondition, Callable[[], Availability]] = {
    "unprivileged-userns": _unprivileged_userns,
    "legacy-tiocsti": _legacy_tiocsti,
}


def probe_all() -> dict[Precondition, Availability]:
    """Probe every precondition. Call before starting threads: some probes fork."""
    return {name: PROBES[name]() for name in PRECONDITIONS}
