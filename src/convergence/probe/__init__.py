"""The capability probe behind ``convergence doctor``.

It reports what the running kernel can enforce, proven by live tests in throwaway forked
children. It never confines the calling process.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from convergence.kernel import landlock as ll
from convergence.probe import facts, live, report
from convergence.probe.report import DoctorReport


def run_doctor() -> DoctorReport:
    host = facts.collect()
    if not host.is_linux:
        info = report.landlock_info(None, "not Linux", None)
        seccomp = report.SeccompInfo(None, None, None, "not Linux")
        return report.build(host, info, seccomp, [])

    abi: int | None
    reason: str | None = None
    errata: int | None = None
    try:
        abi = ll.abi_version()
        errata = ll.errata()
    except ll.LandlockUnavailable as exc:
        abi, reason = None, exc.reason

    workdir = Path(tempfile.mkdtemp(prefix="convergence-probe-"))
    try:
        ctx = live.ProbeContext(
            abi=abi, landlock_reason=reason, workdir=workdir, parent_pid=os.getpid(), facts=host
        )
        probes = live.run_all(ctx)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return report.build(
        host, report.landlock_info(abi, reason, errata), report.seccomp_info(), probes
    )


__all__ = ["DoctorReport", "run_doctor"]
