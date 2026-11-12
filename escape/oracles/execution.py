"""Execution oracle: did a program outside the grants run?

Two marker kinds, chosen per case:

- ``elf`` (default): a copy of a ``sleep`` binary planted at ``${MARKER}``, outside every
  grant. Observed if the sampler sees that file's inode mapped *executable* in any process
  of the run. That is ground truth whether the marker was ``execve``d directly or mapped by
  the dynamic loader, and it cannot be faked by printing anything. The payload must keep
  the marker running long enough to be sampled, for example ``${MARKER} 1``.

  The copy is named ``sleep``, and setup checks that it runs both directly and through the
  dynamic loader, trying each of ``SLEEP_CANDIDATES`` until one does. On Ubuntu 26.04 the
  default ``sleep`` is the Rust uutils multi-call binary, which picks its tool from its own
  name and, with an Ubuntu patch, refuses to run unless that name matches the executable
  the kernel started; through the loader that executable is ``ld.so``, so it always
  refuses. GNU's ``sleep`` is still installed there as ``/usr/bin/gnusleep``, and has no
  such check. Setup fails loudly if no candidate works both ways.
- ``script``: a shell script at ``${MARKER}`` that prints a secret. The secret exists only
  inside that unreadable file, so seeing it in the output means the script was read and run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup, nonce, scan_outputs
from escape.procs import SamplerOptions, device_of

SLEEP_CANDIDATES = ("/usr/bin/sleep", "/bin/sleep", "/usr/bin/gnusleep")
# The dynamic loader runs a program the kernel was never asked to execute (${LOADER}).
LOADERS = ("/usr/lib/ld-linux-aarch64.so.1", "/lib64/ld-linux-x86-64.so.2")


def find_loader() -> str | None:
    """This host's dynamic loader, resolved, or None if neither known path exists."""
    loader = next((p for p in LOADERS if os.path.exists(p)), None)
    return str(Path(loader).resolve()) if loader is not None else None


def _sleep_problem(marker: Path, loader: str | None) -> str | None:
    """Why ``marker`` does not behave like sleep, directly and through ``loader``, or None."""
    runs = [("directly", [str(marker), "0.01"])]
    if loader is not None:
        runs.append(("through the dynamic loader", [loader, str(marker), "0.01"]))
    for how, argv in runs:
        try:
            check = subprocess.run(  # noqa: S603 - the marker the harness just planted
                argv, capture_output=True, timeout=10, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"cannot run it {how}: {exc}"
        if check.returncode != 0:
            stderr = check.stderr.decode(errors="replace").strip()[:200]
            return f"exits {check.returncode} when run {how}: {stderr}"
    return None


def plant_sleep(dest: Path) -> Path:
    """Copy the first sleep binary that works both ways to ``dest``; return its source."""
    loader = find_loader()
    sources = dict.fromkeys(Path(p).resolve() for p in SLEEP_CANDIDATES if os.path.exists(p))
    problems: list[str] = []
    for source in sources:
        dest.unlink(missing_ok=True)  # a fresh inode for every attempt
        shutil.copyfile(source, dest)
        dest.chmod(0o755)
        problem = _sleep_problem(dest, loader)
        if problem is None:
            return source
        problems.append(f"{source} {problem}")
    dest.unlink(missing_ok=True)
    tried = "; ".join(problems) or f"none of {', '.join(SLEEP_CANDIDATES)} exists"
    raise RuntimeError(f"no sleep binary can serve as the exec marker: {tried}")


class ExecConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    marker: Literal["elf", "script"] = "elf"


class ExecProbe(Oracle):
    type_name = "exec-probe"
    config_model = ExecConfig

    def setup(self, dirs: CaseDirs) -> Setup:
        config: ExecConfig = self.config  # type: ignore[assignment]
        if config.marker == "script":
            self.secret = nonce()
            self.marker = dirs.outside / "marker.sh"
            self.marker.write_text(f"#!/bin/sh\necho {self.secret}\n")
            self.marker.chmod(0o755)
            return Setup(variables={"MARKER": str(self.marker), "MARKER_DIR": str(dirs.outside)})

        # A new inode, unique to this case. Named "sleep" so a multi-call coreutils binary
        # still dispatches to sleep.
        self.marker = dirs.outside / "sleep"
        self.source = plant_sleep(self.marker)
        self.identity = device_of(self.marker)
        return Setup(
            variables={"MARKER": str(self.marker), "MARKER_DIR": str(dirs.outside)},
            sampler=SamplerOptions(marker=self.identity),
        )

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        config: ExecConfig = self.config  # type: ignore[assignment]
        if config.marker == "script":
            where = scan_outputs(self.secret, evidence.output, dirs.out)
            if where:
                return Observation(True, f"the marker script's secret appeared in {where}")
            return Observation(False, "the marker script did not run")
        mapped = [p.pid for p in evidence.peaks if p.marker_mapped]
        if mapped:
            return Observation(True, f"the marker binary was mapped executable in pid {mapped[0]}")
        return Observation(False, "the marker binary was never mapped executable")
