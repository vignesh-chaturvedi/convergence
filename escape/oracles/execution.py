"""Execution oracle: did a program outside the grants run?

Two marker kinds, chosen per case:

- ``elf`` (default): a copy of the system ``sleep`` binary planted at ``${MARKER}``, outside
  every grant. Observed if the sampler sees that file's inode mapped *executable* in any
  process of the run. That is ground truth whether the marker was ``execve``d directly or
  mapped by the dynamic loader, and it cannot be faked by printing anything. The payload
  must keep the marker running long enough to be sampled, for example ``${MARKER} 1``.
  The copy is named ``sleep``: where coreutils is a multi-call binary (Ubuntu 26.04 ships the
  Rust uutils), the binary chooses its tool from its own name and would exit at once under
  any other. Setup runs the copy once and fails loudly if it does not behave like sleep.
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

SLEEP_CANDIDATES = ("/usr/bin/sleep", "/bin/sleep")


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

        source = next((Path(p).resolve() for p in SLEEP_CANDIDATES if os.path.exists(p)), None)
        if source is None:
            raise RuntimeError("no sleep binary to copy as the exec marker")
        # A new inode, unique to this case. Named "sleep" so a multi-call coreutils binary
        # still dispatches to sleep.
        self.marker = dirs.outside / "sleep"
        shutil.copyfile(source, self.marker)
        self.marker.chmod(0o755)
        check = subprocess.run(  # noqa: S603 - the marker the harness just planted
            [str(self.marker), "0.01"], capture_output=True, timeout=10, check=False
        )
        if check.returncode != 0:
            raise RuntimeError(
                f"the marker (a copy of {source}) does not behave like sleep: "
                f"exit {check.returncode}, {check.stderr.decode(errors='replace').strip()[:200]}"
            )
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
