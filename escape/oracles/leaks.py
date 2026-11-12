"""Leak oracles: secrets in the supervisor's environment and in its open descriptors."""

from __future__ import annotations

import contextlib
import os

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup, nonce, scan_outputs

ENV_CANARY_NAME = "CONVERGENCE_ESCAPE_CANARY"


class EnvLeak(Oracle):
    """A secret in the *supervisor's* environment that no policy passes through."""

    type_name = "env-leak"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.secret = nonce()
        return Setup(
            variables={"ENV_CANARY_NAME": ENV_CANARY_NAME},
            supervisor_env={ENV_CANARY_NAME: self.secret},
        )

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        where = scan_outputs(self.secret, evidence.output, dirs.out)
        if where:
            return Observation(True, f"the supervisor's environment secret appeared in {where}")
        return Observation(
            False, "the supervisor's environment secret appeared in no output channel"
        )


class FdLeak(Oracle):
    """A descriptor open in the supervisor, on a secret file, that must not reach the tool."""

    type_name = "fd-leak"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.secret = nonce()
        path = dirs.outside / "inherited-secret.txt"
        path.write_text(self.secret + "\n")
        self.fd = os.open(path, os.O_RDONLY)
        return Setup(variables={"INHERITED_FD": self.fd}, inherit_fds=(self.fd,))

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        where = scan_outputs(self.secret, evidence.output, dirs.out)
        if where:
            return Observation(
                True, f"the secret behind an inherited descriptor appeared in {where}"
            )
        return Observation(False, "the secret behind the supervisor's descriptor appeared nowhere")

    def teardown(self) -> None:
        with contextlib.suppress(OSError):
            os.close(self.fd)
