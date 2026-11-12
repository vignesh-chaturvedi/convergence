"""Oracle registry. Each oracle answers "did the effect happen?" from harness-owned ground truth."""

from __future__ import annotations

from pydantic import ValidationError

from escape.oracles.base import CaseDirs, Evidence, Observation, Oracle, Setup
from escape.oracles.execution import ExecProbe
from escape.oracles.files import CanaryDelete, CanaryFileRead, CanaryFileWrite, WorkloadOutput
from escape.oracles.leaks import EnvLeak, FdLeak
from escape.oracles.network import NetworkSink, ServerReachable
from escape.oracles.process import Persist, PrivilegeGain, ProcessRead, ProcessSignal
from escape.oracles.resources import ResourceDos
from escape.schema import OracleSpec

ORACLES: dict[str, type[Oracle]] = {
    cls.type_name: cls
    for cls in (
        CanaryFileRead,
        CanaryFileWrite,
        CanaryDelete,
        WorkloadOutput,
        NetworkSink,
        ServerReachable,
        ProcessRead,
        ProcessSignal,
        PrivilegeGain,
        Persist,
        EnvLeak,
        FdLeak,
        ResourceDos,
        ExecProbe,
    )
}


class OracleConfigError(Exception):
    pass


def create(spec: OracleSpec) -> Oracle:
    cls = ORACLES.get(spec.type)
    if cls is None:
        raise OracleConfigError(
            f"unknown oracle type {spec.type!r}; known: {', '.join(sorted(ORACLES))}"
        )
    try:
        return cls(spec.config)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise OracleConfigError(f"oracle {spec.type}: {problems}") from exc


__all__ = [
    "ORACLES",
    "CaseDirs",
    "Evidence",
    "Observation",
    "Oracle",
    "OracleConfigError",
    "Setup",
    "create",
]
