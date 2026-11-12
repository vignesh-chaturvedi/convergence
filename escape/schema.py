"""The case format, ``convergence.escapecase/1``.

Attack cases and benign controls share this schema. Validation is strict, like the policy
loader: unknown keys are errors and no value is coerced. The case's ``policy`` is kept as
raw data here; it is validated with Convergence's own policy loader after the runner has
expanded its ``${VARIABLES}`` (see :mod:`escape.expand`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from convergence.policy.load import _StrictLoader
from escape.preconditions import Precondition

SCHEMA = "convergence.escapecase/1"

# The attack categories from escape/README.md. A case outside this list is an error, so the
# coverage table and the corpus cannot drift apart silently.
ATTACK_CATEGORIES = (
    "filesystem-read",
    "filesystem-write",
    "filesystem-delete",
    "traversal-symlink",
    "traversal-hardlink",
    "traversal-dotdot",
    "traversal-rename-refer",
    "proc-self",
    "proc-other-pid",
    "exec-disallowed",
    "exec-via-interpreter",
    "exec-via-loader",
    "setuid-no-new-privs",
    "net-tcp-connect",
    "net-tcp-bind",
    "net-udp",
    "net-raw-socket",
    "unix-socket-host",
    "ptrace",
    "process-vm-readv",
    "mount-namespace",
    "clone3-bypass",
    "io-uring-bypass",
    "bpf-perf-keyctl-userfaultfd",
    "tiocsti-injection",
    "signal-outside",
    "resource-fork-bomb",
    "resource-memory",
    "resource-cpu",
    "resource-file-size",
    "resource-fd-exhaustion",
    "persist-setsid-doublefork",
    "env-leak",
    "fd-leak",
)
CONTROL_CATEGORY = "control"

_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_ARCHES: tuple[Literal["x86_64", "aarch64"], ...] = ("x86_64", "aarch64")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Expect(_Strict):
    verdict: Literal["blocked", "allowed"]
    mechanism: str = Field(min_length=1, description="Informational: the expected mechanism.")
    min_abi: Annotated[int, Field(ge=0)] = Field(
        default=0,
        description=(
            "Landlock ABI the mechanism needs. Below it, an escape is a documented "
            "limitation, not a failure. 0 means the case must be blocked on every kernel."
        ),
    )


class Payload(_Strict):
    argv: tuple[str, ...] | None = None
    file: str | None = Field(
        default=None,
        description="A .py or .sh file next to the case; copied into ${WORKDIR} and run.",
    )
    stdin: str | None = None

    @model_validator(mode="after")
    def _one_source(self) -> Payload:
        if (self.argv is None) == (self.file is None):
            raise ValueError("payload needs exactly one of 'argv' or 'file'")
        if self.argv is not None and not self.argv:
            raise ValueError("payload.argv must not be empty")
        if self.file is not None:
            if not self.file.endswith((".py", ".sh")):
                raise ValueError("payload.file must be a .py or .sh file")
            if self.file.startswith("/") or ".." in Path(self.file).parts:
                raise ValueError("payload.file must be a relative path inside the case directory")
        return self


class OracleSpec(BaseModel):
    """``type`` selects the oracle; the other keys are that oracle's configuration.

    Each oracle validates its own configuration strictly (see :mod:`escape.oracles`).
    """

    model_config = ConfigDict(extra="allow", strict=True, frozen=True)

    type: str

    @property
    def config(self) -> dict[str, Any]:
        return dict(self.model_extra or {})


class Platforms(_Strict):
    arch: tuple[Literal["x86_64", "aarch64"], ...] = _ARCHES
    requires: tuple[Precondition, ...] = Field(
        default=(),
        description=(
            "Host behaviour the case needs (see escape/preconditions.py). Where the host "
            "already prevents it, the case is not-testable, never counted as blocked."
        ),
    )


class Case(_Strict):
    id: str
    category: str
    description: str = Field(min_length=1)
    expect: Expect
    policy: dict[str, Any]
    payload: Payload
    oracle: OracleSpec
    platforms: Platforms = Field(default_factory=Platforms)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError("id must be kebab-case: lowercase letters, digits, and hyphens")
        return value

    @field_validator("category")
    @classmethod
    def _category(cls, value: str) -> str:
        if value != CONTROL_CATEGORY and value not in ATTACK_CATEGORIES:
            raise ValueError(f"unknown category {value!r}; see escape/README.md")
        return value

    @model_validator(mode="after")
    def _kind(self) -> Case:
        if self.category == CONTROL_CATEGORY and self.expect.verdict != "allowed":
            raise ValueError("a control must expect verdict 'allowed'")
        if self.category != CONTROL_CATEGORY and self.expect.verdict != "blocked":
            raise ValueError("an attack must expect verdict 'blocked'")
        return self

    @property
    def is_control(self) -> bool:
        return self.category == CONTROL_CATEGORY


class CaseError(Exception):
    def __init__(self, source: str, message: str) -> None:
        super().__init__(f"{source}: {message}")
        self.source = source


def load_case(path: Path) -> Case:
    """Load one case file. Raises :class:`CaseError` with every schema problem."""
    source = str(path)
    try:
        data = yaml.load(path.read_text(), Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except (OSError, yaml.YAMLError) as exc:
        raise CaseError(source, f"cannot read case: {exc}") from exc
    if not isinstance(data, dict):
        raise CaseError(source, "a case must be a mapping")
    try:
        # Validate through JSON, as the policy loader does: strict, no coercion, and YAML-only
        # values (dates, sets) are rejected.
        encoded = json.dumps(data, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise CaseError(source, f"case contains a value that is not plain data: {exc}") from exc
    try:
        return Case.model_validate_json(encoded)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
            for e in exc.errors(include_url=False)
        )
        raise CaseError(source, problems) from exc


def load_dir(directory: Path) -> list[tuple[Path, Case]]:
    """Load every ``*.yaml`` case under ``directory`` (sorted), refusing duplicate ids."""
    cases: list[tuple[Path, Case]] = []
    seen: dict[str, Path] = {}
    for path in sorted(directory.rglob("*.yaml")):
        case = load_case(path)
        if case.id in seen:
            raise CaseError(str(path), f"duplicate id {case.id!r} (also in {seen[case.id]})")
        seen[case.id] = path
        cases.append((path, case))
    return cases
