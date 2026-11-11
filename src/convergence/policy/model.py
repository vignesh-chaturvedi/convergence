"""The policy schema, version 1 (``convergence.policy/1``).

A policy lists what a tool may do. Everything not listed is denied. The semantics of every
field are specified in docs/policy.md and ADR 0004; this module only defines the shape and
the checks that need nothing but the policy itself. Checks that need the host (do paths
exist, which syscalls exist here) live in :mod:`convergence.policy.validate`.

Validation is strict: unknown keys are errors, and no value is coerced (``"443"`` is not a
port, ``true`` is not a version number).
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA = "convergence.policy/1"
SUPPORTED_VERSION = 1

# ${NAME} placeholders allowed at the start of a path. They are resolved at run time.
PATH_VARIABLES = ("HOME", "CWD", "SCRATCH")
_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SYSCALL_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

MAX_WALL_CLOCK_SECONDS = 24 * 60 * 60


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, populate_by_name=True)


def check_path(path: str) -> str:
    """Accept an absolute path, or one that starts with a known ``${VARIABLE}``."""
    if not path:
        raise ValueError("path is empty")
    if "\0" in path:
        raise ValueError("path contains a NUL byte")
    variables = _VARIABLE.findall(path)
    for name in variables:
        if name not in PATH_VARIABLES:
            raise ValueError(
                f"unknown variable ${{{name}}}; allowed: "
                + ", ".join(f"${{{v}}}" for v in PATH_VARIABLES)
            )
    if variables and not path.startswith("${"):
        raise ValueError("a ${VARIABLE} may only appear at the start of a path")
    if len(variables) > 1:
        raise ValueError("a path may contain at most one ${VARIABLE}")
    if not variables and not path.startswith("/"):
        raise ValueError(
            "path must be absolute (start with /) or start with ${HOME}, ${CWD}, or ${SCRATCH}"
        )
    rest = _VARIABLE.sub("", path, count=1)
    if variables and rest and not rest.startswith("/"):
        raise ValueError("after ${VARIABLE} the path must continue with /")
    if any(part == ".." for part in rest.split("/")):
        raise ValueError("path must not contain '..'")
    return path


class PathRule(_Strict):
    """A path with options. A bare string in a policy means ``{path: ..., optional: false}``."""

    path: str
    optional: bool = Field(
        default=False,
        description="If true, a path that does not exist is skipped instead of being an error.",
    )

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return check_path(value)


PathString = Annotated[str, AfterValidator(check_path)]
PathEntry = Annotated[
    PathString | PathRule,
    Field(description="An absolute path, or {path, optional}."),
]


def normalise_entries(entries: tuple[str | PathRule, ...]) -> tuple[PathRule, ...]:
    return tuple(e if isinstance(e, PathRule) else PathRule(path=e) for e in entries)


class Filesystem(_Strict):
    read: tuple[PathEntry, ...] = Field(
        default=(),
        description="Paths that may be read: files exactly, directories recursively.",
    )
    write: tuple[PathEntry, ...] = Field(
        default=(),
        description=(
            "Paths that may be read and modified. On a directory this includes creating, "
            "removing, and renaming entries beneath it."
        ),
    )
    execute: tuple[PathEntry, ...] = Field(
        default=(),
        description="Files (or directories of files) that may be executed. Implies read.",
    )

    def rules(self, bucket: Literal["read", "write", "execute"]) -> tuple[PathRule, ...]:
        entries: tuple[str | PathRule, ...] = getattr(self, bucket)
        return normalise_entries(entries)


Port = Annotated[int, Field(ge=0, le=65535)]
PortList = tuple[Port, ...] | Literal["any"]


class Network(_Strict):
    tcp_connect: PortList = Field(
        default=(),
        description="Remote TCP ports that may be connected to, on any host, or 'any'.",
    )
    tcp_bind: PortList = Field(
        default=(),
        description="Local TCP ports that may be bound (0 = an ephemeral port), or 'any'.",
    )
    udp_send: PortList = Field(
        default=(),
        description="Remote UDP ports that may be sent to, on any host, or 'any'.",
    )
    udp_bind: PortList = Field(
        default=(),
        description="Local UDP ports that may be bound (0 = an ephemeral port), or 'any'.",
    )
    unix_sockets: Literal["deny", "allow"] = Field(
        default="deny",
        description=(
            "'deny': no connections to unix sockets outside the sandbox. 'allow': unix sockets "
            "are not restricted (this can reach host services)."
        ),
    )

    @field_validator("tcp_connect", "udp_send")
    @classmethod
    def _no_remote_port_zero(cls, value: tuple[int, ...] | str) -> tuple[int, ...] | str:
        if isinstance(value, tuple) and 0 in value:
            raise ValueError("port 0 is not a valid remote port")
        return value

    @property
    def any_ip(self) -> bool:
        """Whether any IPv4/IPv6 networking is granted at all."""
        return any(
            value == "any" or value
            for value in (self.tcp_connect, self.tcp_bind, self.udp_send, self.udp_bind)
        )


class Syscalls(_Strict):
    mode: Literal["deny-list", "allow-list"] = Field(
        default="deny-list",
        description=(
            "'deny-list': everything is allowed except Convergence's built-in deny list and "
            "'deny'. 'allow-list': only 'allow' is permitted, minus the built-in deny list."
        ),
    )
    deny: tuple[str, ...] = Field(default=(), description="Extra syscalls to deny.")
    allow: tuple[str, ...] = Field(
        default=(), description="allow-list mode only: every syscall the tool may make."
    )

    @field_validator("deny", "allow")
    @classmethod
    def _names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            if not _SYSCALL_NAME.match(name):
                raise ValueError(f"not a syscall name: {name!r}")
        return value

    @model_validator(mode="after")
    def _mode(self) -> Syscalls:
        if self.mode == "deny-list" and self.allow:
            raise ValueError("'allow' is only used with mode: allow-list")
        if self.mode == "allow-list" and not self.allow:
            raise ValueError("mode: allow-list needs a non-empty 'allow' list")
        return self


Positive = Annotated[int, Field(gt=0)]


class Resources(_Strict):
    wall_clock_seconds: Annotated[int, Field(gt=0, le=MAX_WALL_CLOCK_SECONDS)] = Field(
        default=60, description="Kill the whole sandbox after this many seconds."
    )
    cpu_seconds: Positive | None = Field(default=60, description="RLIMIT_CPU per process.")
    memory_mb: Positive | None = Field(
        default=2048,
        description=(
            "RLIMIT_DATA per process: private writable memory (heap, anonymous mappings). "
            "Not a cgroup memory limit."
        ),
    )
    address_space_mb: Positive | None = Field(
        default=None,
        description=(
            "RLIMIT_AS per process. Off by default: runtimes such as V8 and Go reserve large "
            "virtual ranges and fail under it."
        ),
    )
    max_processes: Positive | None = Field(
        default=64,
        description=(
            "Processes the sandbox may add (RLIMIT_NPROC, which the kernel counts per user, "
            "not per sandbox)."
        ),
    )
    max_file_size_mb: Positive | None = Field(default=1024, description="RLIMIT_FSIZE.")
    max_open_files: Positive | None = Field(default=1024, description="RLIMIT_NOFILE.")


class Environment(_Strict):
    pass_: tuple[str, ...] = Field(
        default=(),
        alias="pass",
        description="Names of variables copied from the caller's environment, if set.",
    )
    set: dict[str, str] = Field(default_factory=dict, description="Variables set to fixed values.")

    @field_validator("pass_")
    @classmethod
    def _pass_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            if not _ENV_NAME.match(name):
                raise ValueError(f"not an environment variable name: {name!r}")
        return value

    @field_validator("set")
    @classmethod
    def _set_names(cls, value: dict[str, str]) -> dict[str, str]:
        for name, item in value.items():
            if not _ENV_NAME.match(name):
                raise ValueError(f"not an environment variable name: {name!r}")
            if "\0" in item:
                raise ValueError(f"value of {name} contains a NUL byte")
        return value

    @model_validator(mode="after")
    def _no_overlap(self) -> Environment:
        both = sorted(set(self.pass_) & set(self.set))
        if both:
            raise ValueError(f"variables both passed and set: {', '.join(both)}")
        return self


class Policy(_Strict):
    """A Convergence policy. Everything not granted here is denied."""

    version: int = Field(description="Policy format version. Only 1 exists.")
    name: str | None = None
    description: str | None = None
    filesystem: Filesystem = Field(default_factory=Filesystem)
    network: Network = Field(default_factory=Network)
    syscalls: Syscalls = Field(default_factory=Syscalls)
    resources: Resources = Field(default_factory=Resources)
    environment: Environment = Field(default_factory=Environment)

    @field_validator("version")
    @classmethod
    def _version(cls, value: int) -> int:
        if value != SUPPORTED_VERSION:
            raise ValueError(
                f"unsupported policy version {value}; this Convergence reads version "
                f"{SUPPORTED_VERSION}"
            )
        return value
