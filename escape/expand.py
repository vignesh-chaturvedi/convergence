"""Expanding the runner's ``${VARIABLES}`` in a case's policy and payload.

The runner creates fresh per-case state (directories, canaries, sinks, sentinels) and
exposes it to the case through variables. Policy variables (``${HOME}``, ``${CWD}``,
``${SCRATCH}``) are left untouched: Convergence resolves those itself at run time.

A string that is exactly one numeric variable (for example ``${SINK_PORT}`` in a port list)
becomes an integer, so a case can write ``tcp_connect: ["${SINK_PORT}"]``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from convergence.policy.model import PATH_VARIABLES

_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

VarValue = str | int


class UnknownVariable(Exception):
    pass


def expand_string(text: str, variables: Mapping[str, VarValue], *, strict: bool = True) -> VarValue:
    """Expand runner variables in ``text``.

    ``strict=False`` leaves unknown ``${NAME}`` untouched instead of failing; payload files use
    it because shell scripts have ``${var}`` syntax of their own.
    """
    whole = _VARIABLE.fullmatch(text)
    if whole and isinstance(variables.get(whole.group(1)), int):
        return variables[whole.group(1)]

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in PATH_VARIABLES or (not strict and name not in variables):
            return match.group(0)
        if name not in variables:
            raise UnknownVariable(
                f"${{{name}}} is not provided by the runner for this case "
                f"(available: {', '.join(sorted(variables))})"
            )
        return str(variables[name])

    return _VARIABLE.sub(replace, text)


def expand(value: Any, variables: Mapping[str, VarValue]) -> Any:
    """Expand variables in every string inside ``value`` (dicts, lists, tuples, strings)."""
    if isinstance(value, str):
        return expand_string(value, variables)
    if isinstance(value, dict):
        return {key: expand(item, variables) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [expand(item, variables) for item in value]
    return value


def expand_policy_variables(text: str, home: str, cwd: str, scratch: str) -> str:
    """Resolve ``${HOME}``, ``${CWD}``, ``${SCRATCH}`` the way the runtime will.

    Only the unconfined launcher needs this (it has no runtime to do it); the Convergence
    launcher hands the policy variables to ``convergence run`` unexpanded.
    """
    values = {"HOME": home, "CWD": cwd, "SCRATCH": scratch}

    def replace(match: re.Match[str]) -> str:
        return values.get(match.group(1), match.group(0))

    return _VARIABLE.sub(replace, text)
