"""Read a policy file (YAML or JSON) without surprises.

PyYAML's ``safe_load`` is safe against code execution but still has behaviours that are
wrong for a security policy, so this loader tightens it:

- a **duplicate key** is an error (YAML otherwise keeps the last one silently, so a second
  ``write:`` key could quietly replace the first);
- **anchors and aliases** are rejected (no policy needs them, and they enable
  exponential-expansion documents);
- the document must be plain JSON data: YAML timestamps, sets, and binary values are errors;
- files larger than 1 MiB are refused.

The parsed data is then validated in strict mode, so no value is coerced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from convergence.policy.model import Policy

MAX_POLICY_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class PolicyIssue:
    """One problem with a policy, located by a dotted path such as ``network.tcp_connect.0``."""

    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.location}: {self.message}" if self.location else self.message


class PolicyError(Exception):
    """The policy file could not be read or does not match the schema."""

    def __init__(self, source: str, issues: list[PolicyIssue]) -> None:
        self.source = source
        self.issues = issues
        super().__init__(f"{source}: " + "; ".join(str(i) for i in issues))


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys and aliases."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event: Any = self.peek_event()  # type: ignore[no-untyped-call]
        mark: Any = getattr(event, "start_mark", None)
        if isinstance(event, yaml.AliasEvent):
            raise yaml.constructor.ConstructorError(
                None, None, "YAML aliases are not allowed in policies", mark
            )
        if getattr(event, "anchor", None):
            raise yaml.constructor.ConstructorError(
                None, None, "YAML anchors are not allowed in policies", mark
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _parse(text: str, source: str) -> object:
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(exc, "problem", None) or str(exc)
        raise PolicyError(source, [PolicyIssue(where, f"not valid YAML/JSON: {problem}")]) from exc


def _location(loc: tuple[int | str, ...]) -> str:
    # Pydantic adds union-branch labels such as "tuple[int, ...]" or "literal['any']" to the
    # location; they are noise for a policy author.
    noise = ("str", "PathRule", "function-after")
    parts = [
        str(p)
        for p in loc
        if not (isinstance(p, str) and ("[" in p or p in noise or p.startswith(noise)))
    ]
    return ".".join(parts)


# Errors that only say "this value is not the *other* type of a union" (for example a path
# entry may be a string or an object). They are dropped when a more specific error exists.
_UNION_NOISE = {"string_type", "model_type", "literal_error", "tuple_type", "dict_type"}


def _issues(exc: ValidationError) -> list[PolicyIssue]:
    raw: list[tuple[str, str, str]] = []
    for error in exc.errors(include_url=False):
        location = _location(tuple(error["loc"]))
        message = str(error["msg"]).removeprefix("Value error, ")
        if error["type"] == "extra_forbidden":
            message = "unknown key"
        raw.append((location, error["type"], message))

    def covered(location: str) -> bool:
        return any(
            kind not in _UNION_NOISE and (loc == location or loc.startswith(location + "."))
            for loc, kind, _ in raw
        )

    issues: list[PolicyIssue] = []
    merged: dict[str, list[str]] = {}
    for location, kind, message in raw:
        if kind in _UNION_NOISE:
            if not covered(location):
                merged.setdefault(location, []).append(message)
            continue
        issues.append(PolicyIssue(location, message))
    for location, messages in merged.items():
        unique = list(dict.fromkeys(messages))
        issues.append(
            PolicyIssue(
                location,
                unique[0]
                if len(unique) == 1
                else " or ".join(
                    m.removeprefix("Input should be ") if i else m for i, m in enumerate(unique)
                ),
            )
        )
    # De-duplicate while keeping order.
    return list(dict.fromkeys(issues))


def parse_policy(text: str, source: str = "<policy>") -> Policy:
    """Parse and validate policy text. Raises :class:`PolicyError` with every issue found."""
    if len(text.encode()) > MAX_POLICY_BYTES:
        raise PolicyError(
            source, [PolicyIssue("", f"policy is larger than {MAX_POLICY_BYTES} bytes")]
        )
    data = _parse(text, source)
    if data is None:
        raise PolicyError(source, [PolicyIssue("", "policy is empty")])
    if not isinstance(data, dict):
        raise PolicyError(source, [PolicyIssue("", "a policy must be a mapping of keys to values")])
    try:
        # Re-encode as JSON: this rejects YAML-only values and lets strict validation accept
        # JSON arrays and objects.
        encoded = json.dumps(data, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise PolicyError(
            source, [PolicyIssue("", f"policy contains a value that is not plain data: {exc}")]
        ) from exc
    try:
        return Policy.model_validate_json(encoded)
    except ValidationError as exc:
        raise PolicyError(source, _issues(exc)) from exc


def load_policy(path: str | Path) -> Policy:
    """Read and validate a policy file."""
    source = str(path)
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyError(source, [PolicyIssue("", f"cannot read policy: {exc.strerror}")]) from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(
            source, [PolicyIssue("", f"policy is larger than {MAX_POLICY_BYTES} bytes")]
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(source, [PolicyIssue("", "policy is not UTF-8 text")]) from exc
    return parse_policy(text, source)


def dump_policy(policy: Policy) -> str:
    """Serialise a policy as YAML, with defaults included so nothing is implicit."""
    data = policy.model_dump(mode="json", by_alias=True)
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
