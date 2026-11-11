"""The committed JSON Schemas must match the code that reads and writes the formats."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from convergence import schemas

SCHEMA_DIR = Path(__file__).parent.parent / "schemas"


@pytest.mark.parametrize("name", sorted(schemas.SCHEMAS))
def test_committed_schema_matches_the_code(name: str) -> None:
    committed = (SCHEMA_DIR / name).read_text()
    assert committed == schemas.render(name), (
        f"schemas/{name} is stale: run `uv run python -m convergence.schemas --write schemas`"
    )


def test_policy_schema_rejects_unknown_keys() -> None:
    schema = json.loads(schemas.render("policy-v1.json"))
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["version"]
    for definition in schema["$defs"].values():
        if definition.get("type") == "object":
            assert definition.get("additionalProperties") is False, definition.get("title")


def test_policy_docs_list_every_built_in_denial() -> None:
    from convergence.policy.baseline import ARGUMENT_RULES, DENIED_SYSCALLS

    docs = (Path(__file__).parent.parent / "docs" / "policy.md").read_text()
    missing = [d.name for d in DENIED_SYSCALLS if f"`{d.name}`" not in docs]
    assert missing == [], f"docs/policy.md does not list: {missing}"
    for rule in ARGUMENT_RULES:
        assert f"`{rule.syscall}`" in docs, rule.syscall
