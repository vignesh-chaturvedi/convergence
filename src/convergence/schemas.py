"""JSON Schemas for Convergence's file formats, generated from the code that reads them.

The checked-in copies under ``schemas/`` are regenerated with::

    uv run python -m convergence.schemas --write schemas

and a test fails if they drift from the code.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from convergence.policy.model import SCHEMA as POLICY_SCHEMA
from convergence.policy.model import Policy
from convergence.probe.report import SCHEMA as DOCTOR_SCHEMA
from convergence.probe.report import DoctorReport

BASE_URL = "https://github.com/vignesh-chaturvedi/convergence/blob/main/schemas"


def policy_schema() -> dict[str, Any]:
    schema = Policy.model_json_schema(by_alias=True, mode="validation")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_URL}/policy-v1.json",
        "title": POLICY_SCHEMA,
        "description": (
            "A Convergence policy. Everything not granted is denied. See docs/policy.md."
        ),
        **{k: v for k, v in schema.items() if k not in ("title", "description")},
    }


def doctor_schema() -> dict[str, Any]:
    schema = TypeAdapter(DoctorReport).json_schema(mode="serialization")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_URL}/doctor-v1.json",
        "title": DOCTOR_SCHEMA,
        "description": "Output of `convergence doctor --json`.",
        **{k: v for k, v in schema.items() if k not in ("title", "description")},
    }


SCHEMAS: dict[str, Callable[[], dict[str, Any]]] = {
    "policy-v1.json": policy_schema,
    "doctor-v1.json": doctor_schema,
}


def render(name: str) -> str:
    return json.dumps(SCHEMAS[name](), indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m convergence.schemas")
    parser.add_argument("--write", type=Path, metavar="DIR", help="write every schema into DIR")
    args = parser.parse_args(argv)
    if args.write is None:
        for name in SCHEMAS:
            sys.stdout.write(f"{name}\n")
        return 0
    args.write.mkdir(parents=True, exist_ok=True)
    for name in SCHEMAS:
        (args.write / name).write_text(render(name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
