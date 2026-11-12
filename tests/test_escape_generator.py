"""The development-case generator: unique cases, the marker rule, and file ownership."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from escape import build_cases
from escape.schema import ATTACK_CATEGORIES, load_case, load_dir

REPO = Path(__file__).resolve().parent.parent


def test_every_generated_case_is_valid_and_unique() -> None:
    cases = build_cases.build()
    assert len(cases) == len(build_cases.VARIANTS)
    for case_id, (payload, case) in cases.items():
        assert case["category"] in ATTACK_CATEGORIES
        assert case_id.startswith(case["category"] + "-")
        assert payload.startswith(build_cases.BASE)
        # The marker is announced exactly once, inside the case's own body.
        assert payload.count("reached()") - build_cases.BASE.count("reached()") == 1
        assert "Attempts the" not in case["description"]


def test_a_duplicate_variant_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    first = build_cases.VARIANTS[0]
    monkeypatch.setattr(build_cases, "VARIANTS", (first, first))
    with pytest.raises(SystemExit, match="duplicates"):
        build_cases.build()


def test_policy_overrides_merge_into_the_base() -> None:
    merged = build_cases.merge(
        build_cases.BASE_POLICY,
        {"filesystem": {"read": ["/x"]}, "network": {"tcp_connect": [9]}},
    )
    assert merged["filesystem"]["read"][-1] == "/x"
    assert "/usr" in merged["filesystem"]["read"]
    assert merged["network"] == {"tcp_connect": [9]}
    assert build_cases.BASE_POLICY["network"] == {}  # the base itself is untouched


def test_it_only_replaces_its_own_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dev = tmp_path / "dev"
    dev.mkdir()
    monkeypatch.setattr(build_cases, "DEV", dev)
    monkeypatch.setattr(build_cases, "MANIFEST", dev / ".generated")
    monkeypatch.setattr(build_cases, "ROOT", tmp_path)
    (dev / "hand-written-001.yaml").write_text("kept")
    assert build_cases.main() == 0
    assert (dev / "hand-written-001.yaml").read_text() == "kept"
    listed = json.loads((dev / ".generated").read_text())
    assert len(listed) == 2 * len(build_cases.VARIANTS)

    # A hand-written file with a generated name is never overwritten.
    stray = dev / "filesystem-read-001.py"
    (dev / ".generated").write_text("[]")
    stray.write_text("mine")
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        build_cases.main()
    assert stray.read_text() == "mine"


def test_committed_development_cases_match_the_generator() -> None:
    # The generated files must not be edited by hand: change build_cases.py and regenerate.
    dev = REPO / "escape" / "cases" / "dev"
    for case_id, (payload, case) in build_cases.build().items():
        assert (dev / f"{case_id}.py").read_text() == payload, case_id
        assert json.loads((dev / f"{case_id}.yaml").read_text()) == case, case_id
        load_case(dev / f"{case_id}.yaml")  # and it passes the schema


def test_dev_set_has_no_byte_identical_payloads() -> None:
    payloads = [path.read_bytes() for path in (REPO / "escape" / "cases" / "dev").glob("*.py")]
    assert len(payloads) == len(set(payloads))
    assert len(load_dir(REPO / "escape" / "cases" / "dev")) == len(payloads)
