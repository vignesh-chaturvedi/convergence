"""The escape-case schema, variable expansion, scoring, and the holdout seal (pure logic)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from escape import seal
from escape.expand import UnknownVariable, expand, expand_policy_variables, expand_string
from escape.oracles import ORACLES, OracleConfigError, create
from escape.schema import ATTACK_CATEGORIES, CaseError, OracleSpec, load_case, load_dir
from escape.score import FAILING, Rate, Result, escape_rate, false_denial_rate, score, wilson

REPO = Path(__file__).resolve().parent.parent
CONTROLS = sorted((REPO / "controls").glob("*.yaml"))

CONTROL = """\
id: control-example
category: control
description: example
expect: {verdict: allowed, mechanism: none}
policy: {version: 1}
payload: {argv: [/bin/true]}
oracle: {type: workload-output}
"""


def write(tmp_path: Path, text: str, name: str = "case.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def test_control_loads(tmp_path: Path) -> None:
    case = load_case(write(tmp_path, CONTROL))
    assert case.is_control
    assert case.payload.argv == ("/bin/true",)
    assert case.platforms.arch == ("x86_64", "aarch64")


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        (("id: control-example", "id: Control_Example"), "kebab-case"),
        (("category: control", "category: made-up"), "unknown category"),
        (("verdict: allowed", "verdict: blocked"), "a control must expect verdict 'allowed'"),
        (
            ("category: control", "category: filesystem-read"),
            "an attack must expect verdict 'blocked'",
        ),
        (("mechanism: none}", "mechanism: none, min_abi: '1'}"), "valid integer"),
        (("payload: {argv: [/bin/true]}", "payload: {argv: []}"), "must not be empty"),
        (("payload: {argv: [/bin/true]}", "payload: {}"), "exactly one of"),
        (
            ("payload: {argv: [/bin/true]}", "payload: {argv: [/bin/true], file: x.py}"),
            "exactly one of",
        ),
        (("payload: {argv: [/bin/true]}", "payload: {file: x.rb}"), ".py or .sh"),
        (("payload: {argv: [/bin/true]}", "payload: {file: ../x.py}"), "relative path inside"),
        (("description: example", "description: example\nextra: 1"), "Extra inputs"),
        (("description: example", "description: 2026-01-01"), "not plain data"),
    ],
)
def test_case_rejections(tmp_path: Path, change: tuple[str, str], fragment: str) -> None:
    text = CONTROL.replace(*change)
    with pytest.raises(CaseError, match=re.escape(fragment)):
        load_case(write(tmp_path, text))


def test_duplicate_ids_are_refused(tmp_path: Path) -> None:
    write(tmp_path, CONTROL, "a.yaml")
    write(tmp_path, CONTROL, "b.yaml")
    with pytest.raises(CaseError, match="duplicate id"):
        load_dir(tmp_path)


def test_requires_accepts_known_preconditions_only(tmp_path: Path) -> None:
    ok = CONTROL + "platforms: {requires: [unprivileged-userns, legacy-tiocsti]}\n"
    assert load_case(write(tmp_path, ok)).platforms.requires == (
        "unprivileged-userns",
        "legacy-tiocsti",
    )
    with pytest.raises(CaseError, match="requires"):
        load_case(write(tmp_path, CONTROL + "platforms: {requires: [root-shell]}\n"))


def test_every_repository_control_loads() -> None:
    cases = load_dir(REPO / "controls")
    assert len(cases) >= 10
    for _, case in cases:
        assert case.is_control
        assert case.oracle.type in ORACLES
        create(case.oracle)  # the oracle configuration is valid


def test_attack_categories_match_the_coverage_table() -> None:
    # escape/README.md's checklist and the schema's list must not drift apart.
    readme = (REPO / "escape" / "README.md").read_text()
    table = readme.split("## Category coverage checklist", 1)[1].split("\n## ", 1)[0]
    documented = {
        line.split("|")[1].strip().split(" ")[0]
        for line in table.splitlines()
        if line.startswith("| ") and not line.startswith("| Category") and "---" not in line
    }
    assert documented == set(ATTACK_CATEGORIES)


def test_oracle_creation_errors() -> None:
    with pytest.raises(OracleConfigError, match="unknown oracle type"):
        create(OracleSpec(type="nope"))
    with pytest.raises(OracleConfigError, match="measure"):
        create(OracleSpec.model_validate({"type": "resource-dos"}))
    with pytest.raises(OracleConfigError, match="Extra inputs"):
        create(OracleSpec.model_validate({"type": "canary-file-read", "bogus": 1}))


# --- variable expansion ------------------------------------------------------------------


def test_expansion_is_strict_and_leaves_policy_variables_alone() -> None:
    variables: dict[str, str | int] = {"WORKDIR": "/w", "SINK_PORT": 4242}
    assert expand_string("${WORKDIR}/x", variables) == "/w/x"
    assert expand_string("${SINK_PORT}", variables) == 4242
    assert expand_string("${SCRATCH}", variables) == "${SCRATCH}"
    assert expand({"a": ["${SINK_PORT}", "${HOME}/y"]}, variables) == {"a": [4242, "${HOME}/y"]}
    with pytest.raises(UnknownVariable, match="NOPE"):
        expand_string("${NOPE}", variables)


def test_lenient_expansion_keeps_shell_variables() -> None:
    text = 'for f in ${files}; do cat "${WORKDIR}/$f"; done'
    assert expand_string(text, {"WORKDIR": "/w"}, strict=False) == (
        'for f in ${files}; do cat "/w/$f"; done'
    )


def test_policy_variables_for_the_unconfined_launcher() -> None:
    assert expand_policy_variables("${SCRATCH}:${CWD}:${HOME}:${X}", "/h", "/c", "/s") == (
        "/s:/c:/h:${X}"
    )


# --- scoring -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("is_control", "launcher", "observed", "reached", "min_abi", "abi", "expected"),
    [
        # Unconfined: attacks must escape *and* announce they reached the attempt.
        (False, "unconfined", True, True, 0, 4, Result.VALID),
        (False, "unconfined", True, False, 0, 4, Result.INVALID),
        (False, "unconfined", False, True, 0, 4, Result.INVALID),
        (True, "unconfined", True, False, 0, 4, Result.VALID),  # controls ignore the marker
        (True, "unconfined", False, False, 0, 4, Result.INVALID),
        # Convergence: containment counts only if the attack reached its attempt.
        (False, "convergence", False, True, 0, 4, Result.PASS),
        (False, "convergence", False, False, 0, 4, Result.NOT_REACHED),
        # An escape is an escape, marker or not: the marker can never excuse one.
        (False, "convergence", True, False, 0, 4, Result.ESCAPE),
        (False, "convergence", True, True, 0, 4, Result.ESCAPE),
        (False, "convergence", True, True, 6, 4, Result.DOCUMENTED_LIMITATION),
        (False, "convergence", True, True, 6, 8, Result.ESCAPE),
        (False, "convergence", False, True, 6, 4, Result.PASS),
        (False, "convergence", True, True, 4, None, Result.DOCUMENTED_LIMITATION),
        (True, "convergence", True, False, 0, 4, Result.PASS),
        (True, "convergence", False, False, 0, 4, Result.FALSE_DENIAL),
    ],
)
def test_score(
    is_control: bool,
    launcher: str,
    observed: bool,
    reached: bool,
    min_abi: int,
    abi: int | None,
    expected: Result,
) -> None:
    got = score(
        is_control=is_control,
        launcher=launcher,
        observed=observed,
        reached=reached,
        min_abi=min_abi,
        kernel_abi=abi,
    )
    assert got is expected


def test_not_reached_and_not_testable_are_handled_honestly() -> None:
    assert Result.NOT_REACHED in FAILING  # never a silent pass
    assert Result.NOT_TESTABLE not in FAILING  # the host's doing, not the case's
    # Neither counts toward the escape rate in either direction.
    assert escape_rate([Result.NOT_REACHED, Result.NOT_TESTABLE, Result.PASS]) == Rate(0, 1)


def test_wilson_matches_published_intervals() -> None:
    # Divergence's README reports 0/35 as "CI 0.0-9.9%" and 49/50 as "CI 89.5-99.6%".
    low, high = wilson(0, 35)
    assert low == 0.0
    assert round(100 * high, 1) == 9.9
    low, high = wilson(49, 50)
    assert (round(100 * low, 1), round(100 * high, 1)) == (89.5, 99.6)
    assert wilson(0, 0) == (0.0, 0.0)


def test_rates_count_only_judged_cases() -> None:
    attacks = [
        Result.PASS,
        Result.ESCAPE,
        Result.DOCUMENTED_LIMITATION,
        Result.SKIPPED_UNENFORCEABLE,
    ]
    assert escape_rate(attacks) == Rate(1, 2)
    controls = [Result.PASS, Result.FALSE_DENIAL, Result.LAUNCHER_UNAVAILABLE]
    assert false_denial_rate(controls) == Rate(1, 2)
    assert Rate(0, 0).describe() == "n/a (nothing counted)"


# --- the holdout seal --------------------------------------------------------------------


def test_seal_detects_every_kind_of_change(tmp_path: Path) -> None:
    holdout = tmp_path / "holdout"
    holdout.mkdir()
    manifest = tmp_path / "holdout.sha256"
    assert seal.verify(holdout, manifest, tmp_path) == []

    (holdout / "a.yaml").write_text("a")
    (holdout / "b.yaml").write_text("b")
    assert seal.verify(holdout, manifest, tmp_path) == [
        "the holdout has 2 file(s) but is not sealed"
    ]
    assert seal.seal(holdout, manifest, tmp_path) == 2
    assert seal.verify(holdout, manifest, tmp_path) == []

    (holdout / "a.yaml").write_text("a, edited while tuning")
    assert seal.verify(holdout, manifest, tmp_path) == ["changed after sealing: holdout/a.yaml"]
    (holdout / "a.yaml").write_text("a")
    (holdout / "c.yaml").write_text("c")
    assert seal.verify(holdout, manifest, tmp_path) == ["added after sealing: holdout/c.yaml"]
    (holdout / "c.yaml").unlink()
    (holdout / "b.yaml").unlink()
    assert seal.verify(holdout, manifest, tmp_path) == ["removed after sealing: holdout/b.yaml"]


def test_seal_detects_a_tampered_manifest(tmp_path: Path) -> None:
    holdout = tmp_path / "holdout"
    holdout.mkdir()
    (holdout / "a.yaml").write_text("a")
    manifest = tmp_path / "holdout.sha256"
    seal.seal(holdout, manifest, tmp_path)
    lines = manifest.read_text().splitlines()
    manifest.write_text(lines[0] + "\n" + "0" * 64 + "  MANIFEST\n")
    assert seal.verify(holdout, manifest, tmp_path) == [
        "the manifest's own digest does not match its contents"
    ]


def test_repository_holdout_matches_its_seal() -> None:
    assert seal.verify() == []
