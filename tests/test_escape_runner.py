"""The runner end to end, with the real controls and the real kernel."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from escape import runner
from escape.launchers import LAUNCHERS, ConvergenceLauncher, UnconfinedLauncher
from escape.preconditions import Availability
from escape.report import CaseResult
from escape.schema import CaseError, load_case
from escape.score import Result

pytestmark = pytest.mark.kernel

REPO = Path(__file__).resolve().parent.parent
CONTROLS = REPO / "controls"


def run_control(name: str) -> Result:
    path = CONTROLS / name
    result = runner.Runner(UnconfinedLauncher(), subreaper=False).run_case(
        path, load_case(path), "controls"
    )
    return result.result


@pytest.mark.parametrize("name", sorted(p.name for p in CONTROLS.glob("*.yaml")))
def test_every_control_is_valid_unconfined(name: str) -> None:
    assert run_control(name) is Result.VALID


class _UnavailableConvergence(ConvergenceLauncher):
    def unavailable_reason(self) -> str | None:
        return "`convergence run` is not installed here; nothing was executed"


def test_an_unavailable_launcher_is_never_a_silent_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    path = CONTROLS / "c01-python-read-write.yaml"
    item = runner.Runner(_UnavailableConvergence(), subreaper=False).run_case(
        path, load_case(path), "controls"
    )
    assert item.result is Result.LAUNCHER_UNAVAILABLE
    assert "nothing was executed" in item.evidence
    monkeypatch.setitem(LAUNCHERS, "convergence", _UnavailableConvergence)
    code = runner.main(
        [
            "run",
            "--launcher",
            "convergence",
            "--set",
            "controls",
            "--case",
            "control-python-read-write",
            "--no-subreaper",
        ]
    )
    assert code == 1


def test_a_control_passes_under_convergence() -> None:
    path = CONTROLS / "c01-python-read-write.yaml"
    item = runner.Runner(ConvergenceLauncher(), subreaper=False).run_case(
        path, load_case(path), "controls"
    )
    assert item.result is Result.PASS, item.evidence


def test_validity_command_writes_reports(tmp_path: Path) -> None:
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    code = runner.main(
        [
            "validity",
            "--set",
            "controls",
            "--case",
            "control-json-tool",
            "--json",
            str(out_json),
            "--markdown",
            str(out_md),
            "--no-subreaper",
        ]
    )
    assert code == 0
    data = json.loads(out_json.read_text())
    assert data["schema"] == "convergence.escape-report/1"
    assert data["environment"]["launcher"] == "unconfined"
    assert data["results"][0]["result"] == "valid"
    assert "control-json-tool" in out_md.read_text()


def test_holdout_needs_the_one_time_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert runner.main(["run", "--launcher", "unconfined", "--set", "holdout"]) == 2
    assert "--holdout-run" in capsys.readouterr().err
    assert runner.main(["validity", "--set", "all"]) == 2
    assert runner.main(["list", "--set", "holdout"]) == 2


def test_unknown_case_id_is_a_usage_error() -> None:
    assert runner.main(["validity", "--set", "controls", "--case", "nope", "--no-subreaper"]) == 2


def test_payload_file_and_unknown_variables(tmp_path: Path) -> None:
    (tmp_path / "copy.sh").write_text(
        '#!/bin/sh\nfor f in "${WORKDIR}"/input.txt; do grep MARKER "$f" > "${OUT}"; done\n'
    )
    case_text = """\
id: control-file-payload
category: control
description: a shell payload file, with shell variables the runner must leave alone
expect: {verdict: allowed, mechanism: none}
policy:
  version: 1
  environment: {set: {PATH: /usr/bin:/bin}}
payload: {file: copy.sh}
oracle: {type: workload-output, require_file: true}
"""
    path = tmp_path / "case.yaml"
    path.write_text(case_text)
    item = runner.Runner(UnconfinedLauncher(), subreaper=False).run_case(
        path, load_case(path), "dev"
    )
    assert item.result is Result.VALID, item.evidence

    path.write_text(
        case_text.replace("version: 1", "version: 1\n  filesystem: {read: ['${NOPE}']}")
    )
    item = runner.Runner(UnconfinedLauncher(), subreaper=False).run_case(
        path, load_case(path), "dev"
    )
    assert item.result is Result.ERROR
    assert "NOPE" in item.evidence


def test_list_controls(capsys: pytest.CaptureFixture[str]) -> None:
    assert runner.main(["list", "--set", "controls"]) == 0
    assert "control-git-log" in capsys.readouterr().out


ATTACK_SHAPED = """\
id: harness-reached-check
category: filesystem-read
description: harness self-test; the payload attempts nothing
expect: {verdict: blocked, mechanism: landlock-fs, min_abi: 1}
policy:
  version: 1
  environment: {set: {PATH: /usr/bin:/bin}}
payload: {argv: [/bin/sh, -c, "PAYLOAD"]}
oracle: {type: canary-file-read}
"""


def _run_text(tmp_path: Path, text: str) -> CaseResult:
    path = tmp_path / "case.yaml"
    path.write_text(text)
    return runner.Runner(UnconfinedLauncher(), subreaper=False).run_case(
        path, load_case(path), "dev"
    )


def test_an_attack_that_does_nothing_is_invalid(tmp_path: Path) -> None:
    # It announced it reached its attempt but the effect never happened.
    item = _run_text(tmp_path, ATTACK_SHAPED.replace("PAYLOAD", "echo ${REACHED}"))
    assert item.result is Result.INVALID
    assert "REACHED" not in item.evidence


def test_a_missing_reached_marker_is_called_out(tmp_path: Path) -> None:
    item = _run_text(tmp_path, ATTACK_SHAPED.replace("PAYLOAD", "true"))
    assert item.result is Result.INVALID
    assert "never emitted ${REACHED}" in item.evidence


def test_missing_host_precondition_is_not_testable(tmp_path: Path) -> None:
    path = tmp_path / "case.yaml"
    path.write_text(
        ATTACK_SHAPED.replace("PAYLOAD", "true") + "platforms: {requires: [unprivileged-userns]}\n"
    )
    case_runner = runner.Runner(UnconfinedLauncher(), subreaper=False)
    case_runner.preconditions["unprivileged-userns"] = Availability(False, "refused for this test")
    item = case_runner.run_case(path, load_case(path), "dev")
    assert item.result is Result.NOT_TESTABLE
    assert "refused for this test" in item.evidence

    case_runner.preconditions["unprivileged-userns"] = Availability(True, "allowed")
    assert case_runner.run_case(path, load_case(path), "dev").result is Result.INVALID


def test_known_limitations_are_development_cases_documented_in_the_threat_model() -> None:
    known = runner.load_known_limitations()
    assert known, "the list is expected to name at least the dynamic-loader case"
    dev_ids = {p.stem for p in (runner.SETS["dev"]).glob("*.yaml")}
    threat_model = (runner.REPO / "THREAT_MODEL.md").read_text()
    for case_id, documented in known.items():
        assert case_id in dev_ids, case_id
        document, _, section = documented.partition(": ")
        assert document == "THREAT_MODEL.md"
        assert f"## {section}" in threat_model, section


def test_an_incomplete_known_limitation_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "known.yaml"
    path.write_text("- id: something-001\n  reason: because\n")
    with pytest.raises(CaseError, match="incomplete"):
        runner.load_known_limitations(path)


def test_a_known_limitation_counts_as_an_escape_but_does_not_fail() -> None:
    from escape.score import FAILING, escape_rate

    rate = escape_rate([Result.PASS, Result.PASS, Result.KNOWN_LIMITATION])
    assert (rate.numerator, rate.denominator) == (1, 3)
    assert Result.KNOWN_LIMITATION not in FAILING
