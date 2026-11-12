"""The runner end to end, with the real controls and the real kernel."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from escape import runner
from escape.launchers import ConvergenceLauncher, UnconfinedLauncher
from escape.schema import load_case
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


def test_convergence_launcher_is_never_a_silent_pass() -> None:
    path = CONTROLS / "c01-python-read-write.yaml"
    item = runner.Runner(ConvergenceLauncher(), subreaper=False).run_case(
        path, load_case(path), "controls"
    )
    assert item.result is Result.LAUNCHER_UNAVAILABLE
    assert "not implemented yet" in item.evidence
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
