"""The false-denial harness: observe a control, generate its policy, run it again."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from convergence.runtime.tracer import find_strace
from escape import fdr

pytestmark = [
    pytest.mark.kernel,
    pytest.mark.skipif(find_strace() is None, reason="strace is not installed"),
]


def test_a_control_passes_under_its_generated_policy(tmp_path: Path) -> None:
    out = tmp_path / "fdr.json"
    code = fdr.main(
        ["--case", "control-python-read-write", "--json", str(out), "--policies", str(tmp_path)]
    )
    report = json.loads(out.read_text())
    assert code == 0
    assert report["schema"] == "convergence.fdr/1"
    assert report["same_input"]["numerator"] == 0
    row = report["controls"][0]
    assert row["observed"] == "pass"
    assert row["same_input"] == "pass"
    assert row["rules"] > 0
    assert (tmp_path / "control-python-read-write.yaml").read_text().startswith("# Generated")
