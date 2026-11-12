"""The benchmark harness's statistics and reports, and the README table it generates."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "benchmarks"))

import bench  # noqa: E402 - benchmarks/ is a directory of scripts, not a package


def test_percentiles_are_nearest_rank() -> None:
    row = bench.summary([i / 1000 for i in range(1, 101)])  # 1 ms .. 100 ms
    assert (row["p50_ms"], row["p95_ms"], row["p99_ms"]) == (50.0, 95.0, 99.0)
    assert row["runs"] == 100
    assert bench.summary([0.002])["p99_ms"] == 2.0


def test_unavailable_configurations_are_shown_with_their_reason() -> None:
    report = {
        "results": {
            "bare": {w: {"runs": 1, "p50_ms": 1, "p95_ms": 2} for w in bench.WORKLOADS},
            "bwrap": {w: {"unavailable": "bwrap cannot run here"} for w in bench.WORKLOADS},
        }
    }
    table = bench.table(report)
    assert "| bubblewrap | n/a | n/a | n/a |" in table
    assert "n/a: bwrap cannot run here" in table


def test_the_readme_table_matches_the_committed_results() -> None:
    readme = (REPO / "README.md").read_text()
    start = readme.index(bench.MARK_START)
    end = readme.index(bench.MARK_END) + len(bench.MARK_END)
    if not bench.README_SOURCE.exists():
        assert readme[start:end] == f"{bench.MARK_START}\n{bench.MARK_END}"
        return
    expected = bench.readme_section(json.loads(bench.README_SOURCE.read_text()))
    assert readme[start:end] == expected, "run: python benchmarks/bench.py readme"
