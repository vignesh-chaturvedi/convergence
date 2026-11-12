"""The Divergence importer, on reports produced by running Divergence itself.

The fixtures are real output of Divergence's dynamic tier, at a recorded commit (see
tests/fixtures/divergence/README.md). Decoys, secrets, and blocked attempts must survive the
import, flagged, and must never become grants.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from convergence.generate.elf import elf_interpreter
from convergence.generate.policy import generate, render
from convergence.importers.divergence import NO_BASELINE, ImportError_, import_divergence
from convergence.observe.model import Event, Observation
from convergence.policy.load import parse_policy

FIXTURES = Path(__file__).parent / "fixtures" / "divergence"
COMMIT = "8c15b5fe3cbcb084ce2a6615a47a06f5a8575edb"


def imported(name: str, baseline: Observation | None = None) -> Observation:
    path = FIXTURES / name
    return import_divergence(
        path, json.loads(path.read_text()), baseline=baseline, divergence_commit=COMMIT
    )


@pytest.mark.parametrize("name", ["probe.sandbox.json", "probe.scan.json"])
def test_both_report_formats_import_the_same_events(name: str) -> None:
    obs = imported(name)
    assert obs.source == "divergence"
    assert obs.complete is False
    assert obs.provenance["divergence_commit"] == COMMIT
    assert obs.provenance["runner_version"] == "1.1.0"
    seen = [(e.kind, e.op, e.path or e.address, e.decoy, e.secret, e.blocked) for e in obs.events]
    assert seen == [
        ("file", "read", "/home/user/divergence-probe/artifact/data.csv", False, False, False),
        ("file", "write", seen[1][2], False, False, False),
        ("file", "delete", seen[2][2], False, False, False),
        ("file", "write", "${SCRATCH}/summary.txt", False, False, False),
        ("exec", "exec", "/bin/true", False, False, False),
        ("net", "connect", "127.0.0.1", False, False, True),
        ("file", "read", "${HOME}/.ssh/id_rsa", True, True, False),
    ]
    assert str(seen[1][2]).startswith("${SCRATCH}/")
    assert obs.events[5].port == 443
    assert obs.events[6].requested is not None
    assert "divergence-overlay-" in obs.events[6].requested
    assert NO_BASELINE in obs.warnings


def test_the_generated_policy_never_grants_decoys_secrets_or_blocked_attempts() -> None:
    generated = generate(imported("probe.sandbox.json"))
    policy = generated.policy
    true = os.path.realpath("/bin/true")
    loader = elf_interpreter(true)
    expected = sorted([true] + ([os.path.realpath(loader)] if loader else []))
    assert policy["filesystem"]["execute"] == expected
    assert policy["filesystem"]["write"] == ["${SCRATCH}"]
    read = [e if isinstance(e, str) else e["path"] for e in policy["filesystem"]["read"]]
    assert read == ["/home/user/divergence-probe/artifact/data.csv"]
    assert policy["network"] == {}
    assert policy["environment"]["set"] == {"TMPDIR": "${SCRATCH}"}
    text = "\n".join(generated.warnings)
    assert ".ssh/id_rsa was a decoy; never granted" in text
    assert "network attempt was blocked; not granted" in text
    assert "no runtime baseline" in text
    rendered = render(generated)
    assert "id_rsa" not in rendered.split("version: 1", 1)[1]
    parse_policy(rendered)


def test_a_runtime_baseline_is_merged_and_renumbered() -> None:
    baseline = Observation(
        id="base",
        created_at="2026-11-12T00:00:00Z",
        source="strace",
        command=["python3", "-c", "pass"],
        cwd="/w",
        home="/home/user",
        complete=True,
        events=[Event(id="e1", kind="file", op="read", path="/usr/lib/python3.12/os.py")],
        processes=[10],
        environment_names=["PATH"],
    )
    obs = imported("probe.sandbox.json", baseline=baseline)
    assert NO_BASELINE not in obs.warnings
    assert obs.events[-1].id == "e8"
    assert obs.events[-1].path == "/usr/lib/python3.12/os.py"
    assert any("runtime baseline merged" in line for line in obs.limitations)


def test_other_files_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ImportError_, match="neither"):
        import_divergence(tmp_path / "x.json", {"schema": "something/1"})
    dynamic = {
        "ran": False,
        "observations": [],
        "coverage": {},
        "unavailable_reason": "no Landlock",
    }
    not_run = {"targets": [{"name": "t", "dynamic": dynamic}]}
    with pytest.raises(ImportError_, match="no Landlock"):
        import_divergence(tmp_path / "x.json", not_run)
