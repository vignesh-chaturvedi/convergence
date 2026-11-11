"""The CLI skeleton: version reporting and an honest no-op."""

from __future__ import annotations

import subprocess
import sys

import pytest

from convergence import __version__
from convergence.cli import main


def test_version_flag_prints_installed_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"convergence {__version__}"


def test_version_comes_from_installed_metadata() -> None:
    # "0+unknown" would mean the package metadata was not found, i.e. a broken install.
    assert __version__ != "0+unknown"


def test_no_arguments_prints_help_and_states_status(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "usage: convergence" in out
    # argparse wraps the description to the terminal width, so compare word sequences.
    assert "no enforcement is implemented yet" in " ".join(out.split())


def test_module_entry_point_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "convergence", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"convergence {__version__}"
