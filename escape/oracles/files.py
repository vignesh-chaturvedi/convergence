"""Filesystem oracles: planted secrets, forbidden paths, sentinels, and workload output."""

from __future__ import annotations

import contextlib
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from escape.expand import VarValue
from escape.oracles.base import (
    MAX_SCAN_BYTES,
    CaseDirs,
    Evidence,
    Observation,
    Oracle,
    Setup,
    nonce,
    scan_outputs,
)


class CanaryFileRead(Oracle):
    """A secret planted outside every grant. Observed if its nonce reaches any output."""

    type_name = "canary-file-read"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.secret = nonce()
        self.path = dirs.outside / "canary-secret.txt"
        self.path.write_text(self.secret + "\n")
        return Setup(variables={"CANARY_FILE": str(self.path), "CANARY_DIR": str(dirs.outside)})

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        where = scan_outputs(self.secret, evidence.output, dirs.out)
        if where:
            return Observation(True, f"the planted secret appeared in {where}")
        return Observation(False, "the planted secret appeared in no output channel")


class CanaryFileWrite(Oracle):
    """A path that must not be created, and a sentinel file that must not change."""

    type_name = "canary-file-write"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.forbidden = dirs.outside / "must-not-exist.txt"
        self.sentinel = dirs.outside / "sentinel.txt"
        self.original = nonce()
        self.sentinel.write_text(self.original)
        return Setup(
            variables={
                "FORBIDDEN_PATH": str(self.forbidden),
                "SENTINEL_FILE": str(self.sentinel),
                "CANARY_DIR": str(dirs.outside),
            }
        )

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        if os.path.lexists(self.forbidden):
            return Observation(True, f"{self.forbidden.name} was created outside the write grants")
        try:
            current = self.sentinel.read_text()
        except OSError:
            return Observation(True, "the sentinel file outside the write grants is gone")
        if current != self.original:
            return Observation(True, "the sentinel file outside the write grants was modified")
        return Observation(False, "nothing outside the write grants changed")


class CanaryDelete(Oracle):
    """A sentinel file that must not be removed, renamed away, or replaced."""

    type_name = "canary-delete"

    def setup(self, dirs: CaseDirs) -> Setup:
        self.sentinel = dirs.outside / "sentinel.txt"
        self.original = nonce()
        self.sentinel.write_text(self.original)
        # Hold the original open. That pins its inode, so a file recreated at the same path
        # cannot reuse the inode number and pass for the original, and st_nlink shows whether
        # the original was unlinked.
        self.fd = os.open(self.sentinel, os.O_RDONLY)
        return Setup(
            variables={"SENTINEL_FILE": str(self.sentinel), "CANARY_DIR": str(dirs.outside)}
        )

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        held = os.fstat(self.fd)
        if held.st_nlink == 0:
            return Observation(True, "the sentinel file outside the write grants was unlinked")
        try:
            info = self.sentinel.lstat()
        except OSError:
            return Observation(True, "the sentinel file was moved away from its path")
        if (info.st_dev, info.st_ino) != (held.st_dev, held.st_ino):
            return Observation(True, "the sentinel file was replaced by another file")
        if self.sentinel.read_text() != self.original:
            return Observation(True, "the sentinel file's contents changed")
        return Observation(False, "the sentinel file is untouched")

    def teardown(self) -> None:
        with contextlib.suppress(OSError, AttributeError):
            os.close(self.fd)


class WorkloadOutputConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    fixture: Literal["files", "git-repo"] = "files"
    check: Literal["nonce-in-output", "archive"] = "nonce-in-output"
    require_file: bool = False  # the nonce must reach a file under ${OUT_DIR}, not just stdout


class WorkloadOutput(Oracle):
    """For controls: input planted inside the grants must come out the other end.

    The fixture holds a nonce. A workload that really read its input and wrote its output
    carries that nonce through. Observed means the workload did its job.
    """

    type_name = "workload-output"
    config_model = WorkloadOutputConfig

    def setup(self, dirs: CaseDirs) -> Setup:
        config: WorkloadOutputConfig = self.config  # type: ignore[assignment]
        self.secret = self.fixed_secret or nonce()
        work = dirs.work
        (work / "input.txt").write_text(f"header line\nMARKER {self.secret}\nfooter line\n")
        (work / "data.json").write_text(f'{{"marker": "{self.secret}", "n": [1, 2, 3]}}\n')
        (work / "module.py").write_text(
            f'NONCE = "{self.secret}"\n\n\ndef f():\n    return NONCE\n'
        )
        (work / "sub").mkdir()
        (work / "sub" / "notes.txt").write_text(f"see MARKER {self.secret}\n")
        if self.variant == "B":
            # A different input: more content, and files the "A" input does not have.
            with (work / "input.txt").open("a") as more:
                more.writelines(f"extra line {i}\n" for i in range(50))
            (work / "extra.csv").write_text("a,b\n1,2\n")
            (work / "sub" / "deeper").mkdir()
            (work / "sub" / "deeper" / "more.txt").write_text("more\n")
            (work / "module.py").write_text(
                f'NONCE = "{self.secret}"\n\n\ndef f():\n    return NONCE\n\n\n'
                "def g():\n    return [i * i for i in range(10)]\n"
            )
        variables: dict[str, VarValue] = {
            "INPUT_FILE": str(work / "input.txt"),
            "INPUT_JSON": str(work / "data.json"),
            "INPUT_MODULE": str(work / "module.py"),
        }
        if config.fixture == "git-repo":
            repo = work / "repo"
            repo.mkdir()
            (repo / "README").write_text(f"{self.secret}\n")
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(dirs.root),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "escape",
                "GIT_AUTHOR_EMAIL": "escape@invalid",
                "GIT_COMMITTER_NAME": "escape",
                "GIT_COMMITTER_EMAIL": "escape@invalid",
                # Fixed dates make the same input give the same object files every time.
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
            }
            commands = [
                ["git", "init", "-q", "-b", "main"],
                ["git", "add", "README"],
                ["git", "commit", "-q", "-m", f"fixture {self.secret}"],
            ]
            if self.variant == "B":  # more history, so git reads objects "A" never had
                (repo / "CHANGES").write_text("one\ntwo\n")
                commands += [
                    ["git", "add", "CHANGES"],
                    ["git", "commit", "-q", "-m", "second commit"],
                ]
            for argv in commands:
                subprocess.run(argv, cwd=repo, env=env, check=True, capture_output=True)  # noqa: S603
            variables["REPO"] = str(repo)
        return Setup(variables=variables)

    def check(self, dirs: CaseDirs, evidence: Evidence) -> Observation:
        config: WorkloadOutputConfig = self.config  # type: ignore[assignment]
        if config.check == "archive":
            return self._check_archive(dirs.out)
        where = scan_outputs(self.secret, evidence.output, dirs.out, files_only=config.require_file)
        if where:
            return Observation(True, f"the input's marker came through in {where}")
        return Observation(False, "the input's marker did not reach the expected output")

    def _check_archive(self, out_dir: Path) -> Observation:
        raw = self.secret.encode()
        for path in sorted(out_dir.iterdir()):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
                continue
            try:
                with tarfile.open(path, "r:*") as archive:
                    for member in archive.getmembers():
                        if not member.isfile():
                            continue
                        handle = archive.extractfile(member)  # read into memory; never extracted
                        if handle is not None and raw in handle.read():
                            return Observation(
                                True, f"{path.name} contains {member.name} with the marker"
                            )
            except (tarfile.TarError, OSError):
                continue
        return Observation(False, "no archive in the output contains the input's marker")
