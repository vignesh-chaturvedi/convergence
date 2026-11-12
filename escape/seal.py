"""The holdout seal: a committed SHA-256 manifest of every holdout file.

Format of escape/cases/holdout.sha256: one ``<sha256>  <path>`` line per file under
escape/cases/holdout/ (paths relative to the repository, sorted), then a final
``<sha256>  MANIFEST`` line with the digest of the lines above it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOLDOUT_DIR = REPO / "escape" / "cases" / "holdout"
MANIFEST = REPO / "escape" / "cases" / "holdout.sha256"
IGNORED = {".gitkeep"}


def holdout_files(directory: Path = HOLDOUT_DIR, base: Path = REPO) -> list[Path]:
    if not directory.exists():
        return []
    files = [p for p in directory.rglob("*") if p.is_file() and p.name not in IGNORED]
    return sorted(files, key=lambda p: p.relative_to(base).as_posix())


def manifest_text(files: list[Path], base: Path = REPO) -> str:
    lines = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(base).as_posix()}"
        for p in files
    ]
    body = "".join(line + "\n" for line in lines)
    return body + f"{hashlib.sha256(body.encode()).hexdigest()}  MANIFEST\n"


def seal(directory: Path = HOLDOUT_DIR, manifest: Path = MANIFEST, base: Path = REPO) -> int:
    """Write the manifest. Returns how many files were sealed."""
    files = holdout_files(directory, base)
    if not files:
        manifest.unlink(missing_ok=True)
        return 0
    manifest.write_text(manifest_text(files, base))
    return len(files)


def _entries(text: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in text.splitlines()[:-1]:
        digest, _, path = line.partition("  ")
        entries[path] = digest
    return entries


def verify(
    directory: Path = HOLDOUT_DIR, manifest: Path = MANIFEST, base: Path = REPO
) -> list[str]:
    """Problems with the seal; empty means the holdout matches what was committed."""
    files = holdout_files(directory, base)
    if not manifest.exists():
        return [f"the holdout has {len(files)} file(s) but is not sealed"] if files else []
    if not files:
        return ["a holdout manifest exists but the holdout directory is empty"]
    committed = manifest.read_text()
    current = manifest_text(files, base)
    if committed == current:
        return []
    old, new = _entries(committed), _entries(current)
    problems = [f"added after sealing: {p}" for p in sorted(new.keys() - old.keys())]
    problems += [f"removed after sealing: {p}" for p in sorted(old.keys() - new.keys())]
    problems += [
        f"changed after sealing: {p}" for p in sorted(old.keys() & new.keys()) if old[p] != new[p]
    ]
    return problems or ["the manifest's own digest does not match its contents"]
