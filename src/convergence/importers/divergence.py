"""Importing a Divergence report as a (partial) observation (PLAN section 3.1).

Divergence's dynamic tier runs an MCP server or a skill inside its own sandbox and reports
what it touched (``divergence.sandbox/1``). ``divergence scan --json`` embeds those reports
under ``targets[].dynamic``. Both are accepted.

Such a report is never complete for policy purposes:
- Divergence drops runtime noise on purpose (``/usr/lib``, ``/lib``, ``/etc``, ``/proc``,
  ``/sys``, ``/dev``, ``site-packages``, ``*.py``, ``*.so``);
- it caps observations at 10,000;
- its sandbox denies the network, so every network attempt is a blocked one.

So the import is marked partial, decoys, secrets, and blocked attempts are kept but flagged
never to be granted, and the user is asked for a runtime baseline that Convergence observes
itself. Without one, the generated policy fails closed on the runtime's own paths.
"""

from __future__ import annotations

import errno
import hashlib
import re
from pathlib import Path
from typing import Any

from convergence.observe.model import Event, Observation
from convergence.runtime.record import new_run_id, now_iso

SANDBOX_SCHEMA = "divergence.sandbox/1"
NOISE = (
    "Divergence drops runtime noise on purpose (/usr/lib, /lib, /etc, /proc, /sys, /dev, "
    "site-packages, *.py, *.so) and caps observations at 10,000: the report describes the "
    "artifact's interesting behaviour, not every file its interpreter needs"
)
NO_BASELINE = (
    "no runtime baseline was merged: the policy will fail closed on the interpreter's own "
    "paths. Observe the runtime with `convergence observe -- <interpreter> -c pass` (or a "
    "trivial run of the tool) and pass it with --baseline"
)
INET = re.compile(r"^(?P<host>\d+\.\d+\.\d+\.\d+|\[ipv6\]):(?P<port>\d+)$")
# Divergence runs each artifact in a private overlay, with its own scratch and HOME.
OVERLAY = re.compile(
    r"^(?P<root>/(?:[^/]+/)*divergence-overlay-[^/]+)/(?P<area>scratch|home)(?P<rest>/.*)?$"
)
SECRET = re.compile(r"/\.ssh/|/\.aws/|/\.netrc$|/credentials|/secrets/|/keychain|/etc/g?shadow$")


class ImportError_(Exception):
    """The file is not a Divergence report this importer understands."""


def find_reports(data: Any) -> list[tuple[str, dict[str, Any]]]:
    """(label, sandbox report) pairs from a sandbox report or a ``scan --json`` document."""
    if isinstance(data, dict) and data.get("schema") == SANDBOX_SCHEMA:
        return [("report", data)]
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, list):
        raise ImportError_(f"neither a {SANDBOX_SCHEMA} report nor `divergence scan --json` output")
    found: list[tuple[str, dict[str, Any]]] = []
    skipped: list[str] = []
    for index, target in enumerate(targets):
        dynamic = target.get("dynamic") if isinstance(target, dict) else None
        if not isinstance(dynamic, dict):
            continue
        label = str(target.get("name") or target.get("source") or f"target {index}")
        # `scan --json` embeds the runner's fields directly, without its schema key.
        if not ("observations" in dynamic and "coverage" in dynamic):
            continue
        if not dynamic.get("ran", False):
            skipped.append(f"{label}: {dynamic.get('unavailable_reason') or 'did not run'}")
            continue
        found.append((label, dynamic))
    if not found:
        detail = f" ({'; '.join(skipped)})" if skipped else ""
        raise ImportError_(f"the scan output contains no dynamic report that ran{detail}")
    return found


def _result(item: dict[str, Any]) -> str:
    if item.get("succeeded"):
        return "ok"
    value = item.get("result")
    if isinstance(value, int) and value < 0:
        return errno.errorcode.get(-value, f"E{-value}")
    return "EBLOCKED"


def _map_overlay(target: str) -> str:
    """Divergence's private scratch becomes ${SCRATCH}; its private HOME becomes ${HOME}."""
    match = OVERLAY.match(target)
    if match is None:
        return target
    variable = "${SCRATCH}" if match.group("area") == "scratch" else "${HOME}"
    return variable + (match.group("rest") or "")


def _events(report: dict[str, Any], start: int) -> list[Event]:
    events: list[Event] = []
    for item in report.get("observations", []):
        capability = str(item.get("capability", ""))
        raw_target = str(item.get("target", ""))
        target = _map_overlay(raw_target)
        syscall = str(item.get("syscall", ""))
        event = Event(
            id=f"e{start + len(events) + 1}",
            kind="file",
            op="read",
            result=_result(item),
            syscall=syscall,
            decoy=bool(item.get("decoy", False)),
            blocked=not item.get("succeeded", False),
            requested=raw_target if target != raw_target else None,
        )
        if capability in ("fs_read", "secrets_read"):
            event.path = target
            event.secret = capability == "secrets_read" or bool(SECRET.search(target))
        elif capability in ("fs_write", "fs_delete"):
            event.op = "write" if capability == "fs_write" else "delete"
            event.path = target
        elif capability == "proc_spawn" and target.startswith("/"):
            event.kind, event.op, event.path = "exec", "exec", target
        elif capability in ("net_outbound", "net_listen"):
            event.kind = "net"
            if capability == "net_listen":
                event.op = "bind"
            else:
                event.op = "send" if "send" in syscall else "connect"
            if target.startswith("unix:"):
                event.protocol, event.address = "unix", target[5:]
            else:
                match = INET.match(target)
                if match is None:
                    continue  # "socket fd N", or a family Divergence names only by number
                # Divergence does not record TCP or UDP; a send is taken as UDP.
                event.protocol = "udp" if event.op == "send" else "tcp"
                event.port = int(match.group("port"))
                event.address = match.group("host")
        else:
            continue
        events.append(event)
    return events


def import_divergence(
    path: Path,
    data: Any,
    *,
    baseline: Observation | None = None,
    divergence_commit: str | None = None,
) -> Observation:
    """An observation built from every sandbox report in ``data``."""
    reports = find_reports(data)
    events: list[Event] = []
    limitations = [NOISE, "imported, so partial: generated policies must be reviewed"]
    warnings: list[str] = []
    syscalls_observed = 0
    for label, report in reports:
        new = _events(report, len(events))
        events += new
        coverage = report.get("coverage", {}) or {}
        syscalls_observed += int(coverage.get("syscalls_observed", 0) or 0)
        if coverage.get("observations_dropped"):
            limitations.append(
                f"{label}: Divergence dropped {coverage['observations_dropped']} observations"
            )
        if coverage.get("timed_out"):
            limitations.append(f"{label}: the Divergence run timed out")
        if not coverage.get("confinement_enforced", True):
            warnings.append(f"{label}: Divergence reports its confinement was NOT enforced")
        failed = coverage.get("entrypoints_failed", 0)
        if failed:
            limitations.append(f"{label}: {failed} entrypoint(s) failed in Divergence's run")
        for line in report.get("limitations", []) or []:
            limitations.append(f"{label}: {line}")
    if any((e.path or "").startswith("${") for e in events):
        limitations.append(
            "paths in Divergence's private overlay were mapped: its scratch to ${SCRATCH}, its "
            "HOME to ${HOME} (which held only Divergence's sanitized files and decoys)"
        )
    if any(e.kind == "net" and e.blocked for e in events):
        limitations.append(
            "Divergence's sandbox denies the network, so network attempts are reported but "
            "never granted; and it does not record TCP or UDP, which is inferred from the call"
        )
    if baseline is not None:
        offset = len(events)
        for event in baseline.events:
            copy = Event(**{**_as_dict(event), "id": f"e{offset + _number(event.id)}"})
            events.append(copy)
        limitations.append(f"runtime baseline merged from observation {baseline.id}")
    else:
        warnings.append(NO_BASELINE)
    provenance = {
        "report": str(path),
        "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "runner_version": str(reports[0][1].get("runner_version", "")),
    }
    provenance["divergence_syscalls_observed"] = str(syscalls_observed)
    if divergence_commit:
        provenance["divergence_commit"] = divergence_commit
    return Observation(
        id=new_run_id(),
        created_at=now_iso(),
        source="divergence",
        command=[label for label, _ in reports],
        cwd=baseline.cwd if baseline else str(path.parent.resolve()),
        home=baseline.home if baseline else None,
        complete=False,
        events=events,
        processes=baseline.processes if baseline else [],
        environment_names=baseline.environment_names if baseline else [],
        syscalls=dict(baseline.syscalls) if baseline else {},
        limitations=limitations,
        warnings=warnings,
        provenance=provenance,
    )


def _number(event_id: str) -> int:
    return int(event_id[1:]) if event_id[1:].isdigit() else 0


def _as_dict(event: Event) -> dict[str, Any]:
    return {name: getattr(event, name) for name in Event.__slots__}
