"""``convergence explain --run``: why each denial happened, and the smallest fix.

For every denial in a run record (``run --trace``), this gives:
- the cause;
- the policy rule that decided it;
- the smallest policy change that would permit it, as a YAML diff;
- a risk note.

It never changes the policy. Baseline protections cannot be relaxed by a policy, and are
explained rather than offered as a change.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from convergence.policy.baseline import DENIED_SYSCALLS
from convergence.policy.model import Policy
from convergence.policy.validate import CREDENTIAL_PATHS, HOST_SERVICE_SOCKETS
from convergence.runtime.record import Denial, RunRecord

FAMILY = re.compile(r"^socket\((?P<family>AF_[A-Z0-9]+), (?P<type>SOCK_[A-Z]+)")
CREATE_CALLS = frozenset(
    {
        "creat", "mkdir", "mkdirat", "mknod", "mknodat", "symlink", "symlinkat", "link",
        "linkat", "rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir",
    }
)  # fmt: skip
BUILTIN_REASONS = {d.name: d.reason for d in DENIED_SYSCALLS}
RESOURCE_UNITS = {
    "cpu_seconds": "s",
    "memory_mb": "MiB",
    "address_space_mb": "MiB",
    "max_processes": "processes",
    "max_file_size_mb": "MiB",
    "max_open_files": "files",
    "wall_clock_seconds": "s",
}


@dataclass(slots=True)
class Explanation:
    mechanism: str
    what: str  # the operation, e.g. "openat /etc/passwd"
    count: int
    cause: str
    rule: str
    change: str | None  # a YAML diff, or None when no policy change can permit it
    risk: str
    pids: list[int] = field(default_factory=list)


def _diff(section: list[str], added: list[str], removed: list[str] | None = None) -> str:
    lines = ["--- policy", "+++ policy (suggested; not applied)"]
    lines += [f" {line}" for line in section]
    lines += [f"-{line}" for line in removed or []]
    lines += [f"+{line}" for line in added]
    return "\n".join(lines)


def _list_entry(value: str | int, indent: int = 4) -> str:
    return " " * indent + "- " + (json.dumps(value) if isinstance(value, str) else str(value))


class _Explainer:
    def __init__(self, record: RunRecord, policy: Policy | None) -> None:
        self.record = record
        self.policy = policy
        self.home = os.environ.get("HOME")

    def path_risk(self, path: str, bucket: str, directory: bool) -> str:
        notes: list[str] = []
        if self.home and any(
            path == f"{self.home}/{c}" or path.startswith(f"{self.home}/{c}/")
            for c in CREDENTIAL_PATHS
        ):
            notes.append(f"{path} is a credential location: granting it exposes secrets")
        elif self.home and (path == self.home or path.startswith(self.home + "/")):
            notes.append(f"this grants {bucket} access under your home directory ({path})")
        if path in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers") or path.startswith(
            "/etc/ssl/private"
        ):
            notes.append(f"{path} holds system secrets")
        if bucket == "write" and directory:
            notes.append(f"the tool could create, delete, and rename anything under {path}")
        elif bucket == "write":
            notes.append(f"the tool could change or truncate {path}")
        if bucket == "execute":
            notes.append(f"the tool could run {path}, with the sandbox still applied")
        return "; ".join(notes) or f"grants {bucket} on {path} only"

    def filesystem(self, denial: Denial) -> tuple[str, str, str | None, str]:
        bucket = denial.rule.split(".", 1)[1] if "." in denial.rule else "read"
        paths = [p for p in denial.target.split(" -> ") if p]
        target = paths[-1] if paths else denial.target
        directory = denial.syscall in CREATE_CALLS or (
            bucket == "write" and "O_CREAT" in denial.line
        )
        grant = os.path.dirname(target) if directory else target
        cause = f"Landlock denied {denial.syscall} on {denial.target} ({denial.errno})"
        rule = f"no grant in filesystem.{bucket} covers {grant}"
        if directory:
            rule += " (creating, removing, or renaming entries needs write on the directory)"
        change = _diff(["filesystem:", f"  {bucket}:"], [_list_entry(grant)])
        return cause, rule, change, self.path_risk(grant, bucket, directory)

    def network(self, denial: Denial) -> tuple[str, str, str | None, str]:
        port = denial.target.removeprefix("port ").strip()
        key = denial.rule.removeprefix("network.")
        cause = f"Landlock denied {denial.syscall} to {denial.target} ({denial.errno})"
        if not port.isdigit():
            return cause, f"{denial.rule} does not include that port", None, ""
        rule = f"network.{key} does not include port {port}"
        change = _diff(["network:", f"  {key}:"], [_list_entry(int(port))])
        risk = (
            f"Landlock filters ports, not hosts: this allows port {port} on every host"
            if key in ("tcp_connect", "udp_send")
            else f"the tool could listen on port {port}"
        )
        return cause, rule, change, risk

    def seccomp(self, denial: Denial) -> tuple[str, str, str | None, str]:
        name = denial.syscall
        cause = f"the seccomp filter denied {name} ({denial.errno})"
        policy = self.policy
        if name in BUILTIN_REASONS:
            return (
                cause,
                f"{name} is on Convergence's built-in deny list ({BUILTIN_REASONS[name]})",
                None,
                "baseline protections cannot be relaxed by a policy",
            )
        if policy is not None and name in policy.syscalls.deny:
            entries = [_list_entry(n) for n in policy.syscalls.deny]
            kept = [_list_entry(n) for n in policy.syscalls.deny if n != name]
            return (
                cause,
                f"the policy denies {name} in syscalls.deny",
                _diff(["syscalls:", "  deny:"], kept, entries),
                f"the tool could call {name} again",
            )
        if denial.rule == "syscalls.allow":
            return (
                cause,
                f"{name} is not in syscalls.allow (allow-list mode)",
                _diff(["syscalls:", "  allow:"], [_list_entry(name)]),
                f"the tool could call {name}",
            )
        if name == "socket":
            return self.socket(denial, cause)
        return (
            cause,
            denial.rule or "an argument rule of the baseline filter",
            None,
            ("baseline protections cannot be relaxed by a policy"),
        )

    def socket(self, denial: Denial, cause: str) -> tuple[str, str, str | None, str]:
        match = FAMILY.match(denial.line)
        family = match.group("family") if match else ""
        kind = match.group("type") if match else ""
        if family == "AF_UNIX":
            sockets = ", ".join(HOST_SERVICE_SOCKETS[:2])
            return (
                cause,
                "network.unix_sockets is deny, and this kernel cannot limit unix sockets to the "
                "sandbox (that needs Landlock ABI 9), so creating them is denied",
                _diff(["network:"], ["  unix_sockets: allow"]),
                f"unix sockets reach host services such as {sockets} (root-equivalent)",
            )
        if family in ("AF_INET", "AF_INET6") and kind == "SOCK_DGRAM":
            return (
                cause,
                "no UDP port is granted, so UDP sockets cannot be created",
                _diff(["network:", "  udp_send:"], ["    - PORT  # the port the tool sends to"]),
                "Landlock filters UDP ports only from ABI 10; below it any UDP port is reachable",
            )
        if family in ("AF_INET", "AF_INET6") and kind == "SOCK_STREAM":
            return (
                cause,
                "no TCP port is granted (or the protocol is not TCP, which is never allowed)",
                _diff(
                    ["network:", "  tcp_connect:"], ["    - PORT  # the port the tool connects to"]
                ),
                "Landlock filters ports, not hosts",
            )
        return (
            cause,
            f"socket family {family or 'unknown'} is not allowed in any policy",
            None,
            "only unix, IPv4, and IPv6 sockets can be granted",
        )

    def rlimit(self, denial: Denial) -> tuple[str, str, str | None, str]:
        name = denial.rule.removeprefix("resources.")
        current = getattr(self.policy.resources, name, None) if self.policy else None
        what = denial.syscall or "the tool"
        cause = f"{what} hit resources.{name} ({denial.errno or denial.syscall})"
        unit = RESOURCE_UNITS.get(name, "")
        if current is None:
            return cause, f"resources.{name} is set by the policy", None, ""
        new = current * 2
        return (
            cause,
            f"resources.{name} is {current} {unit}".strip(),
            _diff(["resources:"], [f"  {name}: {new}"], [f"  {name}: {current}"]),
            f"every process of the tool could use up to {new} {unit}".strip(),
        )

    def explain(self, denial: Denial) -> tuple[str, str, str | None, str]:
        if denial.mechanism == "landlock-filesystem":
            return self.filesystem(denial)
        if denial.mechanism == "landlock-network":
            return self.network(denial)
        if denial.mechanism == "seccomp":
            return self.seccomp(denial)
        if denial.mechanism in ("rlimit", "timeout"):
            return self.rlimit(denial)
        return (
            f"{denial.syscall} failed with {denial.errno}",
            "nothing in the sandbox explains it (for example: file permissions, or a path "
            "inside a grant that does not exist)",
            None,
            "",
        )


def explain_run(record: RunRecord, policy: Policy | None) -> list[Explanation]:
    explainer = _Explainer(record, policy)
    merged: dict[tuple[str, str, str], Explanation] = {}
    for denial in record.denials:
        cause, rule, change, risk = explainer.explain(denial)
        what = " ".join(x for x in (denial.syscall, denial.target) if x) or denial.mechanism
        key = (denial.mechanism, rule, change or "")
        if key in merged:
            merged[key].count += 1
            if denial.pid not in merged[key].pids:
                merged[key].pids.append(denial.pid)
            continue
        merged[key] = Explanation(
            denial.mechanism, what, 1, cause, rule, change, risk, [denial.pid]
        )
    return list(merged.values())


def render_text(record: RunRecord, explanations: list[Explanation], policy_note: str) -> str:
    lines = [f"run {record.id}: {' '.join(record.command)}", f"  {policy_note}"]
    if not record.tracing.active and not record.denials:
        lines.append(
            "  This run was not traced, so its denials were not recorded. Run it again with "
            "`convergence run --trace` and explain that run."
        )
        return "\n".join(lines) + "\n"
    if not explanations:
        lines.append("  No denials were recorded.")
        return "\n".join(lines) + "\n"
    for index, item in enumerate(explanations, 1):
        times = f" ({item.count} times)" if item.count > 1 else ""
        lines += ["", f"{index}. [{item.mechanism}] {item.what}{times}"]
        lines.append(f"   cause: {item.cause}")
        lines.append(f"   rule:  {item.rule}")
        if item.change:
            lines.append("   smallest change that would permit it:")
            lines += [f"     {line}" for line in item.change.splitlines()]
        else:
            lines.append("   no policy change can permit it")
        if item.risk:
            lines.append(f"   risk:  {item.risk}")
    lines += ["", "Nothing was changed. Review each change before applying it to the policy."]
    return "\n".join(lines) + "\n"


def to_json(record: RunRecord, explanations: list[Explanation]) -> str:
    return json.dumps(
        {
            "schema": "convergence.explanation/1",
            "run": record.id,
            "traced": record.tracing.active,
            "explanations": [asdict(e) for e in explanations],
        },
        indent=2,
    )


def find_record(reference: str, runs: Path) -> Path:
    """A run id (from the runs directory) or a path to a record file."""
    candidate = Path(reference)
    if candidate.is_file():
        return candidate
    named = runs / f"{reference}.json"
    if named.is_file():
        return named
    raise FileNotFoundError(f"no run record {reference!r} (looked in {runs})")


def load_record(path: Path) -> RunRecord:
    from pydantic import TypeAdapter

    data: Any = json.loads(path.read_text())
    return TypeAdapter(RunRecord).validate_python(data)
