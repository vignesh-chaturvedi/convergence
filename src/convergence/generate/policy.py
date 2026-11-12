"""Generating a policy from an observation (ADR 0009).

Grants are exact unless an operation needs a directory, or a runtime tree is read heavily
enough to be collapsed. Every rule keeps the ids of the events that justify it. Credential
locations, other processes' ``/proc`` entries, and unix-socket connections are never
granted; they become warnings.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from convergence.generate.elf import elf_interpreter, shebang_interpreter
from convergence.observe.model import Event, Observation
from convergence.policy.load import parse_policy
from convergence.policy.model import MAX_WALL_CLOCK_SECONDS, Resources
from convergence.policy.validate import CREDENTIAL_PATHS

MIN_COLLAPSE = 5
COLLAPSE_ROOTS = (
    "/usr/lib",
    "/usr/lib64",
    "/usr/share",
    "/usr/local/lib",
    "/lib",
    "/lib64",
    "/opt",
)
COLLAPSE_MARKERS = ("site-packages", "dist-packages", "node_modules")
PASSED_ENVIRONMENT = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ")
# A connect that the network refused still shows the tool needs the port.
GRANTED_NET_RESULTS = frozenset(
    {"ok", "ECONNREFUSED", "ETIMEDOUT", "ENETUNREACH", "EHOSTUNREACH", "EINPROGRESS", "ECONNRESET"}
)
PROC_PID = re.compile(r"^/proc/(?P<pid>\d+)(?P<rest>/.*)?$")
SYSCALL_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")
BUCKETS = ("read", "write", "execute")


@dataclass(slots=True)
class Reason:
    rule: str  # e.g. "filesystem.read"
    value: str  # the path, port, or setting
    events: list[str]
    why: str


@dataclass(slots=True)
class Generated:
    policy: dict[str, Any]
    reasons: list[Reason]
    warnings: list[str]
    observation_id: str
    complete: bool

    def rationale_json(self) -> str:
        return json.dumps(
            {
                "schema": "convergence.rationale/1",
                "observation": self.observation_id,
                "observation_complete": self.complete,
                "rules": [
                    {"rule": r.rule, "value": r.value, "events": r.events, "why": r.why}
                    for r in self.reasons
                ],
                "warnings": self.warnings,
            },
            indent=2,
        )


@dataclass(slots=True)
class _Grant:
    bucket: str
    path: str
    is_dir: bool
    why: str
    events: list[str] = field(default_factory=list)


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def collapse_candidate(path: str) -> str | None:
    """The runtime directory a file belongs to, if it is in one (ADR 0009)."""
    parts = path.split("/")
    for index in range(len(parts) - 2, 0, -1):
        if parts[index] in COLLAPSE_MARKERS:
            return "/".join(parts[: index + 1])
    for root in COLLAPSE_ROOTS:
        if path.startswith(root + "/"):
            rest = path[len(root) + 1 :].split("/")
            if len(rest) >= 2:
                return f"{root}/{rest[0]}"
    return None


class _Generator:
    def __init__(self, observation: Observation) -> None:
        self.obs = observation
        self.home = observation.home.rstrip("/") if observation.home else None
        self.cwd = observation.cwd.rstrip("/") or "/"
        self.root_pid = observation.processes[0] if observation.processes else None
        self.warnings: list[str] = list(observation.warnings)
        self.reasons: list[Reason] = []
        self.needs: dict[tuple[str, str], list[str]] = defaultdict(list)  # (bucket, path) -> ids
        self.dir_needs: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.created: set[str] = set()
        self.notes: dict[tuple[str, str], str] = {}

    # --- paths ----------------------------------------------------------------------------

    def credential(self, path: str) -> bool:
        return self.home is not None and any(
            _under(path, f"{self.home}/{cred}") for cred in CREDENTIAL_PATHS
        )

    def forbidden_collapse(self, directory: str) -> bool:
        protected = ["/", "/etc", "/usr"] + ([self.home] if self.home else [])
        if any(_under(p, directory) for p in protected):  # directory is p or an ancestor
            return True
        return self.home is not None and any(
            _under(f"{self.home}/{c}", directory) for c in CREDENTIAL_PATHS
        )

    def absolute(self, path: str) -> str:
        if path.startswith("${HOME}") and self.home:
            path = self.home + path[len("${HOME}") :]
        if path.startswith("${"):
            return path
        return os.path.normpath(path if path.startswith("/") else os.path.join(self.cwd, path))

    def proc(self, event: Event, path: str) -> str | None:
        """Map /proc paths; None means: do not grant (a warning was added)."""
        requested = event.requested or ""
        if requested.startswith(("/proc/self", "/proc/thread-self")):
            return requested
        match = PROC_PID.match(path)
        if match is None:
            return path
        pid = int(match.group("pid"))
        if pid == self.root_pid:
            return "/proc/self" + (match.group("rest") or "")
        if pid in self.obs.processes:
            self.warnings.append(
                f"{event.id}: a child process read its own {path}; a /proc/self grant covers "
                "only the tool's first process, so it is not granted"
            )
        else:
            self.warnings.append(f"{event.id}: read another process's {path}; never granted")
        return None

    def portable(self, path: str) -> str:
        if _under(path, self.cwd) and self.cwd != "/":
            return "${CWD}" + path[len(self.cwd) :]
        if self.home and _under(path, self.home):
            return "${HOME}" + path[len(self.home) :]
        return path

    # --- events ---------------------------------------------------------------------------

    def file_event(self, event: Event) -> None:
        if event.result != "ok" or event.path is None:
            if event.result in ("EACCES", "EPERM") and event.path:
                self.warnings.append(
                    f"{event.id}: {event.op} {event.path} was refused ({event.result}) while "
                    "observed; not granted"
                )
            return
        path = self.absolute(event.path)
        if event.decoy or event.blocked or event.secret:
            what = "a decoy" if event.decoy else "a secret" if event.secret else "blocked"
            self.warnings.append(f"{event.id}: {event.op} {path} was {what}; never granted")
            return
        if self.credential(path):
            self.warnings.append(
                f"{event.id}: {event.op} {path} is a credential location; never granted"
            )
            return
        if path.startswith("${SCRATCH}"):
            # Only ${SCRATCH} itself can be granted (docs/policy.md): any use needs write on it.
            self.dir_needs[("write", "${SCRATCH}")].append(event.id)
            self.notes[("write", "${SCRATCH}")] = "the tool's private temporary directory"
            return
        if path.startswith("${"):
            self.warnings.append(f"{event.id}: {event.op} {path} has no host path; not granted")
            return
        if path.startswith("/proc/"):
            mapped = self.proc(event, path)
            if mapped is None:
                return
            path = mapped
        if event.op == "read":
            self.needs[("read", path)].append(event.id)
        elif event.op == "readdir":
            self.dir_needs[("read", path)].append(event.id)
            self.notes[("read", path)] = "listed; Landlock grants reading a directory recursively"
        elif event.op in ("write", "truncate"):
            self.needs[("write", path)].append(event.id)
        else:  # create, delete, rename-from, rename-to: the directory changes
            parent = os.path.dirname(path) or "/"
            self.dir_needs[("write", parent)].append(event.id)
            self.notes[("write", parent)] = "entries created, removed, or renamed in it"
            self.created.add(path)

    def exec_event(self, event: Event) -> None:
        if event.result != "ok" or event.path is None:
            return
        if event.blocked or event.decoy or event.secret:
            self.warnings.append(f"{event.id}: exec of {event.path} was blocked; not granted")
            return
        path = os.path.realpath(self.absolute(event.path))
        self.needs[("execute", path)].append(event.id)
        interpreter = elf_interpreter(path)
        how = "its ELF interpreter (PT_INTERP)"
        if interpreter is None:
            interpreter = shebang_interpreter(path)
            how = "its #! interpreter"
        if interpreter:
            real = os.path.realpath(interpreter)
            self.needs[("execute", real)].append(event.id)
            self.notes[("execute", real)] = (
                f"{how} of {path}; the kernel loads it, no tracer sees it"
            )

    # --- assembly -------------------------------------------------------------------------

    def collapse(self) -> list[_Grant]:
        grants: list[_Grant] = []
        groups: dict[str, list[tuple[str, list[str]]]] = defaultdict(list)
        exact: list[tuple[str, list[str]]] = []
        for (bucket, path), ids in self.needs.items():
            if bucket != "read":
                continue
            candidate = collapse_candidate(path)
            if candidate and not self.forbidden_collapse(candidate):
                groups[candidate].append((path, ids))
            else:
                exact.append((path, ids))
        for directory, members in sorted(groups.items()):
            if len(members) >= MIN_COLLAPSE:
                ids = sorted({i for _, member_ids in members for i in member_ids}, key=_id_key)
                grants.append(
                    _Grant(
                        "read", directory, True, f"{len(members)} files read under {directory}", ids
                    )
                )
            else:
                exact += members
        for path, ids in exact:
            grants.append(
                _Grant("read", path, os.path.isdir(path), "read", sorted(ids, key=_id_key))
            )
        return grants

    def grants(self) -> list[_Grant]:
        grants = self.collapse()
        for (bucket, path), ids in self.needs.items():
            if bucket == "read":
                continue
            why = self.notes.get(
                (bucket, path), "opened for writing" if bucket == "write" else "executed"
            )
            grants.append(_Grant(bucket, path, os.path.isdir(path), why, sorted(ids, key=_id_key)))
        for (bucket, path), ids in self.dir_needs.items():
            grants.append(
                _Grant(
                    bucket, path, True, self.notes.get((bucket, path), ""), sorted(ids, key=_id_key)
                )
            )
        # Paths the tool created itself are covered by the write grant on their directory.
        grants = [
            g for g in grants if g.is_dir or g.path not in self.created or g.bucket == "execute"
        ]
        return _minimise(grants)

    def network(self) -> dict[str, list[tuple[int, list[str], str]]]:
        found: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
        for event in self.obs.events:
            if event.kind != "net":
                continue
            if event.decoy or event.blocked or event.secret:
                self.warnings.append(f"{event.id}: network attempt was blocked; not granted")
                continue
            if event.protocol == "unix":
                if event.result == "ok":
                    self.warnings.append(
                        f"{event.id}: connected to the unix socket {event.address}; unix sockets "
                        "can reach host services, so this is not granted (set "
                        "network.unix_sockets: allow if the tool needs it)"
                    )
                continue
            if event.port is None or event.result not in GRANTED_NET_RESULTS:
                continue
            if event.op == "bind":
                key = f"{event.protocol}_bind"
            else:
                key = "tcp_connect" if event.protocol == "tcp" else "udp_send"
            found[key][event.port].append(event.id)
        result: dict[str, list[tuple[int, list[str], str]]] = {}
        for key, ports in found.items():
            verb = {"tcp_connect": "connected to", "udp_send": "sent to"}.get(key, "bound")
            result[key] = [
                (port, sorted(ids, key=_id_key), f"{verb} port {port}")
                for port, ids in sorted(ports.items())
            ]
        return result


def _id_key(event_id: str) -> int:
    return int(event_id[1:]) if event_id[1:].isdigit() else 0


def _covers(grant: _Grant, other: _Grant) -> bool:
    if grant is other:
        return False
    if other.bucket == "write" and grant.bucket != "write":
        return False
    if other.bucket == "execute" and grant.bucket != "execute":
        return False
    if grant.path == other.path:
        order = {"read": 0, "write": 1, "execute": 1}
        return order[grant.bucket] >= order[other.bucket] and (
            grant.bucket != other.bucket or grant.is_dir >= other.is_dir
        )
    return grant.is_dir and _under(other.path, grant.path)


def _minimise(grants: list[_Grant]) -> list[_Grant]:
    """Drop grants another grant already covers, moving their event ids to the cover."""
    removed: set[int] = set()
    for index, grant in enumerate(grants):
        for other_index, other in enumerate(grants):
            if other_index == index or other_index in removed or not _covers(other, grant):
                continue
            identical = (other.bucket, other.path, other.is_dir) == (
                grant.bucket,
                grant.path,
                grant.is_dir,
            )
            if identical and other_index > index:
                continue  # of identical grants, keep the first
            removed.add(index)
            break
    kept = [g for i, g in enumerate(grants) if i not in removed]
    for index in removed:
        grant = grants[index]
        cover = next((k for k in kept if _covers(k, grant)), None)
        if cover is not None:
            cover.events = sorted(set(cover.events) | set(grant.events), key=_id_key)
    return kept


def generate(observation: Observation, *, allow_list: bool = False) -> Generated:
    gen = _Generator(observation)
    if not observation.complete:
        first = observation.limitations[0] if observation.limitations else observation.source
        more = len(observation.limitations) - 1
        gen.warnings.insert(
            0,
            f"the observation is incomplete: {first}"
            + (f" (+{more} more noted in the observation)" if more > 0 else "")
            + "; the policy will fail closed on anything it missed",
        )
    for event in observation.events:
        if event.kind == "file":
            gen.file_event(event)
        elif event.kind == "exec":
            gen.exec_event(event)
    grants = gen.grants()
    filesystem: dict[str, list[Any]] = {bucket: [] for bucket in BUCKETS}
    for grant in sorted(grants, key=lambda g: (BUCKETS.index(g.bucket), g.path)):
        value = gen.portable(grant.path)
        entry: Any = value
        if not grant.path.startswith(("/proc/self", "${")) and not os.path.exists(grant.path):
            entry = {"path": value, "optional": True}
            gen.warnings.append(
                f"{value} did not exist when the policy was generated; marked optional"
            )
        filesystem[grant.bucket].append(entry)
        gen.reasons.append(Reason(f"filesystem.{grant.bucket}", value, grant.events, grant.why))

    network: dict[str, Any] = {}
    for key, ports in gen.network().items():
        network[key] = [port for port, _, _ in ports]
        for port, ids, why in ports:
            gen.reasons.append(Reason(f"network.{key}", str(port), ids, why))

    syscalls: dict[str, Any] = {"mode": "deny-list"}
    if allow_list:
        names = sorted(
            n
            for n in observation.syscalls
            if SYSCALL_NAME.match(n) and not n.startswith("syscall_")
        )
        syscalls = {"mode": "allow-list", "allow": names}
        gen.reasons.append(
            Reason(
                "syscalls.allow", f"{len(names)} syscalls", [], "every syscall seen while observed"
            )
        )

    resources = _resources(observation, gen.reasons)
    passed = [name for name in PASSED_ENVIRONMENT if name in observation.environment_names]
    environment: dict[str, Any] = {"pass": passed}
    if "${SCRATCH}" in filesystem["write"]:
        environment["set"] = {"TMPDIR": "${SCRATCH}"}
        gen.reasons.append(
            Reason(
                "environment.set",
                "TMPDIR",
                [],
                "the tool used a private temporary directory; point TMPDIR at ${SCRATCH}",
            )
        )
    gen.reasons.append(
        Reason(
            "environment.pass",
            ", ".join(passed) or "(none)",
            [],
            "environment reads cannot be observed; standard variables the caller had are passed",
        )
    )
    command = observation.command[0] if observation.command else "tool"
    policy: dict[str, Any] = {
        "version": 1,
        "name": f"generated-{os.path.basename(command)}",
        "description": (
            f"Generated by convergence generate from observation {observation.id} "
            f"({observation.source}, {'complete' if observation.complete else 'partial'})."
        ),
        "filesystem": filesystem,
        "network": network,
        "syscalls": syscalls,
        "resources": resources,
        "environment": environment,
    }
    return Generated(
        policy, gen.reasons, _dedupe(gen.warnings), observation.id, observation.complete
    )


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _resources(observation: Observation, reasons: list[Reason]) -> dict[str, Any]:
    defaults = Resources()
    wall = max(defaults.wall_clock_seconds, math.ceil(observation.duration_seconds * 3))
    wall = min(wall, MAX_WALL_CLOCK_SECONDS)
    resources: dict[str, Any] = {"wall_clock_seconds": wall}
    reasons.append(
        Reason(
            "resources.wall_clock_seconds",
            str(wall),
            [],
            f"observed {observation.duration_seconds:.1f} s; the default, or 3 times that",
        )
    )
    processes = len(observation.processes)
    if defaults.max_processes is not None and processes * 2 > defaults.max_processes:
        resources["max_processes"] = processes * 2
        reasons.append(
            Reason(
                "resources.max_processes", str(processes * 2), [], f"{processes} processes observed"
            )
        )
    if defaults.cpu_seconds is not None and observation.cpu_seconds * 3 > defaults.cpu_seconds:
        cpu = math.ceil(observation.cpu_seconds * 3)
        resources["cpu_seconds"] = cpu
        reasons.append(
            Reason(
                "resources.cpu_seconds",
                str(cpu),
                [],
                f"{observation.cpu_seconds:.1f} s of CPU observed",
            )
        )
    rss_mb = observation.max_rss_kb / 1024
    if defaults.memory_mb is not None and rss_mb * 2 > defaults.memory_mb:
        memory = math.ceil(rss_mb * 2)
        resources["memory_mb"] = memory
        reasons.append(
            Reason("resources.memory_mb", str(memory), [], f"{rss_mb:.0f} MiB resident observed")
        )
    return resources


# --- YAML ---------------------------------------------------------------------------------


def _ids(events: list[str]) -> str:
    if not events:
        return ""
    shown = ", ".join(events[:5])
    more = f" +{len(events) - 5}" if len(events) > 5 else ""
    return f" [{shown}{more}]"


def render(generated: Generated) -> str:
    """The policy as YAML, with the rationale of each rule as a comment above it."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    reasons: dict[tuple[str, str], Reason] = {(r.rule, r.value): r for r in generated.reasons}
    lines = [
        f"# Generated by `convergence generate` on {stamp} from observation "
        f"{generated.observation_id}.",
        "# Review every rule before relying on it. Each one cites the observation events behind it",
        "# (`--rationale FILE` writes them all as JSON).",
    ]
    if not generated.complete:
        lines.append("# The observation was INCOMPLETE: expect denials on paths it did not see.")
    for warning in generated.warnings:
        lines.append(f"# warning: {warning}")
    policy = generated.policy
    lines += [
        "version: 1",
        f"name: {json.dumps(policy['name'])}",
        f"description: {json.dumps(policy['description'])}",
        "filesystem:",
    ]
    for bucket in BUCKETS:
        entries = policy["filesystem"][bucket]
        if not entries:
            lines.append(f"  {bucket}: []")
            continue
        lines.append(f"  {bucket}:")
        for entry in entries:
            value = entry if isinstance(entry, str) else entry["path"]
            reason = reasons.get((f"filesystem.{bucket}", value))
            if reason is not None:
                lines.append(f"    # {reason.why}{_ids(reason.events)}")
            if isinstance(entry, str):
                lines.append(f"    - {json.dumps(entry)}")
            else:
                lines.append(f"    - {{path: {json.dumps(value)}, optional: true}}")
    if policy["network"]:
        lines.append("network:")
        for key, ports in policy["network"].items():
            lines.append(f"  {key}:")
            for port in ports:
                reason = reasons.get((f"network.{key}", str(port)))
                comment = f"  # {reason.why}{_ids(reason.events)}" if reason else ""
                lines.append(f"    - {port}{comment}")
    else:
        lines.append("network: {}  # nothing to grant (see the warnings for refused attempts)")
    syscalls = policy["syscalls"]
    if syscalls["mode"] == "allow-list":
        lines += [
            "syscalls:",
            "  mode: allow-list",
            "  # every syscall seen while observed",
            "  allow:",
        ]
        lines += [f"    - {name}" for name in syscalls["allow"]]
    else:
        lines.append("syscalls: {mode: deny-list}  # Convergence's built-in deny list")
    lines.append("resources:")
    for key, value in policy["resources"].items():
        reason = reasons.get((f"resources.{key}", str(value)))
        comment = f"  # {reason.why}" if reason else ""
        lines.append(f"  {key}: {value}{comment}")
    lines.append("environment:")
    lines.append("  # environment reads cannot be observed; standard variables are passed")
    lines.append(f"  pass: {json.dumps(policy['environment']['pass'])}")
    values = policy["environment"].get("set", {})
    if values:
        for name in values:
            reason = reasons.get(("environment.set", name))
            if reason is not None:
                lines.append(f"  # {name}: {reason.why}")
        lines.append(f"  set: {json.dumps(values)}")
    text = "\n".join(lines) + "\n"
    parse_policy(text, source="generated policy")  # never emit an invalid policy
    return text
