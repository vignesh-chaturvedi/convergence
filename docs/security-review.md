# Security review of Convergence 0.1.0

**Date:** 2026-11-12. **Reviewed:** tag `v0.1.0` (commit `5733ecb`), all of `src/convergence`.
**Fixed in:** 0.1.1.

**This is not an independent audit.** The review was done inside the project, by the same
hands that wrote the code. It found real weaknesses, which is a reason to expect that an
outside reviewer would find more. Treat it as evidence of what was checked, not as a
guarantee.

## Summary

The review found **seven weaknesses** in 0.1.0. Each was reproduced on a real kernel, fixed,
and given a regression test. Five more limits could not be fixed and are now documented.

| # | Weakness | Severity | State |
|---|---|---|---|
| 1 | TCP port grants bypassed with TCP fast open | High | fixed |
| 2 | A tool that keeps forking outlives the wall-clock limit and the clean-up | High | fixed |
| 3 | A grant inside a writable directory can be redirected for later runs | Medium | fixed |
| 4 | MCP clients choose where `${CWD}` points | Medium | fixed |
| 5 | `prlimit64` changes the limits of other processes, and can kill them | Medium | fixed |
| 6 | A socket can listen without a bind grant | Low | fixed in part |
| 7 | The `personality` rule can be bypassed | Low | fixed |

Severity is judged against the project's own claims in
[THREAT_MODEL.md](../THREAT_MODEL.md): High means a headline claim was false for a hostile
tool under an ordinary policy.

**The escape matrix did not catch any of these.** Its 47 development cases and 26 holdout
cases cover other techniques. The published escape rates therefore understate what 0.1.0
let through.

## Scope and method

- **Read in full:** the launch path (`runtime/child.py`, `plan.py`, `filters.py`,
  `supervisor.py`, `tracer.py`), the kernel bindings (`kernel/landlock.py`, `seccomp.py`),
  policy loading and assessment (`policy/`), and the MCP server and its helper (`mcp/`).
- **Read in part:** `observe`, `generate`, and the Divergence importer. They run without
  confinement by design, so only the rules that decide what is granted were read.
- **Method:** each claim in the threat model was compared with the code and with what the
  kernel does. Every suspected weakness was then tried as a real attack under
  `convergence run`. A weakness is only listed here if the attack worked.
- **Where:** stock Ubuntu 24.04, kernel 6.8.0-134, Landlock ABI 4, aarch64.

**Not covered:**
- kernels other than the one above. The regression tests run on the CI kernels (ABI 4 and
  ABI 8) once pushed; the attacks themselves were not replayed there;
- the holdout cases, which stay unread to keep the holdout independent;
- the dependencies: PyYAML, pydantic, the MCP SDK, libseccomp, and strace;
- fuzzing, side channels, and kernel bugs.

## Findings

### 1. TCP port grants bypassed with TCP fast open (High)

- **Claim:** a tool can connect only to the TCP ports in `network.tcp_connect`.
- **Attack:** `sendto(fd, data, MSG_FASTOPEN, address)` on an unconnected TCP socket. The
  kernel connects the socket itself, and on this kernel Landlock's connect check does not
  run. Under a policy granting only port 18001, a plain `connect` to port 18002 failed with
  `EACCES`. The fast-open send to port 18002 delivered its data and read the reply, over
  IPv4 and IPv6.
- **Impact:** any policy that grants at least one TCP port let the tool reach every TCP
  port on every host, including services on localhost. A policy with no TCP at all was not
  affected, because seccomp denies creating the socket.
- **Fix:** seccomp denies `sendto`, `sendmsg`, and `sendmmsg` with `MSG_FASTOPEN`, unless
  `tcp_connect` is `any`.
- **Tests:** `test_tcp_fast_open_cannot_reach_a_port_that_is_not_granted`,
  `test_the_baseline_syscall_filter`.
- **Open question:** whether newer kernels close this in Landlock itself was not checked.

### 2. A tool that keeps forking outlives the wall-clock limit (High)

- **Claim:** at the wall-clock limit the supervisor kills everything the tool started.
- **Attack:** every process forks in a loop, and each child calls `setsid`. The children
  leave the process group, so only a kill by pid reaches them. The supervisor killed and
  reaped its direct children, round after round, and each reap freed a process slot for
  the tool to fork again.
- **Measured:** with `wall_clock_seconds: 3` and `max_processes: 32`, the run ended after
  **269.7 seconds**. The supervisor stopped after 10,000 rounds without an error and left
  **41 processes running**.
- **Fix:** the supervisor now walks the whole process tree, signals parents before
  children, and reaps nothing until everything is dead. A dead process keeps its
  `RLIMIT_NPROC` slot until it is reaped, so the tool runs out of slots. Each process is
  signalled through its `/proc` directory, so a reused pid is never hit. The same attack
  now ends at 3.2 seconds with nothing left. Two harder variants (relay chains, and
  processes that reap each other) end the same way.
- **Limit:** this needs `resources.max_processes` (set by default). Without it the sweep
  gives up after 10 seconds, and the run record's new `outcome.left_running` says how many
  processes are left.
- **Tests:** `test_a_fork_storm_that_leaves_the_group_is_killed`,
  `test_the_sweep_says_what_it_could_not_kill`.

### 3. A grant inside a writable directory can be redirected (Medium)

- **Claim:** a tool gets the paths its policy lists.
- **Attack:** the policy grants `write` on a project directory and `execute` on
  `project/bin`. Run 1 could not read a secret outside the grants. It replaced
  `project/bin` with a symbolic link to the secret's directory. Landlock attaches a rule
  to whatever a path points at when the run starts, so run 2 was granted that directory
  and read the secret.
- **Impact:** any grant that lies inside a directory granted for writing could be pointed
  at any file the user can read, for every later run under that policy.
- **Fix:** `run` resolves such a path step by step. If the path passes through a directory
  granted for writing, it must end inside one, where the tool gains nothing. Otherwise the
  run is refused and the path is named. The final open cannot follow a link, so a change
  made at that moment is refused too.
- **Tests:** `test_a_grant_inside_a_writable_directory_cannot_be_redirected`,
  `test_a_grant_through_a_writable_directory_must_end_in_one`,
  `test_a_redirected_write_grant_is_not_trusted`.

### 4. MCP clients choose where `${CWD}` points (Medium)

- **Claim:** over MCP the operator chooses the policy, not the client (ADR 0010).
- **Problem:** `run_sandboxed` accepted any existing directory as `cwd`, and `${CWD}` in a
  policy follows it. A client could run under the operator's policy with `cwd` set to, for
  example, `~/.ssh`, and every `${CWD}` grant moved there.
- **Fix:** `cwd` must be the server's own directory or one beneath it, after resolving
  symbolic links. `--allow-any-cwd` restores the old behaviour.
- **Test:** `test_cwd_stays_under_the_servers_directory`.

### 5. `prlimit64` reaches other processes (Medium)

- **Claim:** a tool cannot tamper with processes outside the sandbox.
- **Attack:** the kernel lets a process change the resource limits of any process of the
  same user. The tool set `RLIMIT_CPU` of an outside process to 1 second, and the kernel
  killed that process. It could read the supervisor's limits too.
- **Impact:** a way to kill or cripple the user's other processes that does not use a
  signal. Landlock has no check for it, so signal scoping (ABI 6) is not expected to stop
  it. That was not tested on an ABI 6 kernel.
- **Fix:** seccomp denies `prlimit64` for every process but the caller (pid 0).
- **Tests:** `test_the_tool_cannot_change_another_processs_limits`,
  `test_the_baseline_syscall_filter`.

### 6. A socket can listen without a bind grant (Low)

- **Claim:** a tool can bind only the TCP ports in `network.tcp_bind`.
- **Attack:** a TCP socket that calls `listen` without `bind` gets a port from the kernel,
  and Landlock does not check it. With no `tcp_bind` at all, the tool accepted a connection
  from outside on such a port.
- **Fix, in part:** seccomp denies `listen` unless the policy grants a TCP port to bind or
  unix sockets can be created. seccomp cannot tell a TCP socket from a unix socket, so
  where `listen` stays allowed the gap remains. From Landlock ABI 9 unix sockets can be
  created by default, so there the gap is open again.
- **Test:** `test_the_baseline_syscall_filter`.

### 7. The `personality` rule can be bypassed (Low)

- **Claim:** `personality` cannot turn off address-space randomisation.
- **Attack:** the rule matched "flag set and bit 31 clear", to let the query value
  `0xffffffff` through. The kernel stores every other value as given, so
  `personality(0x80040000)` set `ADDR_NO_RANDOMIZE`.
- **Fix:** every value with bit 31 set is denied, except the query.
- **Test:** `test_the_baseline_syscall_filter`.

### Smaller fixes

- A stop signal arriving between `fork` and the line that stores the child's pid could
  leave the child untracked. Stop signals are now blocked across the forks.
- Removing the scratch directory could `chmod` through a symbolic link.
- The MCP server's patterns for policy names and run ids accepted a trailing newline.
- THREAT_MODEL.md still called itself a draft written before the runtime existed.

## Limits that remain

These were confirmed and cannot be fixed with the mechanisms Convergence uses. They are now
in [THREAT_MODEL.md](../THREAT_MODEL.md) and the README.

- **Below Landlock ABI 6, the tool can stop or kill its supervisor.** Measured on stock
  Ubuntu 24.04: a tool sent `SIGSTOP` to the supervisor and was still running after the
  wall-clock limit. The tool stays inside the sandbox, but the time limit and the clean-up
  are gone. The docs said that signals are not confined there; they did not say what that
  means for the supervisor.
- **Programs can be run from memory.** A copy of `/usr/bin/id` in a `memfd` ran under a
  policy that grants only the interpreter. This is the same class as the known loader
  limitation: execute grants do not limit what code runs.
- **The scheduling of other processes.** The tool changed the priority, CPU affinity, and
  scheduling class of an outside process.
- **Listening on a kernel-chosen port,** where `listen` must stay allowed (finding 6).
- **Clean-up without a process limit** (finding 2).

## Checked and found sound

- Inherited descriptors are closed, and the environment comes only from the policy.
- `no_new_privs`, Landlock, and seccomp are applied before `execve`, in that order, and a
  failure at any step stops the launch.
- Foreign-architecture system calls kill the process. On x86_64 this includes x32, checked
  in the generated BPF.
- 32-bit arguments are compared so that high bits cannot slip past a rule.
- `clone3` fails with `ENOSYS`, and namespace flags on `clone` are denied.
- The socket rules cover families, types, and protocols, including negative values.
- Landlock rules are attached to open descriptors, not to path strings.
- The policy loader rejects duplicate keys, anchors, and coerced values.
- Run records are private to the user.
- MCP policy names cannot contain a path, and the helper keeps the protocol pipes away
  from tools.
- The release workflow uses pinned actions and stores no token.

## Recommended next steps

1. **Use 0.1.1 or later.** 0.1.0 has all seven weaknesses.
2. **Add matrix cases** for each finding, then run and publish the matrix again. Use these
   techniques when the next holdout is written.
3. **Protect the supervisor below ABI 6.** seccomp could deny signals aimed at it, which
   needs a supervisor with a single thread. Where a cgroup is delegated, `cgroup.kill`
   would also make the clean-up exact.
4. **Make tracing opt-in on the MCP server.** Today the client decides, and the tracer runs
   outside the sandbox.
5. **Check finding 1 on current kernels,** and report it to the Landlock maintainers if it
   is still there.
6. **Get an independent review.**
