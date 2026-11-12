# ADR 0010 — MCP server: operator-chosen policies, a single-threaded spawn helper

**Status:** accepted · **Phase:** 6 · **Date:** 2026-11-12

## Context

`convergence mcp` exposes Convergence to an agent over the Model Context Protocol, so the
agent can run a tool sandboxed, generate a policy, explain denials, and check a policy.

Checked in the development VM:
- The SDK resolves to `mcp` 2.3.0, the newest release outside the 14-day cooldown.
- In 2.x, `FastMCP` is renamed `MCPServer` (`mcp.server.mcpserver`) and is served with
  `run_stdio_async()`.
- The `mcp.client.client.Client` connects to an in-memory server or launches one over stdio
  (`StdioServerParameters`).
- The server runs an event loop and worker threads. The runtime needs a single-threaded
  process to fork the sandboxed tool (ADR 0006).
- On stdio, the server's stdin and stdout *are* the protocol. Anything a tool inherited or
  printed there would corrupt it.

## Decision

**Who chooses the policy: the operator, not the agent.** A client that could send any policy
could also send `write: [$HOME]`, so the server takes its policies from the person starting
it:
- `--policies DIR`: the client names a policy in that directory (`[A-Za-z0-9_.-]+`, no
  paths).
- `--allow-inline-policy`: the client may also send policy text. This is meant for trusted
  clients and tests, and the server warns about it.

The server refuses to start with neither. No call runs without a policy, and there is no
default allow.

**Tools:**

| Tool | Returns |
|---|---|
| `run_sandboxed(command, policy, timeout_s?, cwd?, trace?)` | exit status, captured output (64 KiB per stream, truncation marked), denials when traced, `run_id` |
| `generate_policy(observation)` | the policy YAML, the rationale per rule, warnings |
| `explain_denials(run_id)` | each denial's cause, rule, smallest change (YAML diff), and risk |
| `check_policy(policy)` | how this kernel enforces each rule, and whether `run_sandboxed` would refuse it |
| `observe(command, cwd?, timeout_s?)` | only with `--allow-observe`: it runs the command **unconfined** |

How the arguments are treated:
- `command` is an argv list and never goes through a shell.
- `cwd` must be an existing absolute directory. `${CWD}` in a policy follows it, so it must
  also be the server's own directory or one beneath it, after resolving symbolic links.
  `--allow-any-cwd` lifts that. (Until the security review of 0.1.0 any directory was
  accepted, which let a client move the operator's `${CWD}` grants anywhere.)
- `observation` is JSON text or the id of a saved observation, never a path. So is
  `run_id`. This keeps the server from reading arbitrary files for a client.
- `run_sandboxed` refuses a policy this kernel cannot fully enforce. There is no
  `--allow-degraded` over MCP.

**The spawn helper:**
- `convergence mcp` starts one helper process, a fresh single-threaded interpreter, before
  the server's event loop. It speaks JSON lines over pipes.
- For each request it forks a worker. The worker points its stdin at `/dev/null` and its
  stdout at stderr, applies the policy, and supervises the tool with output captured
  (ADR 0006). Then it writes the run record back and exits.
- Each call therefore costs a fork and the sandbox setup, not an interpreter startup.
- Runs are serialised by a lock in the server. One run at a time is enough for an agent's
  tool calls.

Inline policies are saved under the state directory by their SHA-256, so `explain_denials`
can find the policy a run used.

## Consequences

- The tool never sees the protocol's descriptors, and nothing it prints can reach the
  client except through the captured output.
- Concurrent calls queue. A long run delays the next.
- The server, helper, and worker run unconfined, like the CLI's supervisor. Their attack
  surface is the JSON they parse and the policy they load.
- Per-call latency is measured in Phase 6, and against other sandboxes in Phase 7.
