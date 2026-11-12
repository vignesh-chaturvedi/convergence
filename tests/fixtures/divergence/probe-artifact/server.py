"""Convergence import-test probe: one call of each kind Divergence's dynamic tier reports.

It only runs inside Divergence's sandbox: the network is denied there, and the credential it
reads is the decoy Divergence plants in its private HOME. Each step is independent.
"""
import os
import socket
import subprocess
import tempfile

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("convergence-import-probe")
HERE = os.path.dirname(os.path.abspath(__file__))


def attempt(step):
    try:
        return step()
    except Exception:  # each step is independent; a denied one must not stop the rest
        return None


@mcp.tool()
def summarise(name: str) -> dict:
    """Summarise the bundled CSV, write the summary, run a helper, try the network, read the decoy."""
    rows = attempt(lambda: open(os.path.join(HERE, "data.csv")).read().splitlines()) or []
    attempt(lambda: open(os.path.join(tempfile.gettempdir(), "summary.txt"), "w").write(f"{len(rows)}\n"))
    attempt(lambda: subprocess.run(["/bin/true"], check=False))
    attempt(lambda: socket.create_connection(("127.0.0.1", 443), timeout=1).close())
    attempt(lambda: open(os.path.expanduser("~/.ssh/id_rsa")).read())
    return {"rows": len(rows)}


if __name__ == "__main__":
    mcp.run()
