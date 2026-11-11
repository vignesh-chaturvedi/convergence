"""Convergence: least-privilege sandboxing for AI agent tools on Linux.

Nothing is enforced yet. See PLAN.md for the phase plan and README.md for the current status.
"""

from importlib.metadata import PackageNotFoundError, version

DISTRIBUTION = "convergence-sandbox"

try:
    __version__ = version(DISTRIBUTION)
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"

__all__ = ["DISTRIBUTION", "__version__"]
