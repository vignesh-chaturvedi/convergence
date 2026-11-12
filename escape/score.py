"""Turning an oracle's observation into a case result, and results into the two rates."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum


class Result(StrEnum):
    # Attack contained, or control succeeded, under Convergence.
    PASS = "pass"  # noqa: S105 - a result name, not a password
    ESCAPE = "escape"  # attack observed under Convergence: the policy was too loose
    DOCUMENTED_LIMITATION = "documented-limitation"  # escape on a kernel below the case's ABI
    FALSE_DENIAL = "false-denial"  # control failed under Convergence: the policy was too tight
    VALID = "valid"  # unconfined: the attack escaped / the control succeeded, as required
    INVALID = "invalid"  # unconfined: the case did not do what it claims, so it proves nothing
    SKIPPED_UNENFORCEABLE = "skipped-unenforceable"  # the policy cannot be enforced here
    SKIPPED_PLATFORM = "skipped-platform"  # the case does not apply to this architecture
    LAUNCHER_UNAVAILABLE = "launcher-unavailable"  # nothing ran; never counted as a pass
    ERROR = "error"  # the harness could not run the case


FAILING = frozenset(
    {Result.ESCAPE, Result.FALSE_DENIAL, Result.INVALID, Result.LAUNCHER_UNAVAILABLE, Result.ERROR}
)


def score(
    *,
    is_control: bool,
    launcher: str,
    observed: bool,
    min_abi: int,
    kernel_abi: int | None,
) -> Result:
    """Map "did the effect happen?" to a result, as specified in escape/README.md."""
    if launcher == "unconfined":
        # Attacks must escape and controls must succeed: in both cases the effect happens.
        return Result.VALID if observed else Result.INVALID
    if is_control:
        return Result.PASS if observed else Result.FALSE_DENIAL
    if not observed:
        return Result.PASS
    below_floor = min_abi > 0 and (kernel_abi or 0) < min_abi
    return Result.DOCUMENTED_LIMITATION if below_floor else Result.ESCAPE


def wilson(successes: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score 95% interval for a proportion. (0, 0) for n == 0."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    # The bounds are exactly 0 and 1 at the extremes; pin them against rounding error.
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == n else min(1.0, centre + half)
    return (low, high)


@dataclass(frozen=True, slots=True)
class Rate:
    numerator: int
    denominator: int

    @property
    def value(self) -> float | None:
        return self.numerator / self.denominator if self.denominator else None

    @property
    def interval(self) -> tuple[float, float] | None:
        return wilson(self.numerator, self.denominator) if self.denominator else None

    def describe(self) -> str:
        if not self.denominator:
            return "n/a (nothing counted)"
        low, high = wilson(self.numerator, self.denominator)
        return (
            f"{self.numerator}/{self.denominator} ({100 * self.numerator / self.denominator:.1f}%; "
            f"Wilson 95% CI {100 * low:.1f}-{100 * high:.1f}%)"
        )


def escape_rate(attack_results: list[Result]) -> Rate:
    """Escapes over attacks that were actually judged (pass or escape)."""
    counted = [r for r in attack_results if r in (Result.PASS, Result.ESCAPE)]
    return Rate(sum(r is Result.ESCAPE for r in counted), len(counted))


def false_denial_rate(control_results: list[Result]) -> Rate:
    counted = [r for r in control_results if r in (Result.PASS, Result.FALSE_DENIAL)]
    return Rate(sum(r is Result.FALSE_DENIAL for r in counted), len(counted))
