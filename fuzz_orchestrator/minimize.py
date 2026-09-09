"""Replay and delta-debugging helpers for saved findings."""

from __future__ import annotations

from dataclasses import dataclass

from .engine import FuzzEngine
from .models import ExecutionResult


@dataclass
class MinimizeResult:
    original: ExecutionResult
    minimized: ExecutionResult
    payload: bytes
    attempts: int


def replay_payload(engine: FuzzEngine, payload: bytes, case_id: str = "replay") -> ExecutionResult:
    """Execute a payload once with the already validated target configuration."""

    return engine.target.execute(payload, case_id)


def minimize_payload(
    engine: FuzzEngine,
    payload: bytes,
    *,
    max_attempts: int = 500,
) -> MinimizeResult:
    """Minimize a payload while preserving its observable finding status.

    This is a conservative ddmin-style reducer.  It preserves the target's
    status (for example ``crash`` or ``server_error``), not a particular
    stack-trace string.  Transport failures are rejected because reducing an
    offline target to an empty payload would create a misleading artifact.
    """

    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    original = replay_payload(engine, payload, "minimize-original")
    if original.status == "ok":
        raise ValueError("the input does not reproduce a finding (status is ok)")
    if original.status in {"connection_error", "error"}:
        raise ValueError(
            f"refusing to minimize transport/setup status {original.status}; verify the target first"
        )

    best = bytes(payload)
    best_result = original
    attempts = 1
    granularity = 2

    while best and granularity <= len(best) and attempts < max_attempts:
        chunk_size = (len(best) + granularity - 1) // granularity
        reduced = False
        start = 0
        while start < len(best) and attempts < max_attempts:
            end = min(len(best), start + chunk_size)
            candidate = best[:start] + best[end:]
            result = replay_payload(engine, candidate, f"minimize-{attempts:05d}")
            attempts += 1
            if result.status == original.status:
                best = candidate
                best_result = result
                granularity = max(2, granularity - 1)
                reduced = True
                break
            start = end
        if not reduced:
            if granularity >= len(best):
                break
            granularity = min(len(best), granularity * 2)

    return MinimizeResult(
        original=original,
        minimized=best_result,
        payload=best,
        attempts=attempts,
    )
