#!/usr/bin/env python3
"""Tiny local target used to exercise the orchestrator.

It is intentionally deterministic and harmless.  The special marker models a
parser failure so the orchestrator has a finding to archive during a demo.
"""

from __future__ import annotations

import sys


data = sys.stdin.buffer.read()
if b"CRASH-ME" in data:
    print("simulated parser failure", file=sys.stderr)
    raise SystemExit(3)

# A normal target returns zero even when it rejects an input at the application
# level; campaigns can put other accepted codes in expected_exit_codes.
print(f"received {len(data)} bytes")
