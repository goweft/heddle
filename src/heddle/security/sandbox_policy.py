"""Trust-tier policy matrix for the sandbox.

Single source of truth for resource caps and the hardening profile per
trust tier. Replaces the inline dict literal previously at sandbox.py:97.

ADR-004 §3.
"""
from __future__ import annotations

from dataclasses import dataclass

_NOBODY = "65534:65534"
DEFAULT_IMAGE = "python-3.12-slim"


@dataclass(frozen=True)
class TierPolicy:
    memory: str
    cpu: float
    pids: int
    image: str
    seccomp: str  # "default" or "strict"
    user: str
    writable_volume: bool


# T1-T3 run as nobody:nogroup. T4 may opt into a different uid via
# runtime.user (e.g. an agent that needs to write to a host-uid-owned
# volume). Seccomp:strict ships a custom profile dropping ptrace,
# keyctl, and clone3 flags we don't need.
TIER_MATRIX: dict[int, TierPolicy] = {
    1: TierPolicy(
        memory="256m", cpu=0.5, pids=64,
        image=DEFAULT_IMAGE, seccomp="default", user=_NOBODY,
        writable_volume=False,
    ),
    2: TierPolicy(
        memory="512m", cpu=0.5, pids=128,
        image=DEFAULT_IMAGE, seccomp="default", user=_NOBODY,
        writable_volume=True,
    ),
    3: TierPolicy(
        memory="1g", cpu=1.0, pids=256,
        image=DEFAULT_IMAGE, seccomp="strict", user=_NOBODY,
        writable_volume=True,
    ),
    4: TierPolicy(
        memory="2g", cpu=1.0, pids=512,
        image=DEFAULT_IMAGE, seccomp="strict", user=_NOBODY,
        writable_volume=True,
    ),
}


def policy_for(trust_tier: int) -> TierPolicy:
    return TIER_MATRIX.get(trust_tier, TIER_MATRIX[1])
