"""SafetyMixer and ActionSelector (AI Spec 6.8/6.9; DPL mixing contract).

The SafetyMixer forms the realised policy as the safety mixture
``final = (1 - alpha) * base + alpha * exploit`` over the union of actions -- the
exact formula the frozen DPL validates (``dpl_schema._check_mixing_consistency``).
The default CLI run keeps ``alpha = 0`` for baseline compatibility, while Phase 2
fixtures may pass ``alpha > 0`` to exercise the rule-based exploit boundary.

The ActionSelector realises one concrete action by sampling the final policy with a
per-decision seed, so a run is reproducible: the same seed yields the same action.
"""

from __future__ import annotations

import math
import random

from poker_core.dpl_schema import MIXING_ABS_TOL, POLICY_SUM_TOL


def safety_mix(
    base_policy: dict[str, float],
    exploit_policy: dict[str, float],
    alpha: float,
) -> dict[str, float]:
    """Return ``(1 - alpha) * base + alpha * exploit`` over the action union.

    The result is a proper distribution (it sums to 1 when the inputs do) and
    matches the DPL mixing contract exactly, so a DPL built from these policies
    passes ``_check_mixing_consistency``. Actions absent from one policy are
    treated as probability 0.
    """
    if not 0.0 <= alpha <= 1.0:
        raise ValueError(f"alpha must be in [0, 1], got {alpha}")
    for name, policy in (("base_policy", base_policy), ("exploit_policy", exploit_policy)):
        total = math.fsum(policy.values())
        if abs(total - 1.0) > POLICY_SUM_TOL:
            raise ValueError(f"{name} must sum to 1.0, got {total}")

    actions = list(dict.fromkeys((*base_policy, *exploit_policy)))  # union, stable order
    final = {
        action: (1.0 - alpha) * base_policy.get(action, 0.0)
        + alpha * exploit_policy.get(action, 0.0)
        for action in actions
    }
    return final


class ActionSelector:
    """Deterministically sample one action from a final policy (AI Spec 6.9)."""

    def __init__(self, seed: int) -> None:
        self._rng = random.Random(seed)
        self.seed = seed

    def select(self, final_policy: dict[str, float]) -> str:
        """Sample an action from ``final_policy`` (only positive-mass actions).

        Reproducible for a given seed. Raises if the policy has no positive mass.
        """
        positive = [(action, prob) for action, prob in final_policy.items() if prob > 0.0]
        if not positive:
            raise ValueError("final_policy has no action with positive probability")
        total = math.fsum(prob for _action, prob in positive)
        threshold = self._rng.random() * total
        cumulative = 0.0
        for action, prob in positive:
            cumulative += prob
            if threshold < cumulative:
                return action
        # Floating-point guard: fall back to the last positive-mass action.
        return positive[-1][0]


def is_pure_base(base_policy: dict[str, float], final_policy: dict[str, float]) -> bool:
    """True if ``final_policy`` equals ``base_policy`` within the mixing tolerance.

    Used by task-3 tests to assert the ``alpha = 0`` boundary (final == base).
    """
    actions = set(base_policy) | set(final_policy)
    return all(
        abs(final_policy.get(a, 0.0) - base_policy.get(a, 0.0)) <= MIXING_ABS_TOL for a in actions
    )
