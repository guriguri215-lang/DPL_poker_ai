"""SafetyMixer, ActionSelector and ExecutionSampler.

The SafetyMixer forms the realised policy as the safety mixture
``final = (1 - alpha) * base + alpha * exploit`` over the union of actions -- the
exact formula the frozen DPL validates (``dpl_schema._check_mixing_consistency``).
The default CLI run keeps ``alpha = 0`` for baseline compatibility, while Phase 2
fixtures may pass ``alpha > 0`` to exercise the rule-based exploit boundary.

The ActionSelector realises one concrete action by sampling the final policy with a
per-decision seed, so a run is reproducible: the same seed yields the same action.
ADR-0018 adds an independent post-SafetyMixer ExecutionSampler for epsilon
exploration. It leaves ``final_policy`` unchanged and records the explicit
execution distribution only when the epsilon branch fires.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from poker_core.dpl_schema import MIXING_ABS_TOL, POLICY_SUM_TOL

EPSILON_SAMPLER_VERSION = "epsilon-uniform-v1"


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


@dataclass(frozen=True)
class ExecutionSample:
    """Concrete action plus optional ADR-0018 epsilon sampling metadata."""

    selected_action: str
    exploration_fired: bool
    sampler_version: str
    epsilon: float
    epsilon_distribution: dict[str, float] | None
    execution_policy: dict[str, float] | None


class ExecutionSampler:
    """Sample after SafetyMixer, optionally firing epsilon exploration (ADR-0018)."""

    def __init__(self, *, epsilon: float = 0.0, sampler_version: str = EPSILON_SAMPLER_VERSION):
        if not math.isfinite(epsilon) or not 0.0 <= epsilon <= 1.0:
            raise ValueError(f"epsilon must be finite and in [0, 1], got {epsilon}")
        if not sampler_version:
            raise ValueError("sampler_version must not be empty")
        self.epsilon = epsilon
        self.sampler_version = sampler_version

    def sample(
        self,
        *,
        final_policy: dict[str, float],
        legal_actions: tuple[str, ...],
        seed: int,
    ) -> ExecutionSample:
        """Return an executed action without mutating ``final_policy``.

        The epsilon distribution is uniform over the provided legal action list.
        At ``epsilon = 0`` this delegates to :class:`ActionSelector` exactly, so
        the legacy seeded action sequence is preserved.
        """
        q_epsilon = uniform_legal_distribution(legal_actions)
        execution_policy = epsilon_execution_policy(final_policy, q_epsilon, self.epsilon)

        if self.epsilon <= 0.0:
            return ExecutionSample(
                selected_action=ActionSelector(seed).select(final_policy),
                exploration_fired=False,
                sampler_version=self.sampler_version,
                epsilon=self.epsilon,
                epsilon_distribution=None,
                execution_policy=None,
            )

        if self.epsilon >= 1.0:
            return ExecutionSample(
                selected_action=ActionSelector(seed).select(q_epsilon),
                exploration_fired=True,
                sampler_version=self.sampler_version,
                epsilon=self.epsilon,
                epsilon_distribution=q_epsilon,
                execution_policy=execution_policy,
            )

        rng = random.Random(seed)
        if rng.random() < self.epsilon:
            selected_action = _sample_with_rng(q_epsilon, rng)
            return ExecutionSample(
                selected_action=selected_action,
                exploration_fired=True,
                sampler_version=self.sampler_version,
                epsilon=self.epsilon,
                epsilon_distribution=q_epsilon,
                execution_policy=execution_policy,
            )
        return ExecutionSample(
            selected_action=_sample_with_rng(final_policy, rng),
            exploration_fired=False,
            sampler_version=self.sampler_version,
            epsilon=self.epsilon,
            epsilon_distribution=None,
            execution_policy=None,
        )


def uniform_legal_distribution(legal_actions: tuple[str, ...]) -> dict[str, float]:
    """Uniform distribution over a stable, non-empty legal action tuple."""
    if not legal_actions:
        raise ValueError("legal_actions must not be empty")
    if any(not action for action in legal_actions):
        raise ValueError("legal_actions must not contain an empty action")
    if len(set(legal_actions)) != len(legal_actions):
        raise ValueError("legal_actions must not contain duplicates")
    probability = 1.0 / len(legal_actions)
    return {action: probability for action in legal_actions}


def epsilon_execution_policy(
    final_policy: dict[str, float],
    epsilon_distribution: dict[str, float],
    epsilon: float,
) -> dict[str, float]:
    """Audit distribution ``(1-epsilon) * final_policy + epsilon * q_epsilon``."""
    if not math.isfinite(epsilon) or not 0.0 <= epsilon <= 1.0:
        raise ValueError(f"epsilon must be finite and in [0, 1], got {epsilon}")
    for name, policy in (
        ("final_policy", final_policy),
        ("epsilon_distribution", epsilon_distribution),
    ):
        total = math.fsum(policy.values())
        if abs(total - 1.0) > POLICY_SUM_TOL:
            raise ValueError(f"{name} must sum to 1.0, got {total}")
    actions = list(dict.fromkeys((*final_policy, *epsilon_distribution)))
    return {
        action: (1.0 - epsilon) * final_policy.get(action, 0.0)
        + epsilon * epsilon_distribution.get(action, 0.0)
        for action in actions
    }


def is_pure_base(base_policy: dict[str, float], final_policy: dict[str, float]) -> bool:
    """True if ``final_policy`` equals ``base_policy`` within the mixing tolerance.

    Used by task-3 tests to assert the ``alpha = 0`` boundary (final == base).
    """
    actions = set(base_policy) | set(final_policy)
    return all(
        abs(final_policy.get(a, 0.0) - base_policy.get(a, 0.0)) <= MIXING_ABS_TOL for a in actions
    )


def _sample_with_rng(policy: dict[str, float], rng: random.Random) -> str:
    positive = [(action, prob) for action, prob in policy.items() if prob > 0.0]
    if not positive:
        raise ValueError("policy has no action with positive probability")
    total = math.fsum(prob for _action, prob in positive)
    threshold = rng.random() * total
    cumulative = 0.0
    for action, prob in positive:
        cumulative += prob
        if threshold < cumulative:
            return action
    return positive[-1][0]
