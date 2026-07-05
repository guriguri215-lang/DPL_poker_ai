"""Strategy profiles over an extensive-form :class:`~poker_solver.game.Game`.

A *strategy profile* maps every information-set key to a probability
distribution over that infoset's actions::

    {infoset_key: {action: probability, ...}, ...}

Both players' strategies live in one profile; the owning player of each infoset
is recorded by the game. Helpers here build a uniform profile, validate a
profile against a game (all infosets present, distributions normalised and
non-negative, action sets matching), and normalise a raw action distribution
with the ADR-0017 sec.7 rule: an all-zero distribution falls back to uniform rather
than dividing by zero.
"""

from __future__ import annotations

import math

from .game import Game

#: A distribution over actions and a full profile keyed by infoset.
ActionDist = dict[str, float]
StrategyProfile = dict[str, ActionDist]

#: Absolute tolerance when checking a distribution sums to 1.
DIST_SUM_TOLERANCE = 1e-9


def uniform_profile(game: Game) -> StrategyProfile:
    """A profile that plays every action of every infoset with equal probability."""
    profile: StrategyProfile = {}
    for infoset in game.infosets:
        actions = game.actions_of(infoset)
        weight = 1.0 / len(actions)
        profile[infoset] = dict.fromkeys(actions, weight)
    return profile


def normalized_action_dist(dist: ActionDist, actions: tuple[str, ...]) -> ActionDist:
    """Normalise ``dist`` over ``actions``; all-zero mass falls back to uniform.

    This is the ADR-0017 sec.7 convention for an unreached information set's average
    strategy: with no accumulated mass the normalising denominator is 0, so we
    return the uniform distribution rather than dividing by zero.
    """
    total = math.fsum(dist.get(action, 0.0) for action in actions)
    if total <= 0.0:
        weight = 1.0 / len(actions)
        return dict.fromkeys(actions, weight)
    return {action: dist.get(action, 0.0) / total for action in actions}


def validate_profile(
    game: Game, profile: StrategyProfile, tolerance: float = DIST_SUM_TOLERANCE
) -> None:
    """Raise ``ValueError`` unless ``profile`` is a valid strategy for ``game``.

    Checks that the profile's infoset keys match the game's exactly (no missing
    and no extra keys), that every distribution uses the game's action set, that
    all probabilities are finite and non-negative, and that each distribution
    sums to 1 within ``tolerance``. Rejecting extra keys keeps a downstream
    generator (e.g. CFR average-strategy extraction in P3-2) from smuggling
    stale or unknown infosets past the verifier unnoticed.
    """
    extra = set(profile) - set(game.infosets)
    if extra:
        raise ValueError(f"profile has unknown infosets {sorted(extra)}")
    for infoset in game.infosets:
        if infoset not in profile:
            raise ValueError(f"profile missing infoset {infoset!r}")
        actions = game.actions_of(infoset)
        dist = profile[infoset]
        if set(dist) != set(actions):
            raise ValueError(
                f"infoset {infoset!r} profile keys {sorted(dist)} != actions {sorted(actions)}"
            )
        total = 0.0
        for action in actions:
            prob = dist[action]
            if not math.isfinite(prob):
                raise ValueError(f"infoset {infoset!r} action {action!r} prob not finite: {prob}")
            if prob < 0:
                raise ValueError(f"infoset {infoset!r} action {action!r} prob < 0: {prob}")
            total += prob
        if abs(total - 1.0) > tolerance:
            raise ValueError(f"infoset {infoset!r} probabilities sum to {total}, not 1")
