"""Range-vs-range exact showdown EV (Solver spec Phase S0, 8.2/8.3, tests 19.3).

At a river showdown the two players' hole combos are compared and the pot is
awarded to the better hand (split on a tie). This module enumerates every valid
hero/opponent combo pairing -- excluding pairings that share a card with each
other or with the board (blocker removal) -- weights each pairing by the two
combos' range weights, and returns Hero's win/tie/lose equity and EV.

EV convention (``ev_definition = "showdown_net_stake"``): both players are
treated as having contributed ``pot / 2`` to the pot at the showdown node, so
Hero's EV is the net stake exchanged from Hero's perspective::

    hero_ev = (P(win) - P(lose)) * (pot / 2)

This is antisymmetric (``opponent_ev == -hero_ev``), a complete tie yields 0,
and an always-winning range yields ``+pot / 2``. It is *not* the betting-tree
``incremental_ev_from_current_node`` definition (Solver spec 8.3), which the CFR
solver introduces in a later phase; this is the standalone showdown evaluator.
The evaluation is exact (full enumeration), hence deterministic and seedless.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from .card import Card, cards_mask
from .range_model import Range

#: Number of board cards on the river.
RIVER_BOARD_SIZE = 5

#: Label recorded with a showdown EV so downstream logs know its meaning.
EV_DEFINITION = "showdown_net_stake"
#: Default unit for the pot / EV (big blinds); callers may override.
DEFAULT_EV_UNIT = "bb"

# A prepared combo is (card_mask, hand_strength, weight).
_PreparedCombo = tuple[int, int, float]


def _validate_river_board(board: tuple[Card, ...]) -> None:
    """Reject boards that are not exactly five distinct cards (river only).

    The showdown EV is meant to be an exact ``solver_exact`` value (ADR-0008), so
    a flop/turn board or a duplicated card must fail fast rather than silently
    yield a number that could later reach an explanation.
    """
    if len(board) != RIVER_BOARD_SIZE:
        raise ValueError(
            f"river board must have exactly {RIVER_BOARD_SIZE} cards, got {len(board)}"
        )
    if len({card.index for card in board}) != len(board):
        raise ValueError("river board contains duplicate cards")


@dataclass(frozen=True, slots=True)
class ShowdownEquity:
    """Hero-perspective win/tie/lose probabilities over valid matchups."""

    win: float
    tie: float
    lose: float
    #: Total combo-pair weight actually considered (after blocker removal).
    considered_weight: float

    @property
    def equity(self) -> float:
        """Pot share Hero expects at showdown (ties split): ``win + tie / 2``."""
        return self.win + self.tie / 2.0


@dataclass(frozen=True, slots=True)
class ShowdownEV:
    """Hero-perspective showdown EV with its equity and provenance labels."""

    hero_ev: float
    equity: ShowdownEquity
    pot: float
    ev_unit: str
    ev_definition: str

    @property
    def opponent_ev(self) -> float:
        return -self.hero_ev


def _prepare(range_: Range, board: tuple[Card, ...], board_mask: int) -> list[_PreparedCombo]:
    """Precompute (mask, strength, weight) for board-legal, positive-weight combos."""
    from .hand_evaluator import evaluate_best  # local import avoids a cycle at import time

    prepared: list[_PreparedCombo] = []
    for combo, weight in range_:
        if weight <= 0:
            continue
        if combo.mask & board_mask:
            continue
        strength = evaluate_best((*combo.cards, *board))
        prepared.append((combo.mask, strength, weight))
    return prepared


def showdown_equity(
    hero: Range,
    opponent: Range,
    board: tuple[Card, ...] | list[Card],
) -> ShowdownEquity:
    """Exact Hero win/tie/lose equity vs an opponent range on a river board."""
    board = tuple(board)
    _validate_river_board(board)
    board_mask = cards_mask(board)
    hero_prepared = _prepare(hero, board, board_mask)
    opponent_prepared = _prepare(opponent, board, board_mask)
    if not hero_prepared or not opponent_prepared:
        raise ValueError("no board-legal combos in hero or opponent range")

    win = tie = lose = total = 0.0
    for hero_mask, hero_strength, hero_weight in hero_prepared:
        for opp_mask, opp_strength, opp_weight in opponent_prepared:
            if hero_mask & opp_mask:  # combos share a card: impossible pairing
                continue
            weight = hero_weight * opp_weight
            total += weight
            if hero_strength > opp_strength:
                win += weight
            elif hero_strength < opp_strength:
                lose += weight
            else:
                tie += weight
    if total <= 0:
        raise ValueError("no valid hero/opponent matchups after blocker removal")
    return ShowdownEquity(win / total, tie / total, lose / total, total)


def showdown_ev(
    hero: Range,
    opponent: Range,
    board: tuple[Card, ...] | list[Card],
    pot: float,
    ev_unit: str = DEFAULT_EV_UNIT,
) -> ShowdownEV:
    """Exact Hero showdown EV: ``(win - lose) * pot / 2`` (see module docstring)."""
    _validate_river_board(tuple(board))
    if not math.isfinite(pot):
        raise ValueError(f"pot must be a finite number, got {pot}")
    if pot < 0:
        raise ValueError(f"pot must be non-negative, got {pot}")
    equity = showdown_equity(hero, opponent, board)
    hero_ev = (equity.win - equity.lose) * (pot / 2.0)
    return ShowdownEV(hero_ev, equity, pot, ev_unit, EV_DEFINITION)


def estimate_showdown_equity(
    hero: Range,
    opponent: Range,
    board: tuple[Card, ...] | list[Card],
    samples: int = 10_000,
    seed: int = 0,
) -> ShowdownEquity:
    """Monte Carlo estimate of :func:`showdown_equity`, reproducible per ``seed``.

    Useful as a scalable cross-check of the exact evaluator and for future
    larger games. Given the same inputs and ``seed`` the result is identical.
    """
    if samples <= 0:
        raise ValueError(f"samples must be positive, got {samples}")
    board = tuple(board)
    _validate_river_board(board)
    board_mask = cards_mask(board)
    hero_prepared = _prepare(hero, board, board_mask)
    opponent_prepared = _prepare(opponent, board, board_mask)
    if not hero_prepared or not opponent_prepared:
        raise ValueError("no board-legal combos in hero or opponent range")

    rng = random.Random(seed)
    hero_weights = [combo[2] for combo in hero_prepared]
    opp_weights = [combo[2] for combo in opponent_prepared]

    win = tie = lose = drawn = 0
    attempts = 0
    # Bounded rejection sampling budget; if collisions keep us from reaching
    # `samples` valid draws we raise rather than silently returning a short
    # sample the caller cannot notice.
    max_attempts = samples * 1000
    while drawn < samples:
        if attempts >= max_attempts:
            raise ValueError(
                f"could not draw {samples} non-colliding matchups within "
                f"{max_attempts} attempts; hero and opponent ranges overlap too much"
            )
        attempts += 1
        hero_combo = rng.choices(hero_prepared, weights=hero_weights, k=1)[0]
        opp_combo = rng.choices(opponent_prepared, weights=opp_weights, k=1)[0]
        if hero_combo[0] & opp_combo[0]:  # collision: resample
            continue
        drawn += 1
        if hero_combo[1] > opp_combo[1]:
            win += 1
        elif hero_combo[1] < opp_combo[1]:
            lose += 1
        else:
            tie += 1
    return ShowdownEquity(win / drawn, tie / drawn, lose / drawn, float(drawn))
