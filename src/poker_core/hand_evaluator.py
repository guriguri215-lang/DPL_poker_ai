"""Poker hand evaluation for the River MVP (Solver spec 6.x, tests 19.1).

The evaluator maps any 5-, 6- or 7-card hand to a single comparable integer
*strength* so that a larger integer always beats a smaller one and equal
integers tie (a split pot). Strength packs the hand category and up to five
ordered tie-break ranks into one int, which keeps the range-vs-range showdown
loop cheap (Solver spec Phase S0 performance target).

Ace plays high everywhere except the 5-high "wheel" straight (A-2-3-4-5).
"""

from __future__ import annotations

from collections import Counter
from enum import IntEnum
from itertools import combinations

from .card import Card
from .combo import Combo

#: Number of tie-break slots packed after the category nibble.
_TIEBREAK_SLOTS = 5


class HandCategory(IntEnum):
    """Poker hand categories, ordered weakest to strongest."""

    HIGH_CARD = 0
    PAIR = 1
    TWO_PAIR = 2
    THREE_OF_A_KIND = 3
    STRAIGHT = 4
    FLUSH = 5
    FULL_HOUSE = 6
    FOUR_OF_A_KIND = 7
    STRAIGHT_FLUSH = 8


def _straight_high(rank_values: set[int]) -> int | None:
    """Return the high card of a 5-card straight, or ``None`` if not a straight."""
    if len(rank_values) < 5:
        return None
    for high in range(14, 4, -1):
        if all((high - offset) in rank_values for offset in range(5)):
            return high
    if {14, 2, 3, 4, 5} <= rank_values:  # wheel: ace plays low
        return 5
    return None


def _pack(category: HandCategory, tiebreaks: tuple[int, ...]) -> int:
    """Pack a category and its ordered tie-breaks into one comparable int."""
    key = int(category)
    for slot in range(_TIEBREAK_SLOTS):
        value = tiebreaks[slot] if slot < len(tiebreaks) else 0
        key = (key << 4) | value
    return key


def _require_unique(cards: tuple[Card, ...] | list[Card]) -> None:
    """Reject a hand that repeats a card; a duplicate would be an impossible hand."""
    if len({card.index for card in cards}) != len(cards):
        raise ValueError("hand contains duplicate cards")


def _evaluate_five(cards: tuple[Card, ...] | list[Card]) -> int:
    """Strength of five valid, distinct cards (no input validation)."""
    values = sorted((card.value for card in cards), reverse=True)
    counts = Counter(values)
    # Groups ordered by count desc, then rank desc: this ordering is exactly the
    # tie-break priority for every count-based category.
    groups = sorted(counts.items(), key=lambda item: (item[1], item[0]), reverse=True)
    ordered_ranks = tuple(rank for rank, _count in groups)
    count_pattern = tuple(count for _rank, count in groups)

    is_flush = len({card.suit for card in cards}) == 1
    straight_high = _straight_high(set(values))

    if is_flush and straight_high is not None:
        return _pack(HandCategory.STRAIGHT_FLUSH, (straight_high,))
    if count_pattern == (4, 1):
        return _pack(HandCategory.FOUR_OF_A_KIND, ordered_ranks)
    if count_pattern == (3, 2):
        return _pack(HandCategory.FULL_HOUSE, ordered_ranks)
    if is_flush:
        return _pack(HandCategory.FLUSH, tuple(values))
    if straight_high is not None:
        return _pack(HandCategory.STRAIGHT, (straight_high,))
    if count_pattern == (3, 1, 1):
        return _pack(HandCategory.THREE_OF_A_KIND, ordered_ranks)
    if count_pattern == (2, 2, 1):
        return _pack(HandCategory.TWO_PAIR, ordered_ranks)
    if count_pattern == (2, 1, 1, 1):
        return _pack(HandCategory.PAIR, ordered_ranks)
    return _pack(HandCategory.HIGH_CARD, tuple(values))


def evaluate_five(cards: tuple[Card, ...] | list[Card]) -> int:
    """Strength of exactly five distinct cards as a comparable integer."""
    if len(cards) != 5:
        raise ValueError(f"evaluate_five needs exactly 5 cards, got {len(cards)}")
    _require_unique(cards)
    return _evaluate_five(cards)


def evaluate_best(cards: tuple[Card, ...] | list[Card]) -> int:
    """Strength of the best five-card hand out of five to seven distinct cards."""
    cards = tuple(cards)
    if not (5 <= len(cards) <= 7):
        raise ValueError(f"evaluate_best needs 5 to 7 cards, got {len(cards)}")
    _require_unique(cards)
    if len(cards) == 5:
        return _evaluate_five(cards)
    return max(_evaluate_five(five) for five in combinations(cards, 5))


def hand_strength(hole: Combo, board: tuple[Card, ...] | list[Card]) -> int:
    """Best-hand strength for a hole combo on a board (7 cards on the river)."""
    return evaluate_best((*hole.cards, *board))


def category_of(strength: int) -> HandCategory:
    """Recover the :class:`HandCategory` from a packed strength value."""
    return HandCategory(strength >> (4 * _TIEBREAK_SLOTS))
