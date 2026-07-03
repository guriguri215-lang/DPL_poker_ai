"""Weighted combo ranges (Solver spec 6.3).

A :class:`Range` maps canonical combo strings to non-negative weights. It can
drop zero-weight combos, exclude combos blocked by the board, exclude combos
that conflict with specific dead cards (e.g. the opponent's hand), and
normalise its weights to sum to 1. These operations are the card-exclusion
machinery the showdown EV evaluator relies on (Solver spec Phase S0).
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping

from .card import Card, cards_mask
from .combo import Combo


class Range:
    """An immutable weighted set of combos keyed by canonical combo string."""

    __slots__ = ("_weights",)

    def __init__(self, weights: Mapping[str, float]) -> None:
        canonical: dict[str, float] = {}
        for key, weight in weights.items():
            if weight < 0:
                raise ValueError(f"combo weight must be >= 0, got {weight} for {key!r}")
            combo = Combo.from_str(key)
            canonical_key = combo.canonical()
            if canonical_key in canonical:
                raise ValueError(f"duplicate combo {canonical_key!r} in range")
            canonical[canonical_key] = float(weight)
        self._weights = canonical

    # -- construction helpers ------------------------------------------------

    @classmethod
    def from_combos(cls, combos: Mapping[Combo, float]) -> Range:
        return cls({combo.canonical(): weight for combo, weight in combos.items()})

    @classmethod
    def uniform(cls, combos: list[str]) -> Range:
        return cls(dict.fromkeys(combos, 1.0))

    # -- basic access --------------------------------------------------------

    @property
    def weights(self) -> dict[str, float]:
        """A copy of the ``{canonical_combo: weight}`` mapping."""
        return dict(self._weights)

    def __len__(self) -> int:
        return len(self._weights)

    def __iter__(self) -> Iterator[tuple[Combo, float]]:
        for key, weight in self._weights.items():
            yield Combo.from_str(key), weight

    def total_weight(self) -> float:
        return math.fsum(self._weights.values())

    # -- transformations (all return new Range instances) --------------------

    def drop_zero_weight(self) -> Range:
        """Remove combos whose weight is zero."""
        return Range({key: weight for key, weight in self._weights.items() if weight > 0})

    def without_blockers(self, board: tuple[Card, ...] | list[Card]) -> Range:
        """Remove combos that share a card with the board."""
        return self._without_dead_mask(cards_mask(board))

    def without_conflicts(self, dead_cards: tuple[Card, ...] | list[Card]) -> Range:
        """Remove combos that share a card with the given dead cards."""
        return self._without_dead_mask(cards_mask(dead_cards))

    def _without_dead_mask(self, dead_mask: int) -> Range:
        return Range(
            {
                key: weight
                for key, weight in self._weights.items()
                if not (Combo.from_str(key).mask & dead_mask)
            }
        )

    def normalized(self) -> Range:
        """Scale weights so they sum to 1 (over positive-weight combos)."""
        positive = self.drop_zero_weight()
        total = positive.total_weight()
        if total <= 0:
            raise ValueError("cannot normalize an empty or zero-weight range")
        return Range({key: weight / total for key, weight in positive._weights.items()})
