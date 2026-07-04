"""Two-card combo primitives (Solver spec 6.2).

A :class:`Combo` is an unordered pair of distinct cards with a canonical string
form. Canonicalisation sorts the two cards by descending value then suit order,
so ``"AsKh"`` and ``"KhAs"`` describe the same combo and share one key.
"""

from __future__ import annotations

from dataclasses import dataclass

from .card import Card


@dataclass(frozen=True, slots=True)
class Combo:
    """An unordered pair of distinct cards, stored in canonical order."""

    cards: tuple[Card, Card]

    def __post_init__(self) -> None:
        first, second = self.cards
        if first.index == second.index:
            raise ValueError(f"combo needs two distinct cards, got {first} twice")
        # Store in canonical (descending) order regardless of input order.
        ordered = tuple(sorted(self.cards, key=lambda card: card.sort_key))
        object.__setattr__(self, "cards", ordered)

    @classmethod
    def from_str(cls, text: str) -> Combo:
        """Parse a four-character combo string such as ``"AsKh"``."""
        if len(text) != 4:
            raise ValueError(f"combo string must be 4 characters, got {text!r}")
        return cls((Card.from_str(text[:2]), Card.from_str(text[2:])))

    @classmethod
    def from_cards(cls, first: Card, second: Card) -> Combo:
        return cls((first, second))

    @property
    def mask(self) -> int:
        """Two-bit mask of the combo's cards for fast collision checks."""
        return self.cards[0].mask | self.cards[1].mask

    def canonical(self) -> str:
        """Canonical string key, e.g. ``"AsKh"``."""
        return f"{self.cards[0]}{self.cards[1]}"

    def collides_with(self, other: Combo) -> bool:
        """True if this combo shares a card with ``other``."""
        return bool(self.mask & other.mask)

    def blocked_by(self, dead_mask: int) -> bool:
        """True if this combo shares a card with the given ``dead_mask``."""
        return bool(self.mask & dead_mask)

    def __str__(self) -> str:
        return self.canonical()
