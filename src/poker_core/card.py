"""Card primitives for the River MVP (Solver spec 6.1).

A :class:`Card` is an immutable rank+suit. Ranks are ``2``-``9``, ``T``, ``J``,
``Q``, ``K``, ``A`` (values 2..14, ace high); suits are ``s`` ``h`` ``d`` ``c``.
The two-character string form (``"As"``, ``"Td"``) is the canonical
serialisation used across the project's contracts and logs.

This is the single shared card model imported by both ``poker_ai`` and
``poker_solver`` (REV-20260702 H-2), so the two projects cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Rank characters in ascending value order; index + 2 is the rank value.
RANKS = "23456789TJQKA"
#: Suit characters. The order defines a stable tie-break for canonical sorting.
SUITS = "shdc"

_RANK_VALUE = {rank: value + 2 for value, rank in enumerate(RANKS)}
_SUIT_INDEX = {suit: index for index, suit in enumerate(SUITS)}

#: Number of distinct cards in a standard deck.
DECK_SIZE = 52


@dataclass(frozen=True, slots=True)
class Card:
    """A single playing card, e.g. ``Card("A", "s")`` for the ace of spades."""

    rank: str
    suit: str

    def __post_init__(self) -> None:
        if self.rank not in _RANK_VALUE:
            raise ValueError(f"invalid rank {self.rank!r}; expected one of {RANKS!r}")
        if self.suit not in _SUIT_INDEX:
            raise ValueError(f"invalid suit {self.suit!r}; expected one of {SUITS!r}")

    @property
    def value(self) -> int:
        """Rank value, 2..14 with the ace high."""
        return _RANK_VALUE[self.rank]

    @property
    def index(self) -> int:
        """Stable deck index in ``0..51`` (rank-major), usable as a bit position."""
        return (self.value - 2) * 4 + _SUIT_INDEX[self.suit]

    @property
    def mask(self) -> int:
        """Single-bit mask ``1 << index`` for fast set/collision arithmetic."""
        return 1 << self.index

    @property
    def sort_key(self) -> tuple[int, int]:
        """Descending-by-value, then suit-order key for canonical ordering."""
        return (-self.value, _SUIT_INDEX[self.suit])

    @classmethod
    def from_str(cls, text: str) -> Card:
        """Parse a two-character card string such as ``"As"`` or ``"Td"``."""
        if len(text) != 2:
            raise ValueError(f"card string must be 2 characters, got {text!r}")
        return cls(text[0], text[1])

    def __str__(self) -> str:
        return f"{self.rank}{self.suit}"


def parse_cards(cards: str | list[str] | tuple[str, ...]) -> tuple[Card, ...]:
    """Parse cards from a whitespace-separated string or a sequence of strings.

    Raises ``ValueError`` if any card repeats.
    """
    tokens = cards.split() if isinstance(cards, str) else list(cards)
    parsed = tuple(Card.from_str(token) for token in tokens)
    if len({card.index for card in parsed}) != len(parsed):
        raise ValueError(f"duplicate card in {cards!r}")
    return parsed


def cards_mask(cards: tuple[Card, ...] | list[Card]) -> int:
    """Bitmask of a set of cards (bitwise OR of each card's mask)."""
    mask = 0
    for card in cards:
        mask |= card.mask
    return mask
