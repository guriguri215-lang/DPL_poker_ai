"""River scenario schema and deterministic generator -- Q3 frozen 0.1.0 (REV M-5).

A :class:`Scenario` is the fully specified pre-action river spot the vertical slice
runs a single decision on (ADR-0007): the board, Hero's position, the dead-money pot,
the effective stack, the concrete combo Hero was dealt, Hero's assumed range (used
for the ``hand_bucket`` percentile, ADR-0005) and the opponent's assumed range
(public information Hero may use for showdown EV -- distinct from the opponent's
*hidden* action strategy, AI Spec 6.3). Opponent action is **not** part of the
scenario: the environment produces the public action at the session mode's
causal point, so Hero never receives the hidden policy.

This schema is **frozen at ``0.1.0``** (Q3, ADR-0014, human-approved 2026-07-04) and
is versioned so it can be pinned in a RunManifest. It is not one of the Phase-0
frozen contracts (ADR-0006); changing its fields or invariants now requires a new
ADR and a version bump. :func:`generate_scenarios` builds a session's scenarios
deterministically from a seed, so a run is reproducible.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterator
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from poker_core.card import RANKS, SUITS, Card, parse_cards
from poker_core.combo import Combo
from poker_core.range_model import Range

#: Version of the frozen scenario schema (Q3, ADR-0014). Bump on any field/invariant
#: change; a new version needs its own ADR.
SCENARIO_SCHEMA_VERSION = "0.1.0"

#: Number of river board cards.
RIVER_BOARD_SIZE = 5

Position = Literal["IP", "OOP"]


class Scenario(BaseModel):
    """One fully specified river spot for a single Hero decision (Q3, ADR-0014)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(min_length=1)
    board: tuple[str, ...]
    position: Position
    pot: float = Field(ge=0.0)
    effective_stack: float = Field(gt=0.0)
    hero_combo: str = Field(min_length=4, max_length=4)
    hero_range: dict[str, float]
    opponent_range: dict[str, float]

    @model_validator(mode="after")
    def _validate(self) -> Scenario:
        if not math.isfinite(self.pot) or not math.isfinite(self.effective_stack):
            raise ValueError("pot and effective_stack must be finite")
        board = self.board_cards()  # validates count + uniqueness
        board_mask = 0
        for card in board:
            board_mask |= card.mask

        hero_range = self.hero_range_obj()  # Range() validates weights + combos
        opponent_range = self.opponent_range_obj()
        hero_combo = Combo.from_str(self.hero_combo)
        if hero_combo.mask & board_mask:
            raise ValueError(f"hero_combo {self.hero_combo} is blocked by the board")
        if hero_combo.canonical() not in hero_range.weights:
            raise ValueError(f"hero_combo {self.hero_combo} must be a member of hero_range")

        for name, rng in (("hero_range", hero_range), ("opponent_range", opponent_range)):
            legal = rng.drop_zero_weight().without_blockers(board)
            if len(legal) == 0:
                raise ValueError(f"{name} has no board-legal, positive-weight combo")

        # Every showdown pits Hero's *exact* combo against the opponent range, so the
        # opponent range must keep a combo once both the board and Hero's cards are
        # removed as blockers. Otherwise the scenario passes schema validation but
        # DPL generation fails later when showdown_equity() finds no legal matchup.
        opponent_playable = (
            opponent_range.drop_zero_weight()
            .without_blockers(board)
            .without_conflicts(hero_combo.cards)
        )
        if len(opponent_playable) == 0:
            raise ValueError(
                f"opponent_range has no combo compatible with hero_combo "
                f"{self.hero_combo} and the board (every showdown matchup is blocked)"
            )
        return self

    def board_cards(self) -> tuple[Card, ...]:
        """Parse and validate the board (exactly five distinct river cards)."""
        cards = parse_cards(list(self.board))  # rejects duplicates
        if len(cards) != RIVER_BOARD_SIZE:
            raise ValueError(f"board must have exactly {RIVER_BOARD_SIZE} cards, got {len(cards)}")
        return cards

    def hero_combo_obj(self) -> Combo:
        return Combo.from_str(self.hero_combo)

    def hero_range_obj(self) -> Range:
        return Range(self.hero_range)

    def opponent_range_obj(self) -> Range:
        return Range(self.opponent_range)


# --- deterministic generation ------------------------------------------------

#: Discrete choices the generator samples spot parameters from (bb units).
_POT_OPTIONS: tuple[float, ...] = (4.0, 6.0, 8.0, 10.0)
_STACK_OPTIONS: tuple[float, ...] = (6.0, 10.0, 15.0, 20.0)
_POSITION_OPTIONS: tuple[Position, ...] = ("IP", "OOP")


def _full_deck() -> list[Card]:
    return [Card(rank, suit) for rank in RANKS for suit in SUITS]


def _sample_combos(
    rng: random.Random,
    cards: list[Card],
    count: int,
    *,
    include: Combo | None = None,
) -> dict[str, float]:
    """Sample ``count`` distinct 2-card combos (uniform weight 1.0) from ``cards``.

    If ``include`` is given it is always present. Sampling is driven by ``rng`` so
    it is deterministic for a fixed seed.
    """
    max_combos = len(cards) * (len(cards) - 1) // 2
    if count > max_combos:
        raise ValueError(f"cannot sample {count} distinct combos from {len(cards)} cards")
    combos: dict[str, float] = {}
    if include is not None:
        combos[include.canonical()] = 1.0
    while len(combos) < count:
        first, second = rng.sample(cards, 2)
        combos[Combo.from_cards(first, second).canonical()] = 1.0
    return combos


def generate_scenario(
    rng: random.Random,
    scenario_id: str,
    *,
    hero_range_size: int = 40,
    opponent_range_size: int = 40,
) -> Scenario:
    """Generate one valid river scenario from ``rng`` (deterministic for a seed)."""
    deck = _full_deck()
    rng.shuffle(deck)
    board = deck[:RIVER_BOARD_SIZE]
    hero_cards = deck[RIVER_BOARD_SIZE : RIVER_BOARD_SIZE + 2]
    hero_combo = Combo.from_cards(*hero_cards)

    # Hero range: drawn from every non-board card (may share cards with the
    # opponent's range; that is resolved by blocker removal at EV time). Always
    # contains the dealt combo so its percentile is well defined.
    hero_pool = deck[RIVER_BOARD_SIZE:]
    hero_range = _sample_combos(rng, hero_pool, hero_range_size, include=hero_combo)

    # Opponent range: drawn from cards outside the board and Hero's exact combo, so
    # every hero/opponent pairing is a legal, non-colliding matchup.
    opponent_pool = deck[RIVER_BOARD_SIZE + 2 :]
    opponent_range = _sample_combos(rng, opponent_pool, opponent_range_size)

    return Scenario(
        scenario_id=scenario_id,
        board=tuple(str(card) for card in board),
        position=rng.choice(_POSITION_OPTIONS),
        pot=rng.choice(_POT_OPTIONS),
        effective_stack=rng.choice(_STACK_OPTIONS),
        hero_combo=hero_combo.canonical(),
        hero_range=hero_range,
        opponent_range=opponent_range,
    )


def generate_scenarios(
    seed: int,
    num_hands: int,
    *,
    hero_range_size: int = 40,
    opponent_range_size: int = 40,
) -> Iterator[Scenario]:
    """Yield ``num_hands`` scenarios deterministically from ``seed`` (M-5, Q3).

    The same ``(seed, num_hands)`` always yields the same scenarios, in order.
    """
    if num_hands <= 0:
        raise ValueError(f"num_hands must be positive, got {num_hands}")
    rng = random.Random(seed)
    for index in range(num_hands):
        yield generate_scenario(
            rng,
            scenario_id=f"SC{index:05d}",
            hero_range_size=hero_range_size,
            opponent_range_size=opponent_range_size,
        )
