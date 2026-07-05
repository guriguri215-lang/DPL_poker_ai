"""River single-bet betting tree over combo-granular ranges (P3-1 item 2).

This builds a concrete :class:`~poker_solver.game.Game` for a river spot from a
declarative :class:`RiverBettingConfig` plus two ranges and a board. Card, combo,
range and hand-evaluation logic are **reused from ``poker_core``** (no
re-implementation): nature deals a specific (OOP combo, IP combo) pairing with
blocker/collision removal and range-product weights, and each showdown leaf
compares the two concrete hands with ``poker_core.hand_evaluator.evaluate_best``.

The betting structure is fixed data (no raises, single bet size), so it is
inspectable via the game's infoset/action index and via :data:`BETTING_ROUNDS`:

* OOP (player 0) to act: ``CHECK`` or ``BET``.
* facing ``BET``: the other player ``CALL`` or ``FOLD``.
* ``CHECK`` then IP (player 1): ``CHECK`` (-> showdown) or ``BET`` -> OOP
  ``CALL`` / ``FOLD``.
* ``CHECK, CHECK`` -> showdown.

Full combo-granular river *scenarios* and their performance targets are P3-3;
this module keeps the builder small and correct so P3-2/P3-3 can lean on it.
"""

from __future__ import annotations

from dataclasses import dataclass

from poker_core.card import Card, parse_cards
from poker_core.combo import Combo
from poker_core.hand_evaluator import evaluate_best
from poker_core.range_model import Range

from .game import Chance, Decision, Game, Node, Terminal

#: Human-readable description of the fixed betting structure (for inspection/tests).
BETTING_ROUNDS = (
    ("OOP", "start", ("CHECK", "BET")),
    ("IP", "vs_bet", ("CALL", "FOLD")),
    ("IP", "vs_check", ("CHECK", "BET")),
    ("OOP", "vs_bet", ("CALL", "FOLD")),
)


@dataclass(frozen=True, slots=True)
class RiverBettingConfig:
    """Declarative river betting parameters (all sizes in bb)."""

    pot: float
    bet_fraction: float  # bet size as a fraction of the pot

    def __post_init__(self) -> None:
        if self.pot <= 0:
            raise ValueError(f"pot must be positive, got {self.pot}")
        if self.bet_fraction <= 0:
            raise ValueError(f"bet_fraction must be positive, got {self.bet_fraction}")

    @property
    def bet(self) -> float:
        """Absolute bet size in bb."""
        return self.pot * self.bet_fraction


def _showdown_terminal(oop_strength: int, ip_strength: int, amount: float) -> Terminal:
    """Terminal for a showdown of ``amount`` bb staked by each side (OOP view)."""
    if oop_strength > ip_strength:
        return Terminal(amount)
    if oop_strength < ip_strength:
        return Terminal(-amount)
    return Terminal(0.0)  # exact tie: split, net zero


def _prepare(
    range_: Range, board: tuple[Card, ...], board_mask: int
) -> list[tuple[Combo, float, int]]:
    """Board-legal, positive-weight combos with their showdown strength."""
    prepared: list[tuple[Combo, float, int]] = []
    for combo, weight in range_:
        if weight <= 0 or (combo.mask & board_mask):
            continue
        strength = evaluate_best((*combo.cards, *board))
        prepared.append((combo, weight, strength))
    if not prepared:
        raise ValueError("range has no board-legal positive-weight combos")
    return prepared


def _betting_subtree(
    config: RiverBettingConfig, oop: Combo, ip: Combo, oop_strength: int, ip_strength: int
) -> Node:
    """The card-independent betting structure with this deal's infoset keys/leaves."""
    half = config.pot / 2.0
    bet = config.bet
    oop_key = oop.canonical()
    ip_key = ip.canonical()

    # OOP bets -> IP calls (showdown for pot+bets) or folds (OOP wins pot).
    ip_vs_bet = Decision(
        player=1,
        infoset=f"IP:{ip_key}:vs_bet",
        actions=("CALL", "FOLD"),
        children=(_showdown_terminal(oop_strength, ip_strength, half + bet), Terminal(half)),
    )
    # OOP checks, IP bets -> OOP calls or folds (IP wins pot).
    oop_vs_bet = Decision(
        player=0,
        infoset=f"OOP:{oop_key}:vs_bet",
        actions=("CALL", "FOLD"),
        children=(_showdown_terminal(oop_strength, ip_strength, half + bet), Terminal(-half)),
    )
    # OOP checks, IP to act: check (showdown for pot) or bet.
    ip_vs_check = Decision(
        player=1,
        infoset=f"IP:{ip_key}:vs_check",
        actions=("CHECK", "BET"),
        children=(_showdown_terminal(oop_strength, ip_strength, half), oop_vs_bet),
    )
    return Decision(
        player=0,
        infoset=f"OOP:{oop_key}:start",
        actions=("CHECK", "BET"),
        children=(ip_vs_check, ip_vs_bet),
    )


def build_river_game(
    config: RiverBettingConfig,
    oop_range: Range,
    ip_range: Range,
    board: tuple[Card, ...] | list[Card] | str,
) -> Game:
    """Build the river betting game (player 0 = OOP, player 1 = IP).

    Nature deals every non-colliding, board-legal (OOP combo, IP combo) pairing
    weighted by the range-weight product, normalised to a probability 1 chance
    node.
    """
    if isinstance(board, str):
        board = parse_cards(board)
    board = tuple(board)
    if len(board) != 5:
        raise ValueError(f"river board must have 5 cards, got {len(board)}")
    board_mask = 0
    for card in board:
        board_mask |= card.mask

    oop_prepared = _prepare(oop_range, board, board_mask)
    ip_prepared = _prepare(ip_range, board, board_mask)

    deals: list[tuple[float, Node, str]] = []
    total_weight = 0.0
    for oop, oop_w, oop_s in oop_prepared:
        for ip, ip_w, ip_s in ip_prepared:
            if oop.mask & ip.mask:  # share a card: impossible pairing
                continue
            weight = oop_w * ip_w
            total_weight += weight
            subtree = _betting_subtree(config, oop, ip, oop_s, ip_s)
            deals.append((weight, subtree, f"{oop.canonical()}|{ip.canonical()}"))
    if total_weight <= 0:
        raise ValueError("no valid (OOP, IP) matchups after blocker removal")

    branches = tuple((weight / total_weight, subtree, label) for weight, subtree, label in deals)
    return Game(Chance(branches), name="river")
