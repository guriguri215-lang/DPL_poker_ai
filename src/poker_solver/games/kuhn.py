r"""Kuhn poker: the canonical non-unique-equilibrium fixture (ADR-0017 sec.5).

Kuhn poker has a one-parameter *family* of equilibria (``alpha in [0, 1/3]``), so
per REV-20260705-phase2-gate2-fable5 sec.6 (layer L1) we do **not** assert strategy
equality here -- that is the trap this layer most easily falls into. We assert
only the game value (player 1's, ``-1/18`` bb) and that each member of the family
has exploitability ~ 0.

Rules
-----
Three-card deck ``{J, Q, K}`` (K high); each player is dealt one card, six
distinct orderings equally likely. Each antes 1, so ``ante = 1`` and the single
bet size is ``bet = 1``. Player 1 (= player 0 here) acts first:

* P1 ``CHECK`` -> P2 ``CHECK`` (showdown for the antes) or ``BET`` -> P1
  ``FOLD`` (P2 wins the antes) or ``CALL`` (showdown for antes + bets).
* P1 ``BET`` -> P2 ``FOLD`` (P1 wins the antes) or ``CALL`` (showdown).

Payoffs are net chips to P1 (player 0): a plain showdown is ``+/- ante``, a fold
costs the folder its ante (``+/- ante``), and a called-bet showdown is
``+/- (ante + bet)``. Every leaf is zero-sum.

Equilibrium family (Wikipedia "Kuhn poker"), parameter ``alpha in [0, 1/3]``::

    P1  J : bet with prob alpha (bluff), else check;  facing a bet -> fold
    P1  Q : check;                            facing a bet -> call w.p. alpha + 1/3
    P1  K : bet with prob 3*alpha, else check;        facing a bet -> call
    P2 facing a check : J bet w.p. 1/3, Q check, K bet
    P2 facing a bet   : J fold, Q call w.p. 1/3, K call

Every member has value ``-1/18`` bb to P1 and exploitability 0; the tests sweep
several ``alpha`` values to check this.
"""

from __future__ import annotations

from ..game import Chance, Decision, Game, Terminal
from ..strategy import StrategyProfile

#: Ranks low to high; index is strength (K strongest).
_KUHN_ORDER = ("J", "Q", "K")
_STRENGTH = {rank: i for i, rank in enumerate(_KUHN_ORDER)}

#: Standard Kuhn stakes (bb).
ANTE = 1.0
BET = 1.0

#: Exact game value to player 1 (player 0 here).
GAME_VALUE_P1 = -1.0 / 18.0


def _deals() -> list[tuple[str, str]]:
    return [(a, b) for a in _KUHN_ORDER for b in _KUHN_ORDER if a != b]


def _p1_wins(p1_card: str, p2_card: str) -> bool:
    return _STRENGTH[p1_card] > _STRENGTH[p2_card]


def build_kuhn_game(ante: float = ANTE, bet: float = BET) -> Game:
    """Build the Kuhn poker tree (player 0 = P1 / first to act, player 1 = P2)."""
    if ante <= 0 or bet <= 0:
        raise ValueError(f"ante and bet must be positive, got ante={ante}, bet={bet}")
    branches = []
    for p1_card, p2_card in _deals():
        p1_wins = _p1_wins(p1_card, p2_card)
        showdown_antes = Terminal(ante if p1_wins else -ante)
        showdown_called = Terminal((ante + bet) if p1_wins else -(ante + bet))

        # P1 checked, P2 bet, P1 faces the bet.
        p1_facing_bet = Decision(
            player=0,
            infoset=f"P1:{p1_card}:facing_bet",
            actions=("CALL", "FOLD"),
            children=(showdown_called, Terminal(-ante)),  # fold -> P1 loses its ante
        )
        # P1 checked, P2 to act.
        p2_after_check = Decision(
            player=1,
            infoset=f"P2:{p2_card}:after_check",
            actions=("CHECK", "BET"),
            children=(showdown_antes, p1_facing_bet),
        )
        # P1 bet, P2 faces the bet.
        p2_facing_bet = Decision(
            player=1,
            infoset=f"P2:{p2_card}:facing_bet",
            actions=("CALL", "FOLD"),
            children=(showdown_called, Terminal(ante)),  # fold -> P1 wins the antes
        )
        # P1 to act first.
        p1_start = Decision(
            player=0,
            infoset=f"P1:{p1_card}",
            actions=("CHECK", "BET"),
            children=(p2_after_check, p2_facing_bet),
        )
        branches.append((1.0 / 6.0, p1_start, f"{p1_card}{p2_card}"))
    return Game(Chance(tuple(branches)), name="kuhn")


def kuhn_equilibrium(alpha: float) -> StrategyProfile:
    """A member of the Kuhn equilibrium family for ``alpha in [0, 1/3]``.

    All infosets are specified (including ones off-path for a given ``alpha``) so
    the profile validates; off-path choices follow the same family formulas.
    """
    if not 0.0 <= alpha <= 1.0 / 3.0:
        raise ValueError(f"alpha must be in [0, 1/3], got {alpha}")
    third = 1.0 / 3.0
    profile: StrategyProfile = {
        # Player 1, first action.
        "P1:J": {"CHECK": 1.0 - alpha, "BET": alpha},
        "P1:Q": {"CHECK": 1.0, "BET": 0.0},
        "P1:K": {"CHECK": 1.0 - 3.0 * alpha, "BET": 3.0 * alpha},
        # Player 1, facing a bet after checking. Q calls with prob alpha + 1/3.
        "P1:J:facing_bet": {"CALL": 0.0, "FOLD": 1.0},
        "P1:Q:facing_bet": {"CALL": alpha + third, "FOLD": 1.0 - alpha - third},
        "P1:K:facing_bet": {"CALL": 1.0, "FOLD": 0.0},
        # Player 2, facing a check.
        "P2:J:after_check": {"CHECK": 1.0 - third, "BET": third},
        "P2:Q:after_check": {"CHECK": 1.0, "BET": 0.0},
        "P2:K:after_check": {"CHECK": 0.0, "BET": 1.0},
        # Player 2, facing a bet.
        "P2:J:facing_bet": {"CALL": 0.0, "FOLD": 1.0},
        "P2:Q:facing_bet": {"CALL": third, "FOLD": 1.0 - third},
        "P2:K:facing_bet": {"CALL": 1.0, "FOLD": 0.0},
    }
    return profile
