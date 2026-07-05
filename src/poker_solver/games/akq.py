r"""The AKQ half-street game: a von Neumann-style toy with a closed-form solution.

This is the primary analytic fixture for the verifier (ADR-0017 sec.5, layer L1).
Its equilibrium is **unique**, so unlike Kuhn we may assert the exact strategy
frequencies as well as the game value.

Rules
-----
Two players, out of position (OOP = player 0) and in position (IP = player 1),
each ante so a dead pot of ``pot`` bb sits in the middle. Each is dealt one card
from the three-card deck ``{A, K, Q}`` (A high); the six distinct orderings are
equally likely (probability 1/6 each). It is a *half street*: OOP has no bet, so
play starts with IP.

* IP may ``CHECK`` or ``BET`` (size ``bet`` bb, single size, no raises).
* If IP checks, there is an immediate showdown for the pot (high card wins).
* If IP bets, OOP may ``CALL`` or ``FOLD``.
  * OOP folds -> IP takes the pot.
  * OOP calls -> showdown for the pot plus the bets.

Payoffs are net chips to OOP (player 0); the pot is dead money each contributed
``pot / 2`` to, so a showdown win/loss is ``+/- pot/2`` and a called showdown is
``+/- (pot/2 + bet)``. Every leaf is zero-sum.

Closed-form equilibrium (derivation)
------------------------------------
Let ``P = pot`` and ``b = bet``. Dominance pins three of IP's/OOP's cards:

* IP with **A** (nuts) always bets: betting can only gain (OOP may call and pay
  ``b``) and never loses versus checking, so ``bet A`` strictly dominates when
  OOP ever calls K.
* IP with **K** always checks: a bet only gets called by A (K loses an extra
  ``b``) and only folds out Q (which K already beats at showdown), so checking
  dominates.
* IP with **Q** (air) is the bluff candidate: checking loses ``P/2`` for sure;
  betting can win the pot when OOP folds.
* OOP with **A** always calls (it beats IP's only bet-with-worse hand, Q).
* OOP with **Q** always folds (it beats nothing IP bets).
* OOP with **K** is the bluff-catcher and mixes.

Two indifferences fix the mixing frequencies. Write ``f`` = IP's Q-bluff
frequency and ``c`` = OOP's K-call frequency.

*OOP's K is indifferent between calling and folding.* Given OOP holds K, IP holds
A or Q with equal prior; IP bets A always and Q with frequency ``f``, so
conditional on a bet ``P(A|bet) = 1/(1+f)`` and ``P(Q|bet) = f/(1+f)``::

    EV_call = [f/(1+f)] (P/2 + b) + [1/(1+f)] (-P/2 - b) = (P/2 + b)(f - 1)/(1 + f)
    EV_fold = -P/2
    set equal  ->  (P/2 + b)(f - 1) = -(P/2)(1 + f)  ->  f (P + b) = b
    =>  f = b / (P + b)

*IP's Q is indifferent between betting and checking* (so it is willing to mix).
Given IP holds Q, OOP holds A or K equally; OOP-A always calls, OOP-K calls with
frequency ``c``. Checking Q is worth ``-P/2``::

    EV_bet(Q) = 1/2 (-P/2 - b) + 1/2 [ c(-P/2 - b) + (1 - c)(P/2) ]
    set EV_bet(Q) = -P/2  ->  b + c(P + b) = P  ->  c = (P - b) / (P + b)

(``c >= 0`` requires ``bet <= pot``; the fixture uses ``pot > bet``.)

*Game value.* Summing OOP's net over the six equally likely deals with these
frequencies, the ``c`` terms cancel (because ``f(P + b) = b``) and the total is
``S = f(b - P)``, so::

    value_to_OOP = S / 6 = -b (P - b) / (6 (P + b))            (player-0 utility)

For the fixture defaults ``pot = 3``, ``bet = 1`` this gives ``f = 1/4``,
``c = 1/2`` and ``value = -1/12`` bb.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from ..game import Chance, Decision, Game, Terminal
from ..strategy import StrategyProfile

#: The three ranks, high to low; the index is the strength (A strongest).
_AKQ_ORDER = ("A", "K", "Q")
_STRENGTH = {rank: len(_AKQ_ORDER) - i for i, rank in enumerate(_AKQ_ORDER)}

#: Fixture defaults (bb). ``pot > bet`` keeps OOP's call frequency non-negative.
DEFAULT_POT = 3.0
DEFAULT_BET = 1.0


def _deals() -> list[tuple[str, str]]:
    """The six equally likely (OOP card, IP card) orderings of distinct cards."""
    return [(oop, ip) for oop in _AKQ_ORDER for ip in _AKQ_ORDER if oop != ip]


def _oop_wins(oop_card: str, ip_card: str) -> bool:
    return _STRENGTH[oop_card] > _STRENGTH[ip_card]


def build_akq_game(pot: float = DEFAULT_POT, bet: float = DEFAULT_BET) -> Game:
    """Build the AKQ half-street game tree (player 0 = OOP, player 1 = IP)."""
    if pot <= 0 or bet <= 0:
        raise ValueError(f"pot and bet must be positive, got pot={pot}, bet={bet}")
    half = pot / 2.0
    branches = []
    for oop_card, ip_card in _deals():
        oop_wins = _oop_wins(oop_card, ip_card)
        check_showdown = Terminal(half if oop_wins else -half)
        called_showdown = Terminal((half + bet) if oop_wins else -(half + bet))
        oop_facing_bet = Decision(
            player=0,
            infoset=f"OOP:{oop_card}:facing_bet",
            actions=("CALL", "FOLD"),
            children=(called_showdown, Terminal(-half)),  # fold -> OOP loses the pot
        )
        ip_decision = Decision(
            player=1,
            infoset=f"IP:{ip_card}",
            actions=("BET", "CHECK"),
            children=(oop_facing_bet, check_showdown),
        )
        branches.append((1.0 / 6.0, ip_decision, f"{oop_card}{ip_card}"))
    return Game(Chance(tuple(branches)), name="akq")


@dataclass(frozen=True, slots=True)
class AKQSolution:
    """The closed-form equilibrium of the AKQ game (see module derivation)."""

    pot: float
    bet: float
    bluff_freq: float  # IP bets Q with this probability
    call_freq: float  # OOP calls with K with this probability
    game_value: float  # player-0 (OOP) expected utility, bb


def akq_solution(pot: float = DEFAULT_POT, bet: float = DEFAULT_BET) -> AKQSolution:
    """The unique-equilibrium frequencies and game value (exact rationals)."""
    if pot <= bet:
        raise ValueError(f"closed form requires pot > bet, got pot={pot}, bet={bet}")
    p = Fraction(pot).limit_denominator()
    b = Fraction(bet).limit_denominator()
    f = b / (p + b)
    c = (p - b) / (p + b)
    value = -b * (p - b) / (6 * (p + b))
    return AKQSolution(pot, bet, float(f), float(c), float(value))


def akq_equilibrium(pot: float = DEFAULT_POT, bet: float = DEFAULT_BET) -> StrategyProfile:
    """The equilibrium strategy profile for :func:`build_akq_game`."""
    solution = akq_solution(pot, bet)
    f = solution.bluff_freq
    c = solution.call_freq
    profile: StrategyProfile = {
        # IP value-bets A, checks K, bluffs Q with frequency f.
        "IP:A": {"BET": 1.0, "CHECK": 0.0},
        "IP:K": {"BET": 0.0, "CHECK": 1.0},
        "IP:Q": {"BET": f, "CHECK": 1.0 - f},
        # OOP calls A, folds Q, calls K (bluff-catch) with frequency c.
        "OOP:A:facing_bet": {"CALL": 1.0, "FOLD": 0.0},
        "OOP:K:facing_bet": {"CALL": c, "FOLD": 1.0 - c},
        "OOP:Q:facing_bet": {"CALL": 0.0, "FOLD": 1.0},
    }
    return profile
