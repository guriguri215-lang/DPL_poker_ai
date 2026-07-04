"""River action abstraction for the single-decision MVP (ADR-0007; AI Spec 6.x).

A decision at the river node is over a small, fixed vocabulary of abstract
actions. Two disjoint branches exist, selected by whether Hero is *facing* a bet:

* **no-facing** -- Hero acts first: ``CHECK`` / ``BET_33`` / ``BET_75``.
* **facing** -- Hero faces a bet: ``FOLD`` / ``CALL`` / ``RAISE_ALL_IN``.

The whole vocabulary is declared here so downstream phases share one definition,
but task 3 only *scores* the actions whose terminal is a showdown or a fold, so
that every EV is an exact ``solver_exact`` value (ADR-0008). Concretely, task 3
generates spots where Hero faces an **all-in** bet: the legal set collapses to
``FOLD`` / ``CALL`` (there is nothing left to raise, so ``RAISE_ALL_IN`` is not
legal), ``FOLD`` is a deterministic terminal and ``CALL`` is an exact river
showdown. Bet/raise actions open a betting subtree whose EV needs the opponent's
response model and belongs to the CFR phase (Phase 3); they are intentionally not
realised here. See :mod:`poker_ai.decision` for the EV convention.
"""

from __future__ import annotations

#: Actions available when Hero acts first (no bet to face). Phase 3 scores these.
NO_FACING_ACTIONS: tuple[str, ...] = ("CHECK", "BET_33", "BET_75")

#: Actions available when Hero faces a (non all-in) bet. Phase 3 scores RAISE.
FACING_ACTIONS: tuple[str, ...] = ("FOLD", "CALL", "RAISE_ALL_IN")

#: The complete action vocabulary (both branches), for shared downstream use.
ALL_ACTIONS: tuple[str, ...] = NO_FACING_ACTIONS + FACING_ACTIONS

#: The two actions task 3 realises: both have an exact, showdown/fold terminal.
FACING_ALL_IN_ACTIONS: tuple[str, ...] = ("FOLD", "CALL")


def legal_actions(*, facing_bet: bool, bet_is_all_in: bool) -> tuple[str, ...]:
    """Return the legal action set for a river node.

    Task 3 only supports the facing-an-all-in case, whose legal set is
    ``("FOLD", "CALL")`` -- both actions have an exact terminal EV. The other
    branches (Hero-first bets, raising a non all-in bet) are part of the shared
    vocabulary but are scored only once the CFR betting-tree EV exists (Phase 3);
    requesting them here raises ``NotImplementedError`` so no un-scored action can
    silently enter a decision.
    """
    if not facing_bet:
        raise NotImplementedError(
            "no-facing (Hero-first) decisions are not scored until the CFR phase; "
            "task 3 only supports facing an all-in bet"
        )
    if not bet_is_all_in:
        raise NotImplementedError(
            "facing a non all-in bet (which allows RAISE_ALL_IN) is not scored "
            "until the CFR phase; task 3 only supports facing an all-in bet"
        )
    return FACING_ALL_IN_ACTIONS
