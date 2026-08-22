"""River action abstraction for the single-decision MVP (ADR-0007; AI Spec 6.x).

A decision at the river node is over a small, fixed vocabulary of abstract
actions. Two disjoint branches exist, selected by whether Hero is *facing* a bet:

* **no-facing** -- Hero acts first: ``CHECK`` / ``BET_33`` / ``BET_75``.
* **facing** -- Hero faces a bet: ``FOLD`` / ``CALL`` / ``RAISE_ALL_IN``.

The whole vocabulary is declared here so downstream phases share one definition.
The historical path generates a facing-all-in spot whose legal set collapses to
``FOLD`` / ``CALL``. The opt-in R007 fixture also realizes ``CHECK`` and the
existing fixed tree's 0.33-pot ``BET`` branch as public ``BET_33``. Its downstream
responses are evaluated through the fixed CFR+/HARD-node-lock tree, so the action
EV remains exact ``solver_exact`` under ADR-0008. ``BET_75``, non-all-in facing
bets, and raises remain unrealized. See :mod:`poker_ai.decision` for the EV
convention.
"""

from __future__ import annotations

#: Actions available when Hero acts first (no bet to face). Phase 3 scores these.
NO_FACING_ACTIONS: tuple[str, ...] = ("CHECK", "BET_33", "BET_75")

#: The bounded no-facing action set used by the R007 Hero fixture.  The existing
#: river tree has one configured bet size; this adapter deliberately maps only
#: the always-stack-feasible 0.33-pot branch and does not add a raise branch.
R007_NO_FACING_ACTIONS: tuple[str, ...] = ("CHECK", "BET_33")

#: The bounded no-facing action set used by the explicit R001 Hero fixture.
R001_NO_FACING_ACTIONS: tuple[str, ...] = ("CHECK", "BET_75")

#: Actions available when Hero faces a (non all-in) bet. Phase 3 scores RAISE.
FACING_ACTIONS: tuple[str, ...] = ("FOLD", "CALL", "RAISE_ALL_IN")

#: The complete action vocabulary (both branches), for shared downstream use.
ALL_ACTIONS: tuple[str, ...] = NO_FACING_ACTIONS + FACING_ACTIONS

#: The two historical facing-all-in actions with exact showdown/fold terminals.
FACING_ALL_IN_ACTIONS: tuple[str, ...] = ("FOLD", "CALL")


def legal_actions(
    *,
    facing_bet: bool,
    bet_is_all_in: bool,
    no_facing_bet_action: str | None = None,
) -> tuple[str, ...]:
    """Return the legal action set for a river node.

    The historical path supports a facing-all-in ``FOLD, CALL`` decision. The
    opt-in R007 fixture also supports the existing tree's one fixed no-facing
    size as ``CHECK, BET_33``. Generic no-facing and non-all-in-facing branches
    remain rejected so no unscored action can silently enter a decision.
    """
    if not facing_bet and no_facing_bet_action == "BET_33":
        return R007_NO_FACING_ACTIONS
    if not facing_bet and no_facing_bet_action == "BET_75":
        return R001_NO_FACING_ACTIONS
    if not facing_bet:
        raise NotImplementedError(
            "no-facing decisions require a bounded BET_33 or BET_75 river adapter; "
            "the generic no-facing vocabulary is not scored"
        )
    if not bet_is_all_in:
        raise NotImplementedError(
            "facing a non all-in bet (which allows RAISE_ALL_IN) is not scored "
            "until the CFR phase; task 3 only supports facing an all-in bet"
        )
    return FACING_ALL_IN_ACTIONS
