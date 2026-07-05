"""Hero decision: lookup base policy -> rule exploit -> safety mix -> exact EV.

Hero receives an :class:`Observation` -- only *public* information (board, pot,
facing bet, position, its own combo and range, and the opponent's *assumed range*).
It never receives the opponent object, so it structurally cannot read the opponent's
hidden action strategy (AI Spec 6.3); the tripwire in :mod:`poker_ai.opponent`
guards against a code path that tried.

The EV is exact (``solver_exact``, ADR-0008). Task 3 restricts the model to a
facing-all-in decision whose terminals are showdown-determined:

* ``FOLD`` -> Hero invests nothing more; incremental EV from the node is ``0``.
* ``CALL`` -> a river showdown for the final pot; its win/tie/lose probabilities come
  from the exact enumerator :func:`poker_core.showdown_ev.showdown_equity`.

With effective-stack all-in ``B`` and dead-money pot ``P`` at the node, the
incremental EV of calling is ``win*(P+B) + tie*(P/2) - lose*B`` (chips gained
relative to the decision node; ``ev_definition = "incremental_ev_from_current_node"``,
Solver spec 8.3). The policy EV is the probability-weighted mean of the per-action
EVs, which is exact because each terminal EV is exact.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

from poker_core.card import Card
from poker_core.combo import Combo
from poker_core.dpl_schema import MIXING_ABS_TOL, DetectedLeak, HandBucket
from poker_core.range_model import Range
from poker_core.showdown_ev import DEFAULT_EV_UNIT, ShowdownEquity, showdown_equity
from poker_core.state_cluster import classify_board, cluster_def_version

from .actions import legal_actions
from .baseline_strategy import FACING_ALL_IN, BaselineStrategy, build_situation_key
from .exploit import RuleExploitProvider
from .hand_bucket import BucketDefinition, classify_combo
from .mixer import ActionSelector, safety_mix

#: EV definition label recorded in the DPL for the task-3 decision EV (Solver 8.3).
EV_DEFINITION = "incremental_ev_from_current_node"

#: Exploit source recorded when there is no exploitation (identity rule, alpha=0).
NO_EXPLOIT_SOURCE = "rule_based"


@dataclass(frozen=True)
class Observation:
    """The public information Hero conditions on (no opponent object; AI Spec 6.3)."""

    hand_id: str
    session_id: str
    board: tuple[Card, ...]
    position: str
    pot: float
    facing_bet: float
    effective_stack: float
    hero_combo: Combo
    hero_range: Range
    opponent_assumed_range: Range


@dataclass(frozen=True)
class DecisionResult:
    """The outcome of one Hero decision, ready to assemble into a DPL."""

    state_cluster: str
    cluster_def_version: str
    hand_bucket: HandBucket
    situation_key: str
    base_policy: dict[str, float]
    exploit_policy: dict[str, float]
    final_policy: dict[str, float]
    selected_action: str
    sampling_seed: int
    base_ev: float
    exploit_ev: float
    final_ev: float
    ev_unit: str
    ev_definition: str
    applied_leak_reason_ids: list[str]
    trigger_reasons: list[str]
    mix_reasons: list[str]
    exploit_source: str


def call_fold_action_evs(
    equity: ShowdownEquity,
    pot: float,
    facing_bet: float,
) -> dict[str, float]:
    """Exact incremental EV of each facing-all-in action (see module docstring)."""
    ev_fold = 0.0
    ev_call = equity.win * (pot + facing_bet) + equity.tie * (pot / 2.0) - equity.lose * facing_bet
    return {"FOLD": ev_fold, "CALL": ev_call}


def policy_ev(policy: dict[str, float], action_ev: dict[str, float]) -> float:
    """Probability-weighted EV of a policy over per-action EVs (exact)."""
    return math.fsum(prob * action_ev[action] for action, prob in policy.items())


class HeroAgent:
    """Looks up the base policy, applies rule exploitation, samples and scores EV."""

    def __init__(
        self,
        baseline: BaselineStrategy,
        bucket_def: BucketDefinition,
        *,
        safety_alpha: float = 0.0,
        exploit_provider: RuleExploitProvider | None = None,
    ) -> None:
        if not math.isfinite(safety_alpha) or not 0.0 <= safety_alpha <= 1.0:
            raise ValueError(f"safety_alpha must be finite and in [0, 1], got {safety_alpha}")
        self.baseline = baseline
        self.bucket_def = bucket_def
        self.safety_alpha = safety_alpha
        self.exploit_provider = exploit_provider or RuleExploitProvider()

    def decide(
        self,
        obs: Observation,
        *,
        detected_leaks: tuple[DetectedLeak, ...] | list[DetectedLeak] = (),
    ) -> DecisionResult:
        """Produce the base/exploit/final policies, selected action and exact EVs."""
        # Legal set for facing an all-in bet: {FOLD, CALL} (validates the branch).
        legal = legal_actions(facing_bet=obs.facing_bet > 0.0, bet_is_all_in=True)

        state_cluster = classify_board(obs.board)
        hand_bucket = classify_combo(
            obs.hero_combo, obs.hero_range, obs.board, bucket_def=self.bucket_def
        )
        situation_key = build_situation_key(state_cluster, obs.position, FACING_ALL_IN)

        base_policy = self.baseline.policy_for(FACING_ALL_IN, hand_bucket)
        if set(base_policy) - set(legal):
            raise ValueError(f"base policy cites actions outside the legal set {legal}")

        equity = showdown_equity(
            Range({obs.hero_combo.canonical(): 1.0}),
            obs.opponent_assumed_range,
            obs.board,
        )
        action_ev = call_fold_action_evs(equity, obs.pot, obs.facing_bet)

        exploit = self.exploit_provider.build(
            base_policy=base_policy,
            detected_leaks=detected_leaks if self.safety_alpha > 0.0 else (),
            legal_actions=legal,
            action_ev=action_ev,
        )
        exploit_policy = exploit.policy
        final_policy = safety_mix(base_policy, exploit_policy, self.safety_alpha)
        mix_reasons = (
            ["MIX_R001"]
            if self.safety_alpha > 0.0 and not _policies_equal(base_policy, final_policy)
            else []
        )
        trigger_reasons = list(exploit.trigger_reasons) if mix_reasons else []

        sampling_seed = _sampling_seed_for(obs.session_id, obs.hand_id)
        selected_action = ActionSelector(sampling_seed).select(final_policy)

        return DecisionResult(
            state_cluster=state_cluster,
            cluster_def_version=cluster_def_version(),
            hand_bucket=hand_bucket,
            situation_key=situation_key,
            base_policy=base_policy,
            exploit_policy=exploit_policy,
            final_policy=final_policy,
            selected_action=selected_action,
            sampling_seed=sampling_seed,
            base_ev=policy_ev(base_policy, action_ev),
            exploit_ev=policy_ev(exploit_policy, action_ev),
            final_ev=policy_ev(final_policy, action_ev),
            ev_unit=DEFAULT_EV_UNIT,
            ev_definition=EV_DEFINITION,
            applied_leak_reason_ids=list(exploit.applied_leak_reason_ids) if mix_reasons else [],
            trigger_reasons=trigger_reasons,
            mix_reasons=mix_reasons,
            exploit_source=NO_EXPLOIT_SOURCE,
        )


def _sampling_seed_for(session_id: str, hand_id: str) -> int:
    """Deterministic per-decision sampling seed from stable string ids.

    Uses a fixed hashing scheme (not Python's salted ``hash``) so the same session
    replays identically across processes.
    """
    digest = hashlib.sha256(f"{session_id}:{hand_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _policies_equal(first: dict[str, float], second: dict[str, float]) -> bool:
    actions = set(first) | set(second)
    return all(
        abs(first.get(action, 0.0) - second.get(action, 0.0)) <= MIXING_ABS_TOL
        for action in actions
    )
