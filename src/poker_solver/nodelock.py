"""Node-lock configuration and river application helpers (Phase 4).

This module keeps the first node-lock layer narrow: it validates lock requests,
projects aggregate action targets into per-combo policies, and can either keep
unlocked infosets at the baseline profile or re-run CFR+ with hard-locked
infosets fixed. Mode 2 records the opponent's exact best-response worst-case
value for resolve runs. Sensitivity analysis records exact EV deltas across
target-frequency and combo-allocation sweeps without touching explanation
generation.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from poker_ai.scenario import Scenario

from .best_response import best_response_value, exploitability
from .cfr_plus import CFRPlus
from .evaluate import expected_value
from .game import Chance, Decision, Game, Node
from .river_solve import (
    RiverComboPolicy,
    RiverScenarioSolveResult,
    _combo_policies,
    solve_frozen_river_scenario,
)
from .river_tree import RiverBettingConfig, build_river_game
from .strategy import ActionDist, StrategyProfile, validate_profile

LockMode = Literal["HARD", "SOFT", "DISABLE"]
ComboAllocation = Literal["baseline_scaled", "uniform"]
UnlockedPolicyMode = Literal["fix_to_baseline", "resolve", "soft_resolve"]

LOCK_MODES: tuple[str, ...] = ("HARD", "SOFT", "DISABLE")
COMBO_ALLOCATIONS: tuple[str, ...] = ("baseline_scaled", "uniform")
UNLOCKED_POLICY_MODES: tuple[str, ...] = ("fix_to_baseline", "resolve", "soft_resolve")


@dataclass(frozen=True, slots=True)
class NodeLockRule:
    """One aggregate action-frequency target for a river infoset group."""

    action: str
    target_frequency: float
    actor: str | None = None
    phase: str | None = None
    infoset: str | None = None
    combo_allocation: ComboAllocation = "baseline_scaled"
    rule_id: str = ""

    def __post_init__(self) -> None:
        if not self.action:
            raise ValueError("action must not be empty")
        _validate_probability(self.target_frequency, "target_frequency")
        if self.combo_allocation not in COMBO_ALLOCATIONS:
            raise ValueError(f"unknown combo_allocation {self.combo_allocation!r}")
        has_infoset = self.infoset is not None
        has_group = self.actor is not None or self.phase is not None
        if has_infoset == has_group:
            raise ValueError("set either infoset or actor+phase, but not both")
        if has_infoset:
            if not self.infoset:
                raise ValueError("infoset must not be empty")
        else:
            if self.actor not in ("OOP", "IP"):
                raise ValueError(f"actor must be 'OOP' or 'IP', got {self.actor!r}")
            if not self.phase:
                raise ValueError("phase must not be empty")


@dataclass(frozen=True, slots=True)
class NodeLockConfig:
    """Node-lock mode and rules for a single solve."""

    rules: tuple[NodeLockRule, ...] = ()
    lock_mode: LockMode = "HARD"
    unlocked_policy_mode: UnlockedPolicyMode = "fix_to_baseline"

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))
        if self.lock_mode not in LOCK_MODES:
            raise ValueError(f"unknown lock_mode {self.lock_mode!r}")
        if self.unlocked_policy_mode not in UNLOCKED_POLICY_MODES:
            raise ValueError(f"unknown unlocked_policy_mode {self.unlocked_policy_mode!r}")


@dataclass(frozen=True, slots=True)
class NodeLockComboPolicy:
    """Projected policy for one affected combo infoset."""

    combo: str
    infoset: str
    phase: str
    policy: ActionDist
    reach_weight: float


@dataclass(frozen=True, slots=True)
class AppliedNodeLock:
    """A validated and applied node-lock rule."""

    rule_id: str
    action: str
    target_frequency: float
    achieved_frequency: float
    combo_allocation: ComboAllocation
    target_infosets: tuple[str, ...]
    combo_policies: tuple[NodeLockComboPolicy, ...]


@dataclass(frozen=True, slots=True)
class NodeLockApplication:
    """A full profile after applying node locks plus provenance for the locks."""

    profile: StrategyProfile
    applied_locks: tuple[AppliedNodeLock, ...]
    lock_mode: LockMode
    unlocked_policy_mode: UnlockedPolicyMode


@dataclass(frozen=True, slots=True)
class NodeLockWorstCaseMetrics:
    """Mode 2 opponent best-response metrics for a fixed hero policy.

    ``player0_worst_case_value`` follows the solver convention. Hero fields use
    hero utility, so they remain sign-stable when the scenario hero is IP.
    """

    hero_player: int
    opponent_player: int
    opponent_best_response_value: float
    player0_worst_case_value: float
    hero_value: float
    hero_worst_case_value: float
    worst_case_penalty: float


@dataclass(frozen=True, slots=True)
class NodeLockMetrics:
    """Independent verifier metrics for the node-locked profile.

    Game values follow the solver convention: player 0 expected utility.
    """

    base_game_value: float
    game_value: float
    ev_delta: float
    exploitability: float
    worst_case: NodeLockWorstCaseMetrics | None = None


@dataclass(frozen=True, slots=True)
class RiverNodeLockSolveResult:
    """River scenario solve result with node-lock provenance."""

    base_result: RiverScenarioSolveResult
    strategy: StrategyProfile
    metrics: NodeLockMetrics
    combo_policies: tuple[RiverComboPolicy, ...]
    applied_locks: tuple[AppliedNodeLock, ...]
    lock_mode: LockMode
    unlocked_policy_mode: UnlockedPolicyMode


@dataclass(frozen=True, slots=True)
class NodeLockSensitivityPoint:
    """One exact EV sample in a node-lock target/allocation sweep."""

    target_frequency: float
    combo_allocation: ComboAllocation
    achieved_frequency: float
    base_game_value: float
    game_value: float
    ev_delta: float
    exploitability: float
    worst_case_penalty: float | None = None


@dataclass(frozen=True, slots=True)
class NodeLockAllocationComparison:
    """EV gap between uniform and baseline-scaled allocation at one target."""

    target_frequency: float
    baseline_scaled_game_value: float
    uniform_game_value: float
    uniform_minus_baseline_scaled_game_value: float
    baseline_scaled_ev_delta: float
    uniform_ev_delta: float
    uniform_minus_baseline_scaled_ev_delta: float


@dataclass(frozen=True, slots=True)
class NodeLockSensitivityReport:
    """Node-lock sensitivity sweep with ADR-0002 allocation EV comparisons."""

    scenario_id: str
    action: str
    actor: str | None
    phase: str | None
    infoset: str | None
    lock_mode: LockMode
    unlocked_policy_mode: UnlockedPolicyMode
    base_game_value: float
    points: tuple[NodeLockSensitivityPoint, ...]
    allocation_comparisons: tuple[NodeLockAllocationComparison, ...]


def apply_node_locks(
    game: Game,
    baseline_profile: StrategyProfile,
    config: NodeLockConfig | None = None,
    *,
    reach_weights: Mapping[str, float] | None = None,
    resolve_iterations: int = 0,
    average_delay: int = 0,
) -> NodeLockApplication:
    """Apply node locks to ``baseline_profile`` and return a valid full profile."""
    config = config or NodeLockConfig()
    validate_profile(game, baseline_profile)
    if resolve_iterations < 0:
        raise ValueError(f"resolve_iterations must be non-negative, got {resolve_iterations}")

    projected = _project_node_locks(game, baseline_profile, config, reach_weights=reach_weights)
    if not projected.applied_locks or config.unlocked_policy_mode == "fix_to_baseline":
        return projected
    if config.unlocked_policy_mode == "soft_resolve":
        raise NotImplementedError("soft_resolve is not implemented; requires a new ADR")
    if config.lock_mode != "HARD":
        raise NotImplementedError("resolve currently requires HARD node locks")

    fixed_strategy = {
        infoset: projected.profile[infoset]
        for lock in projected.applied_locks
        for infoset in lock.target_infosets
    }
    profile = (
        CFRPlus(
            game,
            average_delay=average_delay,
            fixed_strategy=fixed_strategy,
        )
        .run(resolve_iterations)
        .average_strategy()
    )
    return NodeLockApplication(
        profile=profile,
        applied_locks=projected.applied_locks,
        lock_mode=config.lock_mode,
        unlocked_policy_mode=config.unlocked_policy_mode,
    )


def solve_nodelocked_river_scenario(
    scenario: Scenario,
    *,
    bet_fraction: float,
    iterations: int,
    nodelock_config: NodeLockConfig | None = None,
    checkpoints: tuple[int, ...] = (),
    average_delay: int = 0,
) -> RiverNodeLockSolveResult:
    """Solve a frozen river scenario and apply P4-1 node-lock configuration."""
    config = nodelock_config or NodeLockConfig()
    base_result = solve_frozen_river_scenario(
        scenario,
        bet_fraction=bet_fraction,
        iterations=iterations,
        checkpoints=checkpoints,
        average_delay=average_delay,
    )
    return _nodelocked_result_from_base(
        scenario,
        bet_fraction=bet_fraction,
        iterations=iterations,
        base_result=base_result,
        config=config,
        average_delay=average_delay,
    )


def analyze_nodelock_sensitivity(
    scenario: Scenario,
    *,
    bet_fraction: float,
    iterations: int,
    rule: NodeLockRule,
    target_frequencies: tuple[float, ...],
    combo_allocations: tuple[ComboAllocation, ...] = COMBO_ALLOCATIONS,
    lock_mode: LockMode = "HARD",
    unlocked_policy_mode: UnlockedPolicyMode = "fix_to_baseline",
    checkpoints: tuple[int, ...] = (),
    average_delay: int = 0,
) -> NodeLockSensitivityReport:
    """Sweep one node-lock rule across targets and allocation rules."""
    target_frequencies = tuple(target_frequencies)
    combo_allocations = tuple(combo_allocations)
    if not target_frequencies:
        raise ValueError("target_frequencies must not be empty")
    if len(set(target_frequencies)) != len(target_frequencies):
        raise ValueError("target_frequencies must be unique")
    if not combo_allocations:
        raise ValueError("combo_allocations must not be empty")
    if len(set(combo_allocations)) != len(combo_allocations):
        raise ValueError("combo_allocations must be unique")
    if lock_mode != "HARD":
        raise NotImplementedError("node-lock sensitivity currently requires HARD locks")
    if unlocked_policy_mode == "soft_resolve":
        raise NotImplementedError("soft_resolve is not implemented; requires a new ADR")
    for target_frequency in target_frequencies:
        _validate_probability(target_frequency, "target_frequency")
    for combo_allocation in combo_allocations:
        if combo_allocation not in COMBO_ALLOCATIONS:
            raise ValueError(f"unknown combo_allocation {combo_allocation!r}")

    base_result = solve_frozen_river_scenario(
        scenario,
        bet_fraction=bet_fraction,
        iterations=iterations,
        checkpoints=checkpoints,
        average_delay=average_delay,
    )
    points: list[NodeLockSensitivityPoint] = []
    by_key: dict[tuple[float, ComboAllocation], NodeLockSensitivityPoint] = {}
    for target_frequency in target_frequencies:
        for combo_allocation in combo_allocations:
            sample_rule = replace(
                rule,
                target_frequency=target_frequency,
                combo_allocation=combo_allocation,
            )
            result = _nodelocked_result_from_base(
                scenario,
                bet_fraction=bet_fraction,
                iterations=iterations,
                base_result=base_result,
                config=NodeLockConfig(
                    rules=(sample_rule,),
                    lock_mode=lock_mode,
                    unlocked_policy_mode=unlocked_policy_mode,
                ),
                average_delay=average_delay,
            )
            if len(result.applied_locks) != 1:
                raise RuntimeError("sensitivity samples must apply exactly one lock")
            applied = result.applied_locks[0]
            worst_case_penalty = (
                None
                if result.metrics.worst_case is None
                else result.metrics.worst_case.worst_case_penalty
            )
            point = NodeLockSensitivityPoint(
                target_frequency=target_frequency,
                combo_allocation=combo_allocation,
                achieved_frequency=applied.achieved_frequency,
                base_game_value=result.metrics.base_game_value,
                game_value=result.metrics.game_value,
                ev_delta=result.metrics.ev_delta,
                exploitability=result.metrics.exploitability,
                worst_case_penalty=worst_case_penalty,
            )
            points.append(point)
            by_key[(target_frequency, combo_allocation)] = point

    return NodeLockSensitivityReport(
        scenario_id=scenario.scenario_id,
        action=rule.action,
        actor=rule.actor,
        phase=rule.phase,
        infoset=rule.infoset,
        lock_mode=lock_mode,
        unlocked_policy_mode=unlocked_policy_mode,
        base_game_value=base_result.metrics.game_value,
        points=tuple(points),
        allocation_comparisons=_allocation_comparisons(target_frequencies, by_key),
    )


def _nodelocked_result_from_base(
    scenario: Scenario,
    *,
    bet_fraction: float,
    iterations: int,
    base_result: RiverScenarioSolveResult,
    config: NodeLockConfig,
    average_delay: int,
) -> RiverNodeLockSolveResult:
    game, hero_prefix = _river_game_for_scenario(scenario, bet_fraction=bet_fraction)
    application = apply_node_locks(
        game,
        base_result.strategy,
        config,
        reach_weights=river_infoset_reach_weights(game, base_result.strategy),
        resolve_iterations=iterations,
        average_delay=average_delay,
    )
    locked_game_value = expected_value(game, application.profile)
    worst_case = _mode2_worst_case_metrics(
        game,
        application.profile,
        hero_prefix,
        game_value=locked_game_value,
        enabled=config.unlocked_policy_mode == "resolve" and bool(application.applied_locks),
    )
    metrics = NodeLockMetrics(
        base_game_value=base_result.metrics.game_value,
        game_value=locked_game_value,
        ev_delta=locked_game_value - base_result.metrics.game_value,
        exploitability=exploitability(game, application.profile),
        worst_case=worst_case,
    )
    return RiverNodeLockSolveResult(
        base_result=base_result,
        strategy=application.profile,
        metrics=metrics,
        combo_policies=_combo_policies(game, application.profile, hero_prefix),
        applied_locks=application.applied_locks,
        lock_mode=application.lock_mode,
        unlocked_policy_mode=application.unlocked_policy_mode,
    )


def _allocation_comparisons(
    target_frequencies: tuple[float, ...],
    points: Mapping[tuple[float, ComboAllocation], NodeLockSensitivityPoint],
) -> tuple[NodeLockAllocationComparison, ...]:
    comparisons: list[NodeLockAllocationComparison] = []
    for target_frequency in target_frequencies:
        baseline = points.get((target_frequency, "baseline_scaled"))
        uniform = points.get((target_frequency, "uniform"))
        if baseline is None or uniform is None:
            continue
        comparisons.append(
            NodeLockAllocationComparison(
                target_frequency=target_frequency,
                baseline_scaled_game_value=baseline.game_value,
                uniform_game_value=uniform.game_value,
                uniform_minus_baseline_scaled_game_value=(uniform.game_value - baseline.game_value),
                baseline_scaled_ev_delta=baseline.ev_delta,
                uniform_ev_delta=uniform.ev_delta,
                uniform_minus_baseline_scaled_ev_delta=uniform.ev_delta - baseline.ev_delta,
            )
        )
    return tuple(comparisons)


def river_infoset_reach_weights(game: Game, profile: StrategyProfile) -> dict[str, float]:
    """Return full profile reach weights for river infosets keyed by infoset."""
    validate_profile(game, profile)
    weights = dict.fromkeys(game.infosets, 0.0)
    _accumulate_infoset_reach(game.root, profile, weights, reach=1.0)
    return weights


def _project_node_locks(
    game: Game,
    baseline_profile: StrategyProfile,
    config: NodeLockConfig,
    *,
    reach_weights: Mapping[str, float] | None,
) -> NodeLockApplication:
    if config.lock_mode == "DISABLE" or not config.rules:
        return NodeLockApplication(
            profile=_copy_profile(baseline_profile),
            applied_locks=(),
            lock_mode=config.lock_mode,
            unlocked_policy_mode=config.unlocked_policy_mode,
        )
    if config.lock_mode == "SOFT":
        raise NotImplementedError("SOFT node locks are not implemented; require a new ADR")

    profile = _copy_profile(baseline_profile)
    applied_locks: list[AppliedNodeLock] = []
    seen_infosets: set[str] = set()
    for rule in config.rules:
        target_infosets = _target_infosets(game, rule)
        overlap = seen_infosets.intersection(target_infosets)
        if overlap:
            raise ValueError(f"multiple node-lock rules target infosets {sorted(overlap)}")
        seen_infosets.update(target_infosets)

        if rule.combo_allocation == "uniform":
            action_probs = dict.fromkeys(target_infosets, rule.target_frequency)
        else:
            action_probs = _baseline_scaled_action_probs(
                profile,
                target_infosets,
                rule.action,
                rule.target_frequency,
                reach_weights=reach_weights,
            )

        for infoset, action_prob in action_probs.items():
            profile[infoset] = _with_action_probability(
                profile[infoset],
                rule.action,
                action_prob,
            )
        achieved = _weighted_action_frequency(
            profile,
            target_infosets,
            rule.action,
            reach_weights=reach_weights,
        )
        combo_policies = tuple(
            _combo_policy_for_infoset(
                infoset,
                profile[infoset],
                reach_weights=reach_weights,
            )
            for infoset in target_infosets
        )
        applied_locks.append(
            AppliedNodeLock(
                rule_id=rule.rule_id,
                action=rule.action,
                target_frequency=rule.target_frequency,
                achieved_frequency=achieved,
                combo_allocation=rule.combo_allocation,
                target_infosets=target_infosets,
                combo_policies=combo_policies,
            )
        )

    validate_profile(game, profile)
    return NodeLockApplication(
        profile=profile,
        applied_locks=tuple(applied_locks),
        lock_mode=config.lock_mode,
        unlocked_policy_mode=config.unlocked_policy_mode,
    )


def _target_infosets(game: Game, rule: NodeLockRule) -> tuple[str, ...]:
    if rule.infoset is not None:
        if rule.infoset not in game.infosets:
            raise ValueError(f"unknown infoset {rule.infoset!r}")
        infosets = (rule.infoset,)
    else:
        infosets = tuple(
            infoset
            for infoset in game.infosets
            if _matches_river_target(infoset, actor=rule.actor, phase=rule.phase)
        )
        if not infosets:
            raise ValueError(
                f"unknown river infoset target actor={rule.actor!r} phase={rule.phase!r}"
            )

    for infoset in infosets:
        actions = game.actions_of(infoset)
        if rule.action not in actions:
            raise ValueError(
                f"action {rule.action!r} is not available at infoset {infoset!r}; "
                f"actions are {actions!r}"
            )
    return infosets


def _accumulate_infoset_reach(
    node: Node,
    profile: StrategyProfile,
    weights: dict[str, float],
    *,
    reach: float,
) -> None:
    if isinstance(node, Chance):
        for prob, child, _label in node.branches:
            _accumulate_infoset_reach(child, profile, weights, reach=reach * prob)
        return
    if isinstance(node, Decision):
        weights[node.infoset] += reach
        dist = profile[node.infoset]
        for action, child in zip(node.actions, node.children, strict=True):
            _accumulate_infoset_reach(child, profile, weights, reach=reach * dist[action])


def _matches_river_target(infoset: str, *, actor: str | None, phase: str | None) -> bool:
    candidate_actor, _combo, candidate_phase = _parse_river_infoset(infoset)
    return candidate_actor == actor and candidate_phase == phase


def _baseline_scaled_action_probs(
    profile: StrategyProfile,
    infosets: tuple[str, ...],
    action: str,
    target_frequency: float,
    *,
    reach_weights: Mapping[str, float] | None,
) -> dict[str, float]:
    baseline_frequency = _weighted_action_frequency(
        profile,
        infosets,
        action,
        reach_weights=reach_weights,
    )
    if target_frequency <= baseline_frequency:
        scale = 0.0 if baseline_frequency == 0.0 else target_frequency / baseline_frequency
        return {infoset: profile[infoset][action] * scale for infoset in infosets}

    complement = 1.0 - baseline_frequency
    scale = 0.0 if complement == 0.0 else (1.0 - target_frequency) / complement
    return {infoset: 1.0 - (1.0 - profile[infoset][action]) * scale for infoset in infosets}


def _weighted_action_frequency(
    profile: StrategyProfile,
    infosets: tuple[str, ...],
    action: str,
    *,
    reach_weights: Mapping[str, float] | None,
) -> float:
    weights = [_infoset_weight(infoset, reach_weights) for infoset in infosets]
    total_weight = math.fsum(weights)
    if total_weight <= 0.0:
        raise ValueError("target infosets have zero aggregate reach weight")
    return (
        math.fsum(
            weight * profile[infoset][action]
            for infoset, weight in zip(infosets, weights, strict=True)
        )
        / total_weight
    )


def _with_action_probability(dist: ActionDist, action: str, action_prob: float) -> ActionDist:
    _validate_probability(action_prob, "action_prob")
    if action not in dist:
        raise ValueError(f"action {action!r} missing from policy")
    if len(dist) == 1:
        if action_prob != 1.0:
            raise ValueError("single-action infosets can only be locked to probability 1")
        return {action: 1.0}

    old_action_prob = dist[action]
    old_other = 1.0 - old_action_prob
    new_other = 1.0 - action_prob
    if old_other > 0.0:
        scale = new_other / old_other
        adjusted = {
            candidate: (action_prob if candidate == action else prob * scale)
            for candidate, prob in dist.items()
        }
    else:
        other_actions = tuple(candidate for candidate in dist if candidate != action)
        fallback = new_other / len(other_actions)
        adjusted = {
            candidate: (action_prob if candidate == action else fallback) for candidate in dist
        }
    total = math.fsum(adjusted.values())
    if total <= 0.0:
        raise ValueError("adjusted policy has zero mass")
    return {candidate: prob / total for candidate, prob in adjusted.items()}


def _combo_policy_for_infoset(
    infoset: str,
    policy: ActionDist,
    *,
    reach_weights: Mapping[str, float] | None,
) -> NodeLockComboPolicy:
    _actor, combo, phase = _parse_river_infoset(infoset)
    return NodeLockComboPolicy(
        combo=combo,
        infoset=infoset,
        phase=phase,
        policy=dict(policy),
        reach_weight=_infoset_weight(infoset, reach_weights),
    )


def _parse_river_infoset(infoset: str) -> tuple[str, str, str]:
    parts = infoset.split(":", maxsplit=2)
    if len(parts) != 3:
        raise ValueError(f"river infoset must have actor:combo:phase form, got {infoset!r}")
    actor, combo, phase = parts
    if actor not in ("OOP", "IP") or not combo or not phase:
        raise ValueError(f"invalid river infoset {infoset!r}")
    return actor, combo, phase


def _infoset_weight(infoset: str, reach_weights: Mapping[str, float] | None) -> float:
    if reach_weights is None:
        return 1.0
    weight = reach_weights.get(infoset, 0.0)
    if not math.isfinite(weight) or weight < 0.0:
        raise ValueError(f"invalid reach weight for infoset {infoset!r}: {weight}")
    return weight


def _river_game_for_scenario(scenario: Scenario, *, bet_fraction: float) -> tuple[Game, str]:
    config = RiverBettingConfig(pot=scenario.pot, bet_fraction=bet_fraction)
    if config.bet > scenario.effective_stack:
        raise ValueError(
            f"bet size {config.bet} exceeds effective stack {scenario.effective_stack}"
        )
    board = scenario.board_cards()
    if scenario.position == "OOP":
        return (
            build_river_game(
                config, scenario.hero_range_obj(), scenario.opponent_range_obj(), board
            ),
            "OOP",
        )
    return (
        build_river_game(config, scenario.opponent_range_obj(), scenario.hero_range_obj(), board),
        "IP",
    )


def _mode2_worst_case_metrics(
    game: Game,
    profile: StrategyProfile,
    hero_prefix: str,
    *,
    game_value: float,
    enabled: bool,
) -> NodeLockWorstCaseMetrics | None:
    if not enabled:
        return None
    hero_player = _river_player_for_actor(hero_prefix)
    opponent_player = 1 - hero_player
    opponent_best_response = best_response_value(game, opponent_player, profile)
    player0_worst_case = opponent_best_response if opponent_player == 0 else -opponent_best_response
    hero_value = _player_utility(game_value, hero_player)
    hero_worst_case = -opponent_best_response
    return NodeLockWorstCaseMetrics(
        hero_player=hero_player,
        opponent_player=opponent_player,
        opponent_best_response_value=opponent_best_response,
        player0_worst_case_value=player0_worst_case,
        hero_value=hero_value,
        hero_worst_case_value=hero_worst_case,
        worst_case_penalty=hero_value - hero_worst_case,
    )


def _river_player_for_actor(actor: str) -> int:
    if actor == "OOP":
        return 0
    if actor == "IP":
        return 1
    raise ValueError(f"unknown river actor {actor!r}")


def _player_utility(player0_value: float, player: int) -> float:
    if player == 0:
        return player0_value
    if player == 1:
        return -player0_value
    raise ValueError(f"player must be 0 or 1, got {player}")


def _copy_profile(profile: StrategyProfile) -> StrategyProfile:
    return {infoset: dict(dist) for infoset, dist in profile.items()}


def _validate_probability(value: float, field_name: str) -> None:
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} must be finite and in [0, 1], got {value}")
