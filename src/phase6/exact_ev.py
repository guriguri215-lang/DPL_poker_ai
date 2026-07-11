"""Strict exact-EV evaluation for frozen Phase 6 policy inputs.

The evaluator compiles complete strategy profiles for one game and one fixed
opponent.  It deliberately accepts no observations, detector outputs, safety
mixing state, or execution-sampling policy: those inputs are outside the exact
EV estimand frozen by ADR-0020.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

from poker_solver.best_response import best_response_strategy
from poker_solver.evaluate import expected_value, expected_value_by_leaves
from poker_solver.game import Game
from poker_solver.strategy import (
    DIST_SUM_TOLERANCE,
    ActionDist,
    StrategyProfile,
    validate_profile,
)

EV_CONSISTENCY_ABS_TOLERANCE = 1e-12
EV_DENOMINATOR_ABS_TOLERANCE = 1e-12
EV_CONSISTENCY_ABS_TOLERANCE_WIRE = "0.000000000001"
EV_DENOMINATOR_ABS_TOLERANCE_WIRE = "0.000000000001"

EFFICIENCY_STATUS_DEFINED = "defined"
EFFICIENCY_STATUS_ZERO_OPPORTUNITY = "zero_or_near_zero_opportunity"


@dataclass(frozen=True, slots=True)
class PolicySlice:
    """A policy fragment joined to one frozen game and opponent identity."""

    game_id: str
    opponent_id: str
    policy: Mapping[str, Mapping[str, float]]


@dataclass(frozen=True, slots=True)
class CompiledStrategyProfiles:
    """Complete base, final, and oracle-best-response strategy profiles."""

    game_id: str
    opponent_id: str
    hero_player: int
    base: StrategyProfile
    final: StrategyProfile
    oracle_br: StrategyProfile


@dataclass(frozen=True, slots=True)
class ExactEvPaths:
    """Hero EV from the production traversal and independent leaf traversal."""

    production: float
    independent_leaves: float


@dataclass(frozen=True, slots=True)
class EfficiencyResult:
    """Unrounded exploitation-efficiency terms for one exact EV cell."""

    gain: float
    opportunity: float
    efficiency: float | None
    efficiency_status: str


@dataclass(frozen=True, slots=True)
class ExactEvCell:
    """The three exact Hero EVs and their derived efficiency result."""

    profiles: CompiledStrategyProfiles
    base_ev: ExactEvPaths
    final_ev: ExactEvPaths
    oracle_br_ev: ExactEvPaths
    gain: float
    opportunity: float
    efficiency: float | None
    efficiency_status: str


def compile_strategy_profiles(
    game: Game,
    *,
    hero_player: int,
    opponent_policy: PolicySlice,
    base_hero_policy: PolicySlice,
    final_hero_policy: PolicySlice,
) -> CompiledStrategyProfiles:
    """Compile complete profiles while keeping one opponent fixed.

    ``opponent_policy`` and ``base_hero_policy`` must cover their respective
    players' infosets exactly. ``final_hero_policy`` is an explicit overlay and
    may mention any subset of Hero infosets; every unmentioned infoset is copied
    from the base policy. Unknown infosets and implicit action defaults are
    rejected.
    """
    if hero_player not in (0, 1):
        raise ValueError(f"hero_player must be 0 or 1, got {hero_player}")
    _validate_join(game, opponent_policy, base_hero_policy, final_hero_policy)

    opponent_player = 1 - hero_player
    opponent_infosets = game.infosets_of(opponent_player)
    hero_infosets = game.infosets_of(hero_player)

    opponent = _validated_slice(
        game,
        opponent_policy.policy,
        expected_infosets=opponent_infosets,
        allow_subset=False,
        label="opponent policy",
    )
    base_hero = _validated_slice(
        game,
        base_hero_policy.policy,
        expected_infosets=hero_infosets,
        allow_subset=False,
        label="base Hero policy",
    )
    final_overlay = _validated_slice(
        game,
        final_hero_policy.policy,
        expected_infosets=hero_infosets,
        allow_subset=True,
        label="final Hero policy",
    )

    base = _combine_profile(game, hero_player, base_hero, opponent)
    final_hero = {
        infoset: _copy_dist(final_overlay.get(infoset, base_hero[infoset]))
        for infoset in hero_infosets
    }
    final = _combine_profile(game, hero_player, final_hero, opponent)

    oracle_actions = best_response_strategy(game, hero_player, base)
    oracle_hero = {
        infoset: {
            action: 1.0 if action == oracle_actions[infoset] else 0.0
            for action in game.actions_of(infoset)
        }
        for infoset in hero_infosets
    }
    oracle = _combine_profile(game, hero_player, oracle_hero, opponent)

    for label, profile in (("base", base), ("final", final), ("oracle BR", oracle)):
        try:
            validate_profile(game, profile)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"compiled {label} profile is invalid: {exc}") from exc

    return CompiledStrategyProfiles(
        game_id=game.name,
        opponent_id=opponent_policy.opponent_id,
        hero_player=hero_player,
        base=base,
        final=final,
        oracle_br=oracle,
    )


def evaluate_exact_ev(
    game: Game,
    *,
    hero_player: int,
    opponent_policy: PolicySlice,
    base_hero_policy: PolicySlice,
    final_hero_policy: PolicySlice,
) -> ExactEvCell:
    """Compile and evaluate base, final, and oracle-BR profiles exactly."""
    profiles = compile_strategy_profiles(
        game,
        hero_player=hero_player,
        opponent_policy=opponent_policy,
        base_hero_policy=base_hero_policy,
        final_hero_policy=final_hero_policy,
    )
    base_ev = _evaluate_profile(game, profiles.base, hero_player, "base")
    final_ev = _evaluate_profile(game, profiles.final, hero_player, "final")
    oracle_ev = _evaluate_profile(game, profiles.oracle_br, hero_player, "oracle BR")
    efficiency = calculate_efficiency(
        base_ev=base_ev.production,
        final_ev=final_ev.production,
        oracle_br_ev=oracle_ev.production,
    )
    return ExactEvCell(
        profiles=profiles,
        base_ev=base_ev,
        final_ev=final_ev,
        oracle_br_ev=oracle_ev,
        gain=efficiency.gain,
        opportunity=efficiency.opportunity,
        efficiency=efficiency.efficiency,
        efficiency_status=efficiency.efficiency_status,
    )


def calculate_efficiency(
    *, base_ev: float, final_ev: float, oracle_br_ev: float
) -> EfficiencyResult:
    """Calculate unrounded efficiency and enforce the oracle invariants."""
    for label, value in (
        ("base EV", base_ev),
        ("final EV", final_ev),
        ("oracle BR EV", oracle_br_ev),
    ):
        if (
            not isinstance(value, int | float)
            or isinstance(value, bool)
            or not math.isfinite(value)
        ):
            raise ValueError(f"{label} must be a finite number, got {value!r}")

    gain = float(final_ev - base_ev)
    opportunity = float(oracle_br_ev - base_ev)
    if opportunity < -EV_DENOMINATOR_ABS_TOLERANCE:
        raise ValueError(
            "oracle BR opportunity is negative beyond tolerance: "
            f"{opportunity} < -{EV_DENOMINATOR_ABS_TOLERANCE}"
        )
    if gain > opportunity + EV_DENOMINATOR_ABS_TOLERANCE:
        raise ValueError(
            "final policy exceeds the oracle BR beyond tolerance: "
            f"gain {gain} > opportunity {opportunity} + "
            f"{EV_DENOMINATOR_ABS_TOLERANCE}"
        )
    if abs(opportunity) <= EV_DENOMINATOR_ABS_TOLERANCE:
        return EfficiencyResult(
            gain=gain,
            opportunity=opportunity,
            efficiency=None,
            efficiency_status=EFFICIENCY_STATUS_ZERO_OPPORTUNITY,
        )
    return EfficiencyResult(
        gain=gain,
        opportunity=opportunity,
        efficiency=gain / opportunity,
        efficiency_status=EFFICIENCY_STATUS_DEFINED,
    )


def _validate_join(game: Game, *inputs: PolicySlice) -> None:
    if not isinstance(game.name, str) or not game.name:
        raise ValueError("game.name must be a non-empty game identity")
    for policy_input in inputs:
        if not isinstance(policy_input.game_id, str) or not policy_input.game_id:
            raise ValueError("policy game_id must be a non-empty string")
        if not isinstance(policy_input.opponent_id, str) or not policy_input.opponent_id:
            raise ValueError("policy opponent_id must be a non-empty string")
    game_ids = {policy_input.game_id for policy_input in inputs}
    if game_ids != {game.name}:
        raise ValueError(
            f"policy game_id values {sorted(game_ids)!r} do not join game {game.name!r}"
        )
    opponent_ids = {policy_input.opponent_id for policy_input in inputs}
    if len(opponent_ids) != 1:
        raise ValueError(f"policy opponent_id values do not join exactly: {sorted(opponent_ids)!r}")


def _validated_slice(
    game: Game,
    policy: Mapping[str, Mapping[str, float]],
    *,
    expected_infosets: tuple[str, ...],
    allow_subset: bool,
    label: str,
) -> StrategyProfile:
    if not isinstance(policy, Mapping):
        raise TypeError(f"{label} must be a mapping")
    expected = set(expected_infosets)
    actual = set(policy)
    extra = actual - expected
    if extra:
        raise ValueError(f"{label} has unknown or wrong-player infosets {sorted(extra)}")
    missing = expected - actual
    if missing and not allow_subset:
        raise ValueError(f"{label} is missing infosets {sorted(missing)}")

    copied: StrategyProfile = {}
    for infoset in expected_infosets:
        if infoset not in policy:
            continue
        dist = policy[infoset]
        if not isinstance(dist, Mapping):
            raise TypeError(f"{label} infoset {infoset!r} distribution must be a mapping")
        actions = game.actions_of(infoset)
        if set(dist) != set(actions):
            raise ValueError(
                f"{label} infoset {infoset!r} action keys {sorted(dist)} "
                f"!= legal actions {sorted(actions)}"
            )
        values: ActionDist = {}
        for action in actions:
            probability = dist[action]
            if (
                not isinstance(probability, int | float)
                or isinstance(probability, bool)
                or not math.isfinite(probability)
            ):
                raise ValueError(
                    f"{label} infoset {infoset!r} action {action!r} probability "
                    f"must be finite, got {probability!r}"
                )
            if probability < 0.0:
                raise ValueError(
                    f"{label} infoset {infoset!r} action {action!r} probability "
                    f"must be non-negative, got {probability}"
                )
            values[action] = float(probability)
        if abs(math.fsum(values.values()) - 1.0) > DIST_SUM_TOLERANCE:
            raise ValueError(f"{label} infoset {infoset!r} probabilities are not normalized")
        copied[infoset] = values
    return copied


def _combine_profile(
    game: Game,
    hero_player: int,
    hero_policy: StrategyProfile,
    opponent_policy: StrategyProfile,
) -> StrategyProfile:
    return {
        infoset: _copy_dist(
            hero_policy[infoset]
            if game.player_of(infoset) == hero_player
            else opponent_policy[infoset]
        )
        for infoset in game.infosets
    }


def _copy_dist(dist: Mapping[str, float]) -> ActionDist:
    return {action: probability for action, probability in dist.items()}


def _evaluate_profile(
    game: Game, profile: StrategyProfile, hero_player: int, label: str
) -> ExactEvPaths:
    production = _hero_value(expected_value(game, profile), hero_player)
    independent = _hero_value(expected_value_by_leaves(game, profile), hero_player)
    if not math.isfinite(production) or not math.isfinite(independent):
        raise ValueError(f"{label} EV evaluation produced a non-finite value")
    if not math.isclose(
        production,
        independent,
        rel_tol=0.0,
        abs_tol=EV_CONSISTENCY_ABS_TOLERANCE,
    ):
        raise ValueError(
            f"{label} EV paths disagree: production={production}, "
            f"independent_leaves={independent}, "
            f"tolerance={EV_CONSISTENCY_ABS_TOLERANCE}"
        )
    return ExactEvPaths(production=production, independent_leaves=independent)


def _hero_value(player_zero_value: float, hero_player: int) -> float:
    return player_zero_value if hero_player == 0 else -player_zero_value
