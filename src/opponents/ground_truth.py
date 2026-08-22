"""Independent reach-weighted ground truth for synthetic opponent leaks."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext

from poker_solver.game import Chance, Game, Node, Terminal
from poker_solver.strategy import StrategyProfile, validate_profile

from .model import LEAK_ACTION_MAPPINGS, OpponentModelConfig, leak_action_mapping

# Phase 6's existing cross-component extractor introspects this private name.
# Keep it as the same canonical object, not a separately authored semantics table.
_GROUND_TRUTH_TARGETS = LEAK_ACTION_MAPPINGS


@dataclass(frozen=True, slots=True)
class TrueLeakMeasurement:
    """An independently measured baseline-relative action-rate leak."""

    reason_id: str
    action: str
    phase: str
    baseline_rate: Decimal
    opponent_rate: Decimal
    true_leak: Decimal


@dataclass(frozen=True, slots=True)
class IndependentActionRate:
    """One independently measured action rate and its opportunity reach."""

    reason_id: str
    action: str
    phase: str
    action_rate: Decimal
    opportunity_reach: Decimal


def extract_true_leaks(
    game: Game,
    baseline_profile: StrategyProfile,
    opponent_profile: StrategyProfile,
    config: OpponentModelConfig,
) -> tuple[TrueLeakMeasurement, ...]:
    """Measure true leak deltas without using node-lock application metadata.

    Reach is traversed from the game root independently for each profile. All
    arithmetic converts stored probability tokens through ``str`` and uses the
    ADR-0019 decimal precision and rounding convention.
    """
    validate_profile(game, baseline_profile)
    validate_profile(game, opponent_profile)
    baseline_reach = _decimal_infoset_reach(game.root, baseline_profile)
    opponent_reach = _decimal_infoset_reach(game.root, opponent_profile)

    measurements: list[TrueLeakMeasurement] = []
    for reason_id, _requested_delta in config.leak_vector:
        mapping = leak_action_mapping(reason_id)
        phase, action = mapping.phase, mapping.action
        baseline_rate = _aggregate_rate(
            game,
            baseline_profile,
            baseline_reach,
            actor=config.opponent_position,
            phase=phase,
            action=action,
        )
        opponent_rate = _aggregate_rate(
            game,
            opponent_profile,
            opponent_reach,
            actor=config.opponent_position,
            phase=phase,
            action=action,
        )
        with localcontext() as context:
            context.prec = 50
            context.rounding = ROUND_HALF_EVEN
            true_leak = opponent_rate - baseline_rate
        measurements.append(
            TrueLeakMeasurement(
                reason_id=reason_id,
                action=action,
                phase=phase,
                baseline_rate=baseline_rate,
                opponent_rate=opponent_rate,
                true_leak=true_leak,
            )
        )
    return tuple(measurements)


def extract_independent_action_rates(
    game: Game,
    profile: StrategyProfile,
    config: OpponentModelConfig,
    *,
    reason_ids: tuple[str, ...],
) -> tuple[IndependentActionRate, ...]:
    """Measure requested action rates without detector or synthesis metadata."""
    validate_profile(game, profile)
    if not reason_ids or len(set(reason_ids)) != len(reason_ids):
        raise ValueError("reason_ids must be non-empty and unique")
    unknown = set(reason_ids) - set(LEAK_ACTION_MAPPINGS)
    if unknown:
        raise ValueError(f"unsupported ground-truth reasons {sorted(unknown)}")
    reaches = _decimal_infoset_reach(game.root, profile)
    measurements: list[IndependentActionRate] = []
    for reason_id in reason_ids:
        mapping = leak_action_mapping(reason_id)
        phase, action = mapping.phase, mapping.action
        action_rate, opportunity_reach = _aggregate_rate_and_reach(
            game,
            profile,
            reaches,
            actor=config.opponent_position,
            phase=phase,
            action=action,
        )
        measurements.append(
            IndependentActionRate(
                reason_id,
                action,
                phase,
                action_rate,
                opportunity_reach,
            )
        )
    return tuple(measurements)


def _decimal_infoset_reach(node: Node, profile: StrategyProfile) -> dict[str, Decimal]:
    reaches: dict[str, Decimal] = {}
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        _walk_reach(node, profile, reaches, reach=Decimal(1))
    return reaches


def _walk_reach(
    node: Node,
    profile: StrategyProfile,
    reaches: dict[str, Decimal],
    *,
    reach: Decimal,
) -> None:
    if isinstance(node, Terminal):
        return
    if isinstance(node, Chance):
        for probability, child, _label in node.branches:
            _walk_reach(child, profile, reaches, reach=reach * Decimal(str(probability)))
        return
    reaches[node.infoset] = reaches.get(node.infoset, Decimal(0)) + reach
    for action, child in zip(node.actions, node.children, strict=True):
        probability = Decimal(str(profile[node.infoset][action]))
        _walk_reach(child, profile, reaches, reach=reach * probability)


def _aggregate_rate(
    game: Game,
    profile: StrategyProfile,
    reaches: dict[str, Decimal],
    *,
    actor: str,
    phase: str,
    action: str,
) -> Decimal:
    rate, _reach = _aggregate_rate_and_reach(
        game,
        profile,
        reaches,
        actor=actor,
        phase=phase,
        action=action,
    )
    return rate


def _aggregate_rate_and_reach(
    game: Game,
    profile: StrategyProfile,
    reaches: dict[str, Decimal],
    *,
    actor: str,
    phase: str,
    action: str,
) -> tuple[Decimal, Decimal]:
    prefix = f"{actor}:"
    suffix = f":{phase}"
    infosets = tuple(
        sorted(
            infoset
            for infoset in game.infosets
            if infoset.startswith(prefix)
            and infoset.endswith(suffix)
            and action in game.actions_of(infoset)
        )
    )
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        denominator = sum((reaches.get(infoset, Decimal(0)) for infoset in infosets), Decimal(0))
        if denominator <= 0:
            raise ValueError("ground-truth target has zero opportunity reach")
        numerator = sum(
            (
                reaches.get(infoset, Decimal(0)) * Decimal(str(profile[infoset][action]))
                for infoset in infosets
            ),
            Decimal(0),
        )
        return numerator / denominator, denominator
