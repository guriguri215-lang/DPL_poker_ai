"""Independent reach-weighted ground truth for synthetic opponent leaks."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext

from poker_solver.game import Chance, Game, Node, Terminal
from poker_solver.strategy import StrategyProfile, validate_profile

from .model import OpponentModelConfig


@dataclass(frozen=True, slots=True)
class TrueLeakMeasurement:
    """An independently measured baseline-relative action-rate leak."""

    reason_id: str
    action: str
    phase: str
    baseline_rate: Decimal
    opponent_rate: Decimal
    true_leak: Decimal


_GROUND_TRUTH_TARGETS: dict[str, tuple[str, str]] = {
    "LEAK_R001": ("vs_bet", "FOLD"),
    "LEAK_R002": ("vs_bet", "CALL"),
    "LEAK_R007": ("vs_check", "CHECK"),
    "LEAK_R008": ("vs_check", "BET"),
}


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
        phase, action = _GROUND_TRUTH_TARGETS[reason_id]
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
        return numerator / denominator
