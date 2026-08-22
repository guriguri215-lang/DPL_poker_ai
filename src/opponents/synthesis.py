"""Deterministic node-lock opponent synthesis for P6-3."""

from __future__ import annotations

import math
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from poker_solver.game import Game
from poker_solver.nodelock import (
    NodeLockApplication,
    NodeLockConfig,
    NodeLockRule,
    apply_node_locks,
    river_infoset_reach_weights,
)
from poker_solver.strategy import StrategyProfile

from .equilibrium import DEFAULT_EQUILIBRIUM_ROOT, load_frozen_equilibrium
from .model import LEAK_ACTION_MAPPINGS, OpponentModelConfig, leak_action_mapping

# Phase 6's existing cross-component extractor introspects this private name.
# Keep it as the same canonical object, not a separately authored semantics table.
_LEAK_MAPPINGS = LEAK_ACTION_MAPPINGS


@dataclass(frozen=True, slots=True)
class LeakTarget:
    """One requested baseline-relative node-lock target."""

    reason_id: str
    action: str
    phase: str
    baseline_frequency: float
    requested_delta: str
    target_frequency: float


@dataclass(frozen=True, slots=True)
class SynthesizedOpponent:
    """Generated profile and complete deterministic provenance."""

    config: OpponentModelConfig
    config_sha256: str
    equilibrium_version: str
    equilibrium_artifact_sha256: str
    bet_fraction: float
    game: Game
    equilibrium_strategy: StrategyProfile
    node_lock_config: NodeLockConfig
    strategy: StrategyProfile
    leak_targets: tuple[LeakTarget, ...]
    application: NodeLockApplication


def synthesize_opponent(
    *,
    config: OpponentModelConfig,
    equilibrium_root: Path | str = DEFAULT_EQUILIBRIUM_ROOT,
) -> SynthesizedOpponent:
    """Apply a canonical leak vector to a frozen equilibrium profile.

    The seed is deliberately part of the model identity even though the current
    HARD baseline-scaled projection has no random operation. This preserves exact
    provenance if a later, separately versioned generator adds seeded allocation.
    """
    equilibrium = load_frozen_equilibrium(
        config.equilibrium_version,
        expected_sha256=config.equilibrium_artifact_sha256,
        equilibrium_root=equilibrium_root,
    )
    game = equilibrium.game
    equilibrium_profile = equilibrium.strategy

    reach_weights = river_infoset_reach_weights(game, equilibrium_profile)
    rules: list[NodeLockRule] = []
    targets: list[LeakTarget] = []
    for reason_id, requested_delta in config.leak_vector:
        mapping = leak_action_mapping(reason_id)
        infosets = _target_infosets(
            game,
            actor=config.opponent_position,
            phase=mapping.phase,
            action=mapping.action,
        )
        baseline_frequency = _weighted_rate(
            equilibrium_profile,
            infosets,
            mapping.action,
            reach_weights,
        )
        target_frequency = baseline_frequency + float(Decimal(requested_delta))
        if not 0.0 <= target_frequency <= 1.0:
            raise ValueError(
                f"requested {reason_id} delta {requested_delta} exceeds available probability mass"
            )
        rules.append(
            NodeLockRule(
                actor=config.opponent_position,
                phase=mapping.phase,
                action=mapping.action,
                target_frequency=target_frequency,
                combo_allocation=config.combo_allocation,
                rule_id=f"{reason_id}_synthetic_opponent",
            )
        )
        targets.append(
            LeakTarget(
                reason_id=reason_id,
                action=mapping.action,
                phase=mapping.phase,
                baseline_frequency=baseline_frequency,
                requested_delta=requested_delta,
                target_frequency=target_frequency,
            )
        )

    node_lock_config = NodeLockConfig(
        rules=tuple(rules),
        lock_mode=config.lock_mode,
        unlocked_policy_mode=config.unlocked_policy_mode,
    )
    application = apply_node_locks(
        game,
        equilibrium_profile,
        node_lock_config,
        reach_weights=reach_weights,
    )
    return SynthesizedOpponent(
        config=config,
        config_sha256=config.config_sha256,
        equilibrium_version=equilibrium.equilibrium_version,
        equilibrium_artifact_sha256=equilibrium.artifact_sha256,
        bet_fraction=equilibrium.bet_fraction,
        game=game,
        equilibrium_strategy={
            infoset: dict(distribution) for infoset, distribution in equilibrium_profile.items()
        },
        node_lock_config=node_lock_config,
        strategy=application.profile,
        leak_targets=tuple(targets),
        application=application,
    )


def _target_infosets(
    game: Game,
    *,
    actor: str,
    phase: str,
    action: str,
) -> tuple[str, ...]:
    prefix = f"{actor}:"
    suffix = f":{phase}"
    infosets = tuple(
        infoset
        for infoset in game.infosets
        if infoset.startswith(prefix)
        and infoset.endswith(suffix)
        and action in game.actions_of(infoset)
    )
    if not infosets:
        raise ValueError(f"game has no {actor} {phase} infosets supporting action {action}")
    return infosets


def _weighted_rate(
    profile: StrategyProfile,
    infosets: tuple[str, ...],
    action: str,
    reach_weights: dict[str, float],
) -> float:
    denominator = math.fsum(reach_weights[infoset] for infoset in infosets)
    if denominator <= 0.0:
        raise ValueError("synthetic leak target has zero opportunity reach")
    numerator = math.fsum(reach_weights[infoset] * profile[infoset][action] for infoset in infosets)
    return numerator / denominator
