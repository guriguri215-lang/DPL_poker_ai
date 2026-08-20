"""Deterministic CFR river policy adapter for normal Hero decisions."""

from __future__ import annotations

import hashlib
import json
import math
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from poker_core.run_manifest import ConfigRef
from poker_core.strategy_table import StrategyEntry, StrategyTable

from .base_policy import BasePolicyObservation, BasePolicySelection
from .scenario import Scenario

if TYPE_CHECKING:
    from poker_solver.strategy import StrategyProfile

CFR_RIVER_POLICY_CONFIG_VERSION = "cfr-river-policy-config-v1"
CFR_RIVER_POLICY_SOURCE = "poker_solver.solve_frozen_river_scenario"
R007_NO_FACING_POLICY_CONFIG_VERSION = "cfr-river-r007-no-facing-config-v1"
R007_NO_FACING_BET_ACTION = "BET_33"
R007_NO_FACING_BET_FRACTION = 0.33


class CfrRiverPolicyConfig(BaseModel):
    """All fixed, auditable inputs that affect the normal CFR solve."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    config_version: Literal["cfr-river-policy-config-v1"] = CFR_RIVER_POLICY_CONFIG_VERSION
    solver: Literal["cfr_plus"] = "cfr_plus"
    phase: Literal["vs_bet"] = "vs_bet"
    bet_size_rule: Literal["observed_facing_bet"] = "observed_facing_bet"
    iterations: int = Field(gt=0)
    average_delay: int = Field(ge=0)
    checkpoints: tuple[int, ...] = ()

    @model_validator(mode="after")
    def _validate_averaging_and_checkpoints(self) -> CfrRiverPolicyConfig:
        if self.average_delay >= self.iterations:
            raise ValueError("average_delay must be smaller than iterations")
        normalized = tuple(sorted(set(self.checkpoints)))
        if normalized != self.checkpoints:
            raise ValueError("checkpoints must be sorted and unique")
        if any(checkpoint <= 0 or checkpoint > self.iterations for checkpoint in self.checkpoints):
            raise ValueError("checkpoints must be in [1, iterations]")
        return self

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


DEFAULT_CFR_RIVER_POLICY_CONFIG = CfrRiverPolicyConfig(
    iterations=40,
    average_delay=0,
    checkpoints=(),
)


class CfrRiverNoFacingPolicyConfig(BaseModel):
    """Auditable inputs for the opt-in R007 OOP ``start`` policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    config_version: Literal["cfr-river-r007-no-facing-config-v1"] = (
        R007_NO_FACING_POLICY_CONFIG_VERSION
    )
    solver: Literal["cfr_plus"] = "cfr_plus"
    phase: Literal["start"] = "start"
    public_bet_action: Literal["BET_33"] = R007_NO_FACING_BET_ACTION
    bet_fraction: float = Field(default=R007_NO_FACING_BET_FRACTION, gt=0.0)
    iterations: int = Field(gt=0)
    average_delay: int = Field(ge=0)
    checkpoints: tuple[int, ...] = ()

    @model_validator(mode="after")
    def _validate_fixed_slice(self) -> CfrRiverNoFacingPolicyConfig:
        if not math.isclose(
            self.bet_fraction,
            R007_NO_FACING_BET_FRACTION,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("R007 no-facing policy requires the fixed 0.33-pot bet")
        if self.average_delay >= self.iterations:
            raise ValueError("average_delay must be smaller than iterations")
        normalized = tuple(sorted(set(self.checkpoints)))
        if normalized != self.checkpoints:
            raise ValueError("checkpoints must be sorted and unique")
        if any(checkpoint <= 0 or checkpoint > self.iterations for checkpoint in self.checkpoints):
            raise ValueError("checkpoints must be in [1, iterations]")
        return self

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class CfrRiverPolicyProvider:
    """Expose Hero's finite-iteration combo- and position-specific ``vs_bet`` policy."""

    source = CFR_RIVER_POLICY_SOURCE

    def __init__(self, config: CfrRiverPolicyConfig) -> None:
        self.config = config

    @property
    def strategy_version(self) -> str:
        return (
            f"cfr-river-policy-v1-i{self.config.iterations}-"
            f"d{self.config.average_delay}-cfg{self.config.sha256[:12]}"
        )

    def config_ref(self) -> ConfigRef:
        checkpoints = ",".join(str(value) for value in self.config.checkpoints) or "none"
        return ConfigRef(
            name="cfr_river_policy",
            role="solver",
            path=(
                f"inline:{self.config.config_version}:solver={self.config.solver}:"
                f"phase={self.config.phase}:iterations={self.config.iterations}:"
                f"average_delay={self.config.average_delay}:"
                f"checkpoints={checkpoints}:"
                f"bet_size={self.config.bet_size_rule}"
            ),
            sha256=self.config.sha256,
        )

    def policy_for(
        self,
        observation: BasePolicyObservation,
        *,
        state_cluster: str,
    ) -> BasePolicySelection:
        if observation.pot <= 0.0:
            raise ValueError("CFR river policy requires a positive pot")
        if observation.facing_bet <= 0.0:
            raise ValueError("CFR river policy requires a positive facing bet")
        if not math.isclose(
            observation.facing_bet,
            observation.effective_stack,
            rel_tol=0.0,
            abs_tol=1e-9,
        ):
            raise ValueError(
                "CFR river policy only supports facing an all-in bet equal to effective_stack"
            )

        scenario = Scenario(
            scenario_id=observation.hand_id,
            board=tuple(str(card) for card in observation.board),
            position=observation.position,
            pot=observation.pot,
            effective_stack=observation.effective_stack,
            hero_combo=observation.hero_combo.canonical(),
            hero_range=observation.hero_range.weights,
            opponent_range=observation.opponent_assumed_range.weights,
        )
        result = _solve_frozen_river_scenario(
            scenario,
            bet_fraction=observation.facing_bet / observation.pot,
            iterations=self.config.iterations,
            checkpoints=self.config.checkpoints,
            average_delay=self.config.average_delay,
        )
        if result.state_cluster != state_cluster:
            raise ValueError("solver result state cluster does not match Hero observation")
        table = _build_baseline_strategy_table(
            result,
            phase=self.config.phase,
            table_version=self.strategy_version,
            source=self.source,
        )
        expected_situation = f"{state_cluster}:{observation.position}:river_{self.config.phase}"
        if table.situation_key != expected_situation:
            raise ValueError("solver StrategyTable is not Hero's exact position/phase")
        return BasePolicySelection(table, self.config.sha256)


class CfrRiverNoFacingPolicyProvider:
    """Expose Hero OOP's bounded ``start`` policy for the R007 fixture."""

    source = CFR_RIVER_POLICY_SOURCE

    def __init__(self, config: CfrRiverNoFacingPolicyConfig) -> None:
        self.config = config

    @property
    def strategy_version(self) -> str:
        return (
            f"cfr-river-r007-no-facing-v1-i{self.config.iterations}-"
            f"d{self.config.average_delay}-cfg{self.config.sha256[:12]}"
        )

    def config_ref(self) -> ConfigRef:
        checkpoints = ",".join(str(value) for value in self.config.checkpoints) or "none"
        return ConfigRef(
            name="cfr_river_policy",
            role="solver",
            path=(
                f"inline:{self.config.config_version}:solver={self.config.solver}:"
                f"phase={self.config.phase}:iterations={self.config.iterations}:"
                f"average_delay={self.config.average_delay}:"
                f"checkpoints={checkpoints}:public_bet={self.config.public_bet_action}:"
                f"bet_fraction={self.config.bet_fraction:g}"
            ),
            sha256=self.config.sha256,
        )

    def policy_for(
        self,
        observation: BasePolicyObservation,
        *,
        state_cluster: str,
    ) -> BasePolicySelection:
        if observation.position != "OOP":
            raise ValueError("R007 no-facing policy requires Hero to be OOP")
        if not math.isclose(observation.facing_bet, 0.0, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("R007 no-facing policy requires no bet facing Hero")
        if observation.pot <= 0.0:
            raise ValueError("R007 no-facing policy requires a positive pot")
        bet_size = observation.pot * self.config.bet_fraction
        if bet_size > observation.effective_stack and not math.isclose(
            bet_size,
            observation.effective_stack,
            rel_tol=0.0,
            abs_tol=1e-9,
        ):
            raise ValueError("R007 BET_33 size exceeds the effective stack")

        scenario = Scenario(
            scenario_id=observation.hand_id,
            board=tuple(str(card) for card in observation.board),
            position=observation.position,
            pot=observation.pot,
            effective_stack=observation.effective_stack,
            hero_combo=observation.hero_combo.canonical(),
            hero_range=observation.hero_range.weights,
            opponent_range=observation.opponent_assumed_range.weights,
        )
        result = _solve_frozen_river_scenario(
            scenario,
            bet_fraction=self.config.bet_fraction,
            iterations=self.config.iterations,
            checkpoints=self.config.checkpoints,
            average_delay=self.config.average_delay,
        )
        if result.state_cluster != state_cluster:
            raise ValueError("solver result state cluster does not match Hero observation")
        tree_table = _build_baseline_strategy_table(
            result,
            phase=self.config.phase,
            table_version=self.strategy_version,
            source=self.source,
        )
        table = _map_start_table_to_bet_33(tree_table)
        expected_situation = f"{state_cluster}:OOP:river_start"
        if table.situation_key != expected_situation:
            raise ValueError("solver StrategyTable is not Hero's OOP start decision")
        action_ev = exact_oop_start_action_evs(
            scenario,
            result.strategy,
            bet_fraction=self.config.bet_fraction,
        )
        return BasePolicySelection(table, self.config.sha256, action_ev)


def exact_oop_start_action_evs(
    scenario: Scenario,
    profile: StrategyProfile,
    *,
    bet_fraction: float = R007_NO_FACING_BET_FRACTION,
) -> dict[str, float]:
    """Exact current-node EVs for OOP ``CHECK`` and public ``BET_33``.

    The existing river game reports player-0 net utility including the player's
    sunk half of the dead pot.  Adding ``pot / 2`` converts it to the DPL's
    incremental-EV-from-current-node convention.  All later actions follow the
    supplied fixed profile; only this exact combo's current action is forced.
    """
    from poker_solver.evaluate import expected_value
    from poker_solver.game import Chance, Decision, Game
    from poker_solver.river_tree import RiverBettingConfig, build_river_game

    if scenario.position != "OOP":
        raise ValueError("current-node no-facing EV requires an OOP Hero scenario")
    config = RiverBettingConfig(pot=scenario.pot, bet_fraction=bet_fraction)
    if config.bet > scenario.effective_stack and not math.isclose(
        config.bet,
        scenario.effective_stack,
        rel_tol=0.0,
        abs_tol=1e-9,
    ):
        raise ValueError("no-facing bet size exceeds the effective stack")
    game = build_river_game(
        config,
        scenario.hero_range_obj(),
        scenario.opponent_range_obj(),
        scenario.board_cards(),
    )
    if not isinstance(game.root, Chance):
        raise ValueError("river game root must be a chance node")

    hero_combo = scenario.hero_combo_obj().canonical()
    selected: list[tuple[float, Decision, str]] = []
    for probability, child, label in game.root.branches:
        dealt = label.split("|", maxsplit=1)
        if len(dealt) != 2:
            raise ValueError(f"river deal label must be 'OOP|IP', got {label!r}")
        if dealt[0] != hero_combo:
            continue
        if not isinstance(child, Decision) or child.infoset != f"OOP:{hero_combo}:start":
            raise ValueError("conditioned river branch is not Hero's OOP start infoset")
        selected.append((probability, child, label))
    total_probability = math.fsum(probability for probability, _child, _label in selected)
    if total_probability <= 0.0:
        raise ValueError("Hero combo has zero chance reach in the river game")

    action_map = (("CHECK", "CHECK"), ("BET", R007_NO_FACING_BET_ACTION))
    action_ev: dict[str, float] = {}
    for tree_action, public_action in action_map:
        branches = tuple(
            (
                probability / total_probability,
                child.child_of(tree_action),
                label,
            )
            for probability, child, label in selected
        )
        conditioned = Game(Chance(branches), name=f"river-oop-start-{tree_action.lower()}")
        action_ev[public_action] = (
            expected_value(conditioned, profile, validate=False) + scenario.pot / 2.0
        )
    return action_ev


def _map_start_table_to_bet_33(table: StrategyTable) -> StrategyTable:
    entries: list[StrategyEntry] = []
    for entry in table.entries:
        if set(entry.policy) != {"CHECK", "BET"}:
            raise ValueError("OOP start solver policy must contain CHECK and BET")
        entries.append(
            StrategyEntry(
                combo=entry.combo,
                policy={
                    "CHECK": entry.policy["CHECK"],
                    R007_NO_FACING_BET_ACTION: entry.policy["BET"],
                },
                reach_prob=entry.reach_prob,
            )
        )
    return StrategyTable(
        table_version=table.table_version,
        situation_key=table.situation_key,
        cluster_def_version=table.cluster_def_version,
        source=table.source,
        entries=tuple(entries),
    )


def _solve_frozen_river_scenario(*args, **kwargs):
    # Lazy import avoids a poker_solver -> poker_ai package initialization cycle.
    from poker_solver.river_solve import solve_frozen_river_scenario

    return solve_frozen_river_scenario(*args, **kwargs)


def _build_baseline_strategy_table(*args, **kwargs):
    from poker_solver.river_solve import build_baseline_strategy_table

    return build_baseline_strategy_table(*args, **kwargs)
