"""Deterministic CFR river policy adapter for normal Hero decisions."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from poker_core.run_manifest import ConfigRef

from .base_policy import BasePolicyObservation, BasePolicySelection
from .scenario import Scenario

CFR_RIVER_POLICY_CONFIG_VERSION = "cfr-river-policy-config-v1"
CFR_RIVER_POLICY_SOURCE = "poker_solver.solve_frozen_river_scenario"


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


class CfrRiverPolicyProvider:
    """Solve the observed river spot and expose Hero's exact ``vs_bet`` combo policy."""

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


def _solve_frozen_river_scenario(*args, **kwargs):
    # Lazy import avoids a poker_solver -> poker_ai package initialization cycle.
    from poker_solver.river_solve import solve_frozen_river_scenario

    return solve_frozen_river_scenario(*args, **kwargs)


def _build_baseline_strategy_table(*args, **kwargs):
    from poker_solver.river_solve import build_baseline_strategy_table

    return build_baseline_strategy_table(*args, **kwargs)
