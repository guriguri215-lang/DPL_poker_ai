"""Base-policy provider boundary used by :class:`poker_ai.decision.HeroAgent`.

The normal session supplies a CFR-backed provider.  The hand-authored task-3
baseline remains available only through :class:`StubBasePolicyProvider` for
compatibility fixtures.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from poker_core.card import Card
from poker_core.combo import Combo
from poker_core.range_model import Range
from poker_core.run_manifest import ConfigRef
from poker_core.strategy_table import StrategyEntry, StrategyTable

from .baseline_strategy import (
    BASELINE_PATH,
    FACING_ALL_IN,
    BaselineStrategy,
    build_situation_key,
    get_baseline_strategy,
)
from .hand_bucket import BucketDefinition, classify_combo, get_bucket_definition


class BasePolicyObservation(Protocol):
    """Public observation fields a base-policy provider may consume."""

    hand_id: str
    board: tuple[Card, ...]
    position: str
    pot: float
    facing_bet: float
    effective_stack: float
    hero_combo: Combo
    hero_range: Range
    opponent_assumed_range: Range


@dataclass(frozen=True, slots=True)
class BasePolicySelection:
    """Validated StrategyTable plus the config identity that produced it."""

    strategy_table: StrategyTable
    config_sha256: str

    def __post_init__(self) -> None:
        if len(self.config_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in self.config_sha256
        ):
            raise ValueError("config_sha256 must be a lowercase SHA-256 digest")


class BasePolicyProvider(Protocol):
    """Provider contract for a combo-granular Hero base strategy."""

    @property
    def strategy_version(self) -> str: ...

    @property
    def source(self) -> str: ...

    def config_ref(self) -> ConfigRef: ...

    def policy_for(
        self,
        observation: BasePolicyObservation,
        *,
        state_cluster: str,
    ) -> BasePolicySelection: ...


class StubBasePolicyProvider:
    """Compatibility-only adapter for the packaged ``0.0.1-stub`` strategy."""

    source = "task3_stub_baseline"

    def __init__(
        self,
        baseline: BaselineStrategy | None = None,
        bucket_def: BucketDefinition | None = None,
    ) -> None:
        self.baseline = baseline or get_baseline_strategy()
        self.bucket_def = bucket_def or get_bucket_definition()
        self._uses_packaged_baseline = baseline is None or baseline is get_baseline_strategy()

    @property
    def strategy_version(self) -> str:
        return self.baseline.baseline_table_version

    def config_ref(self) -> ConfigRef:
        if self._uses_packaged_baseline:
            encoded = BASELINE_PATH.read_bytes()
            path = BASELINE_PATH.name
        else:
            encoded = json.dumps(
                self.baseline.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            path = f"inline:{self.strategy_version}"
        return ConfigRef(
            name="baseline_strategy",
            role="strategy_table",
            path=path,
            sha256=hashlib.sha256(encoded).hexdigest(),
        )

    def policy_for(
        self,
        observation: BasePolicyObservation,
        *,
        state_cluster: str,
    ) -> BasePolicySelection:
        combo = observation.hero_combo.canonical()
        hand_bucket = classify_combo(
            observation.hero_combo,
            observation.hero_range,
            observation.board,
            bucket_def=self.bucket_def,
        )
        table = StrategyTable(
            table_version=self.strategy_version,
            situation_key=build_situation_key(
                state_cluster,
                observation.position,
                FACING_ALL_IN,
            ),
            cluster_def_version=_cluster_def_version(),
            source=self.source,
            entries=(
                StrategyEntry(
                    combo=combo,
                    policy=self.baseline.policy_for(FACING_ALL_IN, hand_bucket),
                    reach_prob=1.0,
                ),
            ),
        )
        return BasePolicySelection(table, self.config_ref().sha256)


def _cluster_def_version() -> str:
    # Local import keeps this small compatibility provider free of import cycles.
    from poker_core.state_cluster import cluster_def_version

    return cluster_def_version()
