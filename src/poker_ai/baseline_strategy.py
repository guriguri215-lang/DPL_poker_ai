"""Compatibility stub strategy: situation + hand_bucket -> policy.

The base strategy is looked up by *situation* (state_cluster + position + facing
state) and then subdivided by ``hand_bucket`` (ADR-0005). The policies are a
hand-authored **placeholder** (:mod:`baseline_strategy.yaml`, whose version ends
with ``-stub``), retained for compatibility fixtures rather than normal Hero play.

The per-combo :class:`~poker_core.strategy_table.StrategyTable` is the canonical
representation of a solved strategy (ADR-0005); :func:`build_strategy_table` builds
one for a situation by assigning every board-legal combo in Hero's range the policy
of its bucket, so the vertical slice exercises and validates that frozen contract.
:meth:`BaselineStrategy.policy_for` is the direct bucket lookup used per decision.
"""

from __future__ import annotations

import math
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from poker_core.card import Card
from poker_core.dpl_schema import HandBucket, Policy
from poker_core.range_model import Range
from poker_core.strategy_table import StrategyEntry, StrategyTable

from .actions import FACING_ALL_IN_ACTIONS
from .hand_bucket import BUCKET_NAMES_WEAK_TO_STRONG, BucketDefinition, classify_combo

#: Location of the packaged stub base strategy.
BASELINE_PATH: Path = Path(__file__).with_name("baseline_strategy.yaml")

#: Facing-state token task 3 uses in the situation key (Hero faces an all-in bet).
FACING_ALL_IN = "facing_all_in"


def build_situation_key(state_cluster: str, position: str, facing_state: str) -> str:
    """Compose the strategy ``situation_key`` (state_cluster + position + facing)."""
    return f"{state_cluster}:{position}:{facing_state}"


class BaselineStrategy(BaseModel):
    """A versioned, hand-authored base strategy keyed by facing state then bucket."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    baseline_table_version: str
    description: str
    #: facing_state -> hand_bucket -> policy (validated distribution over actions).
    profiles: dict[str, dict[str, Policy]]

    @model_validator(mode="after")
    def _validate_profiles(self) -> BaselineStrategy:
        if FACING_ALL_IN not in self.profiles:
            raise ValueError(f"baseline strategy must define the {FACING_ALL_IN!r} profile")
        for facing_state, by_bucket in self.profiles.items():
            missing = set(BUCKET_NAMES_WEAK_TO_STRONG) - set(by_bucket)
            if missing:
                raise ValueError(
                    f"profile {facing_state!r} is missing hand_bucket(s): {sorted(missing)}"
                )
            for bucket, policy in by_bucket.items():
                illegal = set(policy) - set(FACING_ALL_IN_ACTIONS)
                if illegal:
                    raise ValueError(
                        f"profile {facing_state!r}/{bucket!r} cites non-facing-all-in "
                        f"action(s): {sorted(illegal)}"
                    )
        return self

    def policy_for(self, facing_state: str, hand_bucket: HandBucket) -> dict[str, float]:
        """Return the base policy for a facing state and hand bucket (a copy)."""
        try:
            return dict(self.profiles[facing_state][hand_bucket])
        except KeyError as exc:
            raise KeyError(
                f"no base policy for facing_state={facing_state!r}, hand_bucket={hand_bucket!r}"
            ) from exc


def load_baseline_strategy(path: Path | str | None = None) -> BaselineStrategy:
    """Load and validate the stub base strategy (defaults to the packaged file)."""
    target = Path(path) if path is not None else BASELINE_PATH
    with target.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return BaselineStrategy.model_validate(raw)


@lru_cache(maxsize=1)
def get_baseline_strategy() -> BaselineStrategy:
    """Return the process-wide cached stub base strategy from the packaged file."""
    return load_baseline_strategy()


def baseline_table_version() -> str:
    """The packaged compatibility-stub strategy version."""
    return get_baseline_strategy().baseline_table_version


def build_strategy_table(
    *,
    situation_key: str,
    cluster_def_version: str,
    facing_state: str,
    hero_range: Range,
    board: tuple[Card, ...] | list[Card],
    bucket_def: BucketDefinition,
    baseline: BaselineStrategy | None = None,
) -> StrategyTable:
    """Build the per-combo canonical StrategyTable for a situation (ADR-0005).

    Every board-legal, positive-weight combo in ``hero_range`` becomes an entry
    whose policy is the base policy of its ``hand_bucket`` and whose ``reach_prob``
    is its normalised range reach. This is the canonical per-combo form; its
    :meth:`~poker_core.strategy_table.StrategyTable.aggregate_policy` reproduces the
    reach-weighted view (M-3).
    """
    baseline = baseline if baseline is not None else get_baseline_strategy()
    board = tuple(board)
    board_mask = 0
    for card in board:
        board_mask |= card.mask

    legal = [
        (combo, weight)
        for combo, weight in hero_range
        if weight > 0 and not (combo.mask & board_mask)
    ]
    total_reach = math.fsum(weight for _combo, weight in legal)
    if total_reach <= 0:
        raise ValueError("hero_range has no board-legal, positive-weight combos")

    entries: list[StrategyEntry] = []
    for combo, weight in legal:
        bucket = classify_combo(combo, hero_range, board, bucket_def=bucket_def)
        policy = baseline.policy_for(facing_state, bucket)
        entries.append(
            StrategyEntry(
                combo=combo.canonical(),
                policy=policy,
                reach_prob=weight / total_reach,
            )
        )
    return StrategyTable(
        table_version=baseline.baseline_table_version,
        situation_key=situation_key,
        cluster_def_version=cluster_def_version,
        source="task3_stub_baseline",
        entries=tuple(entries),
    )
