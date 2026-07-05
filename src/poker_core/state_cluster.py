"""State-cluster classifier: the single board-texture key (REV-20260702 H-9).

``state_cluster`` labels a board's texture and is used as a shared key by
base-strategy lookup, leak detection and node-lock matching. Because a drift
between those consumers would silently corrupt every strategy match, there is
exactly one classifier -- this module -- driven by a declarative, versioned rule
set (:mod:`state_cluster.yaml`). The classifier computes a fixed vocabulary of
board features and returns the first cluster whose ``when`` constraints hold; the
rule set ends with an empty-``when`` fallback so every board maps to exactly one
cluster.

The MVP taxonomy is frozen at ``cluster_def_version == "0.1.0"`` by ADR-0016.
Future, more granular board-texture taxonomies require a new ADR and a version
bump so persisted tables remain auditable.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from .card import Card

#: Location of the packaged cluster definition.
CLUSTER_DEF_PATH: Path = Path(__file__).with_name("state_cluster.yaml")


@dataclass(frozen=True, slots=True)
class BoardFeatures:
    """The fixed vocabulary of board features the rules are written against."""

    max_suit_count: int
    #: Most distinct board ranks inside any 5-rank window (wheel-aware): 4+ means
    #: a made/one-card straight, 3 means "three to a straight" (connected).
    max_window_ranks: int
    is_paired: bool
    top_rank: int


def board_features(board: tuple[Card, ...] | list[Card]) -> BoardFeatures:
    """Compute :class:`BoardFeatures` for a board (3+ cards; 5 on the river)."""
    board = tuple(board)
    if len(board) < 3:
        raise ValueError(f"board needs at least 3 cards, got {len(board)}")
    values = [card.value for card in board]
    suit_counts = Counter(card.suit for card in board)
    rank_counts = Counter(values)

    distinct = set(values)
    if 14 in distinct:  # ace also plays low for the wheel
        distinct = distinct | {1}
    max_window_ranks = max(
        sum(1 for rank in distinct if start <= rank <= start + 4)
        for start in range(1, 11)  # windows [1..5] through [10..14]
    )

    return BoardFeatures(
        max_suit_count=max(suit_counts.values()),
        max_window_ranks=max_window_ranks,
        is_paired=any(count >= 2 for count in rank_counts.values()),
        top_rank=max(values),
    )


# Constraint key -> predicate over (features, threshold). Unknown keys are
# rejected at load time so a typo in the YAML fails loudly.
_CONSTRAINTS: dict[str, Callable[[BoardFeatures, object], bool]] = {
    "min_suit_count": lambda f, v: f.max_suit_count >= v,
    "min_window_ranks": lambda f, v: f.max_window_ranks >= v,
    "min_top_rank": lambda f, v: f.top_rank >= v,
    "max_top_rank": lambda f, v: f.top_rank <= v,
    "is_paired": lambda f, v: f.is_paired == v,
}


class ClusterRule(BaseModel):
    """One named cluster and the constraints a board must satisfy to match it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    when: dict[str, int | bool]

    @model_validator(mode="after")
    def _validate_keys(self) -> ClusterRule:
        for key in self.when:
            if key not in _CONSTRAINTS:
                raise ValueError(
                    f"cluster {self.name!r} uses unknown constraint {key!r}; "
                    f"allowed: {sorted(_CONSTRAINTS)}"
                )
        return self

    def matches(self, features: BoardFeatures) -> bool:
        return all(_CONSTRAINTS[key](features, value) for key, value in self.when.items())


class ClusterDefinition(BaseModel):
    """An ordered, versioned set of board-texture rules (first match wins)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cluster_def_version: str
    description: str
    clusters: tuple[ClusterRule, ...]

    @model_validator(mode="after")
    def _validate_definition(self) -> ClusterDefinition:
        if not self.clusters:
            raise ValueError("cluster definition needs at least one cluster")
        names = [rule.name for rule in self.clusters]
        if len(names) != len(set(names)):
            raise ValueError("duplicate cluster name in definition")
        # Exactly one fallback, and it must be last so coverage does not shadow
        # any later rule.
        empty = [i for i, rule in enumerate(self.clusters) if not rule.when]
        if empty != [len(self.clusters) - 1]:
            raise ValueError(
                "cluster definition must end with exactly one empty-`when` "
                "fallback rule to guarantee total coverage"
            )
        return self

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(rule.name for rule in self.clusters)

    def classify(self, board: tuple[Card, ...] | list[Card]) -> str:
        """Return the single cluster name for ``board`` (first matching rule)."""
        features = board_features(board)
        for rule in self.clusters:
            if rule.matches(features):
                return rule.name
        # Unreachable: the validated definition always ends with a fallback.
        raise RuntimeError("no cluster matched and no fallback rule present")


def load_cluster_definition(path: Path | str | None = None) -> ClusterDefinition:
    """Load and validate the cluster definition (defaults to the packaged file)."""
    target = Path(path) if path is not None else CLUSTER_DEF_PATH
    with target.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return ClusterDefinition.model_validate(raw)


@lru_cache(maxsize=1)
def get_cluster_definition() -> ClusterDefinition:
    """Return the process-wide cached cluster definition from the packaged file."""
    return load_cluster_definition()


def classify_board(board: tuple[Card, ...] | list[Card]) -> str:
    """Classify a board with the packaged cluster definition."""
    return get_cluster_definition().classify(board)


def cluster_def_version() -> str:
    """The packaged cluster definition's version."""
    return get_cluster_definition().cluster_def_version
