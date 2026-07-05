"""Action-only leak detection for the Phase-2 river MVP.

This module intentionally implements the smallest useful detector: it compares
public opponent action rates against a versioned action baseline and emits frozen
DPL ``DetectedLeak`` records. It does not use showdown information, Beta-Binomial
calibration, node-lock exploitation, or any opponent hidden strategy.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from poker_core.dpl_schema import DetectedLeak
from poker_core.reason_ontology import get_ontology

from .observation import ActionStats

# Public action groups used by the action-only MVP detector.
CHECK_ACTIONS: tuple[str, ...] = ("CHECK",)
BET_ACTIONS: tuple[str, ...] = ("BET_ALL_IN", "BET_33", "BET_75", "RAISE_ALL_IN")


@dataclass(frozen=True)
class LeakDetectorConfig:
    """Thresholds for the MVP confidence heuristic."""

    min_effective_sample_size: int = 10
    min_deviation: float = 0.25
    min_confidence: float = 0.5

    def __post_init__(self) -> None:
        if self.min_effective_sample_size <= 0:
            raise ValueError("min_effective_sample_size must be positive")
        if not 0.0 <= self.min_deviation <= 1.0:
            raise ValueError("min_deviation must be in [0, 1]")
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be in [0, 1]")


@dataclass(frozen=True)
class ActionLeakRule:
    """One action-rate leak rule tied to a LEAK_* ontology entry."""

    reason_id: str
    leak_type: str
    action_group: tuple[str, ...]
    baseline_rate: float
    direction: str
    situation_overrides: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        ontology = get_ontology()
        if not ontology.is_valid(self.reason_id, namespace="LEAK"):
            raise ValueError(f"unknown or non-LEAK reason id {self.reason_id!r}")
        expected_label = ontology.get(self.reason_id).label
        if self.leak_type != expected_label:
            raise ValueError(
                f"leak_type {self.leak_type!r} does not match ontology label "
                f"{expected_label!r} for {self.reason_id!r}"
            )
        if not self.action_group:
            raise ValueError("action_group must not be empty")
        if any(not action for action in self.action_group):
            raise ValueError("action_group must not contain empty labels")
        _validate_rate(self.baseline_rate, "baseline_rate")
        for situation_key, rate in self.situation_overrides.items():
            if not situation_key:
                raise ValueError("situation_overrides must not contain an empty key")
            _validate_rate(rate, f"situation_overrides[{situation_key!r}]")
        if not self.direction:
            raise ValueError("direction must not be empty")

    def baseline_for(self, situation_key: str) -> float:
        """Return the rule's baseline rate for a situation."""
        return self.situation_overrides.get(situation_key, self.baseline_rate)


@dataclass(frozen=True)
class ActionBaselineTable:
    """Versioned action-rate baseline used by the MVP leak detector."""

    table_version: str
    rules: tuple[ActionLeakRule, ...]

    def __post_init__(self) -> None:
        if not self.table_version:
            raise ValueError("table_version must not be empty")
        seen: set[str] = set()
        for rule in self.rules:
            if rule.reason_id in seen:
                raise ValueError(f"duplicate leak rule for {rule.reason_id!r}")
            seen.add(rule.reason_id)


def default_action_baseline_table() -> ActionBaselineTable:
    """Return the task-3-compatible stub action baseline.

    The current stub opponent jams all-in in every generated hand. Matching that
    with a ``BET`` baseline of 1.0 keeps the default CLI session leak-free while
    still exercising the detector with explicit test fixtures.
    """
    return ActionBaselineTable(
        table_version="0.0.1-stub",
        rules=(
            ActionLeakRule(
                reason_id="LEAK_R007",
                leak_type="check_back_too_often",
                action_group=CHECK_ACTIONS,
                baseline_rate=0.0,
                direction="increase_bet_frequency_when_checked_to",
            ),
            ActionLeakRule(
                reason_id="LEAK_R008",
                leak_type="bet_too_often_when_checked_to",
                action_group=BET_ACTIONS,
                baseline_rate=1.0,
                direction="decrease_bet_frequency_when_checked_to",
            ),
        ),
    )


class LeakDetector:
    """Detect public action-rate leaks from ``ObservationTracker`` snapshots."""

    def __init__(
        self,
        baseline_table: ActionBaselineTable | None = None,
        config: LeakDetectorConfig | None = None,
    ) -> None:
        self.baseline_table = baseline_table or default_action_baseline_table()
        self.config = config or LeakDetectorConfig()

    @property
    def baseline_table_version(self) -> str:
        """Version of the action baseline table used for detections."""
        return self.baseline_table.table_version

    def detect(
        self,
        stats: tuple[ActionStats, ...] | list[ActionStats],
    ) -> list[DetectedLeak]:
        """Detect leaks across all observed situation keys."""
        leaks: list[DetectedLeak] = []
        for item in stats:
            leaks.extend(self._detect_for_stats(item))
        return leaks

    def detect_for_situation(
        self,
        stats: tuple[ActionStats, ...] | list[ActionStats],
        situation_key: str,
    ) -> list[DetectedLeak]:
        """Detect leaks only for ``situation_key`` from a snapshot."""
        return [leak for leak in self.detect(stats) if leak.situation_key == situation_key]

    def _detect_for_stats(self, stats: ActionStats) -> list[DetectedLeak]:
        if stats.opportunities < self.config.min_effective_sample_size:
            return []

        leaks: list[DetectedLeak] = []
        for rule in self.baseline_table.rules:
            observed_rate = stats.rate_any(rule.action_group)
            baseline_rate = rule.baseline_for(stats.situation_key)
            deviation = observed_rate - baseline_rate
            if deviation < self.config.min_deviation:
                continue
            confidence = _mvp_confidence(
                deviation=deviation,
                opportunities=stats.opportunities,
                min_effective_sample_size=self.config.min_effective_sample_size,
            )
            if confidence < self.config.min_confidence:
                continue
            leaks.append(
                DetectedLeak(
                    reason_id=rule.reason_id,
                    leak_type=rule.leak_type,
                    situation_key=stats.situation_key,
                    observed_rate=observed_rate,
                    baseline_rate=baseline_rate,
                    effective_sample_size=stats.opportunities,
                    confidence=confidence,
                    direction=rule.direction,
                )
            )
        return leaks


def _mvp_confidence(
    *,
    deviation: float,
    opportunities: int,
    min_effective_sample_size: int,
) -> float:
    """MVP confidence heuristic from REV M-4: deviation scaled by sample coverage."""
    if opportunities <= 0:
        return 0.0
    sample_factor = min(1.0, opportunities / min_effective_sample_size)
    return min(1.0, max(0.0, deviation * 2.0 * sample_factor))


def _validate_rate(rate: float, field_name: str) -> None:
    if not math.isfinite(rate) or not 0.0 <= rate <= 1.0:
        raise ValueError(f"{field_name} must be finite and in [0, 1], got {rate}")
