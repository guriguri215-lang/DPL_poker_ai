"""Action-only leak detection with Beta-Binomial posterior confidence.

This module intentionally implements the smallest useful detector: it compares
public opponent action rates against a versioned action baseline and emits frozen
DPL ``DetectedLeak`` records. Confidence is the ADR-0019 Beta(1, 1) posterior
upper-tail probability. The module does not use showdown information, node-lock
exploitation, or any opponent hidden strategy.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from typing import Literal

from poker_core.dpl_schema import DetectedLeak
from poker_core.reason_ontology import get_ontology
from poker_core.strategy_table import StrategyTable

from .observation import ActionStats

# Public action groups used by the action-only MVP detector and solver artifacts.
CHECK_ACTIONS: tuple[str, ...] = ("CHECK",)
FOLD_ACTIONS: tuple[str, ...] = ("FOLD",)
BET_ACTIONS: tuple[str, ...] = ("BET", "BET_ALL_IN", "BET_33", "BET_75", "RAISE_ALL_IN")
_POLICY_BET_ACTIONS: tuple[str, ...] = BET_ACTIONS
_CHECK_BET_POLICY_ACTIONS = frozenset((*CHECK_ACTIONS, *_POLICY_BET_ACTIONS))
BOUNDARY_ABS_TOLERANCE = "1e-12"
R001_FIXTURE_MIN_DEVIATION = 0.08
R002_FIXTURE_MIN_DEVIATION = R001_FIXTURE_MIN_DEVIATION
R003_FIXTURE_MIN_DEVIATION = R001_FIXTURE_MIN_DEVIATION
GroundTruthBoundary = Literal["positive", "negative", "indifference"]


@dataclass(frozen=True)
class LeakDetectorConfig:
    """Canonical posterior estimator and downstream confidence thresholds."""

    method_version: str = "beta-binomial-upper-tail-v1"
    alpha0: float = 1.0
    beta0: float = 1.0
    tail: str = "upper"
    min_effective_sample_size: int = 10
    min_deviation: float = 0.25
    min_confidence: float = 0.95
    rule_exploit_min_confidence: float = 0.95
    nodelock_exploit_min_confidence: float = 0.95

    def __post_init__(self) -> None:
        if self.method_version != "beta-binomial-upper-tail-v1":
            raise ValueError("unsupported confidence estimator method_version")
        if self.alpha0 != 1.0 or self.beta0 != 1.0:
            raise ValueError("ADR-0019 gate A requires a fixed Beta(1, 1) prior")
        if self.tail != "upper":
            raise ValueError("ADR-0019 gate A supports only the upper posterior tail")
        if self.min_effective_sample_size <= 0:
            raise ValueError("min_effective_sample_size must be positive")
        if not math.isfinite(self.min_deviation) or not 0.0 < self.min_deviation < 1.0:
            raise ValueError("min_deviation (tau) must be finite and in (0, 1)")
        for name in (
            "min_confidence",
            "rule_exploit_min_confidence",
            "nodelock_exploit_min_confidence",
        ):
            value = getattr(self, name)
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be finite and in [0, 1]")


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
        if len(set(self.action_group)) != len(self.action_group):
            raise ValueError("action_group must not contain duplicate actions")
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


def action_baseline_table_from_strategy_table(
    strategy_table: StrategyTable,
    *,
    table_version: str | None = None,
) -> ActionBaselineTable:
    """Build a leak-detector action baseline from a StrategyTable aggregate policy."""
    _validate_check_bet_strategy_table(strategy_table)
    aggregate = strategy_table.aggregate_policy()
    check_rate = _policy_rate(aggregate, CHECK_ACTIONS)
    bet_rate = _policy_rate(aggregate, _POLICY_BET_ACTIONS)
    return ActionBaselineTable(
        table_version=table_version or f"{strategy_table.table_version}-action-baseline",
        rules=(
            ActionLeakRule(
                reason_id="LEAK_R007",
                leak_type="check_back_too_often",
                action_group=CHECK_ACTIONS,
                baseline_rate=check_rate,
                direction="increase_bet_frequency_when_checked_to",
                situation_overrides={strategy_table.situation_key: check_rate},
            ),
            ActionLeakRule(
                reason_id="LEAK_R008",
                leak_type="bet_too_often_when_checked_to",
                action_group=BET_ACTIONS,
                baseline_rate=bet_rate,
                direction="decrease_bet_frequency_when_checked_to",
                situation_overrides={strategy_table.situation_key: bet_rate},
            ),
        ),
    )


def leaky_fixture_action_baseline_table(
    table_version: str = "fixture-action-baseline",
) -> ActionBaselineTable:
    """Return a public fixture baseline that makes the jam-all stub look leaky."""
    return ActionBaselineTable(
        table_version=table_version,
        rules=(
            ActionLeakRule(
                reason_id="LEAK_R008",
                leak_type="bet_too_often_when_checked_to",
                action_group=BET_ACTIONS,
                baseline_rate=0.0,
                direction="decrease_bet_frequency_when_checked_to",
            ),
        ),
    )


def leaky_r007_fixture_action_baseline_table(
    table_version: str = "fixture-r007-action-baseline",
) -> ActionBaselineTable:
    """Return the opt-in baseline for the check-back-too-often Hero fixture."""
    return ActionBaselineTable(
        table_version=table_version,
        rules=(
            ActionLeakRule(
                reason_id="LEAK_R007",
                leak_type="check_back_too_often",
                action_group=CHECK_ACTIONS,
                baseline_rate=0.0,
                direction="increase_bet_frequency_when_checked_to",
            ),
        ),
    )


def leaky_r001_fixture_action_baseline_table() -> ActionBaselineTable:
    """Build R001's detector baseline from the pinned equilibrium artifact."""

    return _leaky_river_large_bet_fixture_action_baseline_table("LEAK_R001")


def leaky_r002_fixture_action_baseline_table() -> ActionBaselineTable:
    """Build R002's CALL baseline from the same pinned equilibrium artifact."""

    return _leaky_river_large_bet_fixture_action_baseline_table("LEAK_R002")


def leaky_r003_fixture_action_baseline_table() -> ActionBaselineTable:
    """Build R003's FOLD baseline from its fixed finite-CFR 0.33-pot profile."""

    from .opponent import (
        R003_FIXTURE_PROFILE_VERSION,
        r003_fixture_config_identity,
        r003_fixture_measurement,
    )

    measurement = r003_fixture_measurement()
    _config_path, config_sha256 = r003_fixture_config_identity()
    return ActionBaselineTable(
        table_version=(
            f"{R003_FIXTURE_PROFILE_VERSION}-cfg{config_sha256[:12]}-r003-action-baseline"
        ),
        rules=(
            ActionLeakRule(
                reason_id="LEAK_R003",
                leak_type="river_small_bet_overfold",
                action_group=(measurement.action,),
                baseline_rate=float(measurement.baseline_rate),
                direction="increase_small_bet_frequency",
            ),
        ),
    )


def _leaky_river_large_bet_fixture_action_baseline_table(
    reason_id: str,
) -> ActionBaselineTable:
    """Share only the frozen-node baseline derivation used by R001 and R002."""

    from .opponent import (
        load_r001_fixture_synthesis,
        load_r002_fixture_synthesis,
        r001_fixture_measurement,
        r002_fixture_measurement,
    )

    if reason_id == "LEAK_R001":
        fixture = load_r001_fixture_synthesis()
        measurement = r001_fixture_measurement(fixture)
        leak_type = "river_large_bet_overfold"
        direction = "increase_large_bet_frequency"
    elif reason_id == "LEAK_R002":
        fixture = load_r002_fixture_synthesis()
        measurement = r002_fixture_measurement(fixture)
        leak_type = "river_large_bet_overcall"
        direction = "adjust_large_bet_frequency_for_overcall"
    else:
        raise ValueError(f"unsupported river-large-bet baseline reason {reason_id!r}")
    return ActionBaselineTable(
        table_version=(
            f"{fixture.equilibrium_version}-"
            f"{reason_id.lower().removeprefix('leak_')}-action-baseline"
        ),
        rules=(
            ActionLeakRule(
                reason_id=reason_id,
                leak_type=leak_type,
                action_group=(measurement.action,),
                baseline_rate=float(measurement.baseline_rate),
                direction=direction,
            ),
        ),
    )


def action_baseline_table_payload(table: ActionBaselineTable) -> dict[str, object]:
    """Return a stable JSON-ready payload for provenance hashes."""
    return {
        "table_version": table.table_version,
        "rules": [
            {
                "reason_id": rule.reason_id,
                "leak_type": rule.leak_type,
                "action_group": list(rule.action_group),
                "baseline_rate": rule.baseline_rate,
                "direction": rule.direction,
                "situation_overrides": dict(sorted(rule.situation_overrides.items())),
            }
            for rule in table.rules
        ],
    }


def load_action_baseline_table_payload(payload: object) -> ActionBaselineTable:
    """Strictly reconstruct an ``ActionBaselineTable`` from canonical JSON data."""
    table_keys = {"table_version", "rules"}
    rule_keys = {
        "reason_id",
        "leak_type",
        "action_group",
        "baseline_rate",
        "direction",
        "situation_overrides",
    }
    if not isinstance(payload, dict) or set(payload) != table_keys:
        raise ValueError("baseline artifact must contain exactly table_version and rules")
    table_version = payload["table_version"]
    rules_payload = payload["rules"]
    if not isinstance(table_version, str) or not table_version:
        raise ValueError("baseline artifact table_version must be a non-empty string")
    if not isinstance(rules_payload, list):
        raise ValueError("baseline artifact rules must be a list")

    rules: list[ActionLeakRule] = []
    for rule_payload in rules_payload:
        if not isinstance(rule_payload, dict) or set(rule_payload) != rule_keys:
            raise ValueError("baseline artifact rule fields do not match the strict contract")
        reason_id = rule_payload["reason_id"]
        leak_type = rule_payload["leak_type"]
        action_group = rule_payload["action_group"]
        baseline_rate = rule_payload["baseline_rate"]
        direction = rule_payload["direction"]
        overrides = rule_payload["situation_overrides"]
        if not isinstance(reason_id, str) or not isinstance(leak_type, str):
            raise ValueError("baseline artifact reason_id and leak_type must be strings")
        if not isinstance(action_group, list) or any(
            not isinstance(action, str) for action in action_group
        ):
            raise ValueError("baseline artifact action_group must be a list of strings")
        if isinstance(baseline_rate, bool) or not isinstance(baseline_rate, int | float):
            raise ValueError("baseline artifact baseline_rate must be numeric")
        if not isinstance(direction, str):
            raise ValueError("baseline artifact direction must be a string")
        if not isinstance(overrides, dict) or any(
            not isinstance(situation_key, str)
            or isinstance(rate, bool)
            or not isinstance(rate, int | float)
            for situation_key, rate in overrides.items()
        ):
            raise ValueError("baseline artifact situation_overrides are invalid")
        rules.append(
            ActionLeakRule(
                reason_id=reason_id,
                leak_type=leak_type,
                action_group=tuple(action_group),
                baseline_rate=baseline_rate,
                direction=direction,
                situation_overrides=dict(overrides),
            )
        )

    table = ActionBaselineTable(table_version=table_version, rules=tuple(rules))
    if action_baseline_table_payload(table) != payload:
        raise ValueError("baseline artifact does not round-trip through ActionBaselineTable")
    return table


def action_baseline_table_sha256(table: ActionBaselineTable) -> str:
    """Return the stable SHA-256 digest of an ActionBaselineTable payload."""
    payload = action_baseline_table_payload(table)
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ActionLeakCandidateScore:
    """Gate-independent posterior score for one rule and situation snapshot."""

    reason_id: str
    situation_key: str
    action_group: tuple[str, ...]
    k: int
    n: int
    observed_rate: float
    baseline_rate: float
    tau: float
    q: float
    confidence: float
    structurally_eligible: bool


def beta_binomial_upper_tail(
    *,
    k: int,
    n: int,
    baseline_rate: float,
    tau: float,
) -> float:
    """Return ``P(p >= baseline_rate + tau | k,n)`` for a Beta(1, 1) prior.

    For integer posterior parameters the tail is the Binomial(n + 1, q) CDF at
    ``k``. A log-sum-exp evaluation avoids overflow and remains deterministic for
    the gate-A range ``n <= 1000`` without adding a runtime dependency.
    """
    if isinstance(k, bool) or not isinstance(k, int):
        raise TypeError("k must be an integer")
    if isinstance(n, bool) or not isinstance(n, int):
        raise TypeError("n must be an integer")
    if n < 0:
        raise ValueError("n must be non-negative")
    if not 0 <= k <= n:
        raise ValueError("k must satisfy 0 <= k <= n")
    _validate_rate(baseline_rate, "baseline_rate")
    if not math.isfinite(tau) or not 0.0 < tau < 1.0:
        raise ValueError("tau must be finite and in (0, 1)")

    q = baseline_rate + tau
    if q <= 0.0:
        return 1.0
    if q >= 1.0:
        return 0.0

    trials = n + 1
    log_q = math.log(q)
    log_one_minus_q = math.log1p(-q)
    log_terms = [
        math.lgamma(trials + 1)
        - math.lgamma(j + 1)
        - math.lgamma(trials - j + 1)
        + j * log_q
        + (trials - j) * log_one_minus_q
        for j in range(k + 1)
    ]
    maximum = max(log_terms)
    probability = math.exp(maximum) * math.fsum(math.exp(term - maximum) for term in log_terms)
    return min(1.0, max(0.0, probability))


def score_action_leak_candidate(
    stats: ActionStats,
    rule: ActionLeakRule,
    config: LeakDetectorConfig,
) -> ActionLeakCandidateScore:
    """Score one candidate without applying sample, deviation, or confidence gates."""
    n = stats.opportunities
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("opportunities must be a non-negative integer")
    k = stats.count_any(rule.action_group)
    if isinstance(k, bool) or not isinstance(k, int) or not 0 <= k <= n:
        raise ValueError("action-group count must satisfy 0 <= k <= opportunities")
    observed_rate = k / n if n else 0.0
    baseline_rate = rule.baseline_for(stats.situation_key)
    q = baseline_rate + config.min_deviation
    confidence = beta_binomial_upper_tail(
        k=k,
        n=n,
        baseline_rate=baseline_rate,
        tau=config.min_deviation,
    )
    return ActionLeakCandidateScore(
        reason_id=rule.reason_id,
        situation_key=stats.situation_key,
        action_group=rule.action_group,
        k=k,
        n=n,
        observed_rate=observed_rate,
        baseline_rate=baseline_rate,
        tau=config.min_deviation,
        q=q,
        confidence=confidence,
        structurally_eligible=0.0 < q < 1.0,
    )


def classify_ground_truth_boundary(
    *,
    p_true: str | Decimal,
    q: str | Decimal,
    tolerance: str = BOUNDARY_ABS_TOLERANCE,
) -> GroundTruthBoundary:
    """Apply the preregistered decimal indifference rule around ``p_true == q``.

    This pure gate-A helper fixes the boundary semantics only; it does not build
    the gate-B evaluator, split catalog, league, or Test batch machinery.
    """
    if isinstance(p_true, float) or isinstance(q, float):
        raise TypeError("p_true and q must be canonical decimal tokens, not floats")
    try:
        true_rate = Decimal(p_true)
        boundary = Decimal(q)
        abs_tolerance = Decimal(tolerance)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("p_true, q, and tolerance must be decimal tokens") from exc
    if not true_rate.is_finite() or not boundary.is_finite():
        raise ValueError("p_true and q must be finite")
    if not Decimal(0) <= true_rate <= Decimal(1):
        raise ValueError("p_true must be in [0, 1]")
    if not Decimal(0) < boundary < Decimal(1):
        raise ValueError("q must be in (0, 1)")
    if not abs_tolerance.is_finite() or abs_tolerance < 0:
        raise ValueError("tolerance must be finite and non-negative")
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        delta = true_rate - boundary
    if abs(delta) <= abs_tolerance:
        return "indifference"
    return "positive" if delta > abs_tolerance else "negative"


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
        leaks: list[DetectedLeak] = []
        for rule in self.baseline_table.rules:
            candidate = score_action_leak_candidate(stats, rule, self.config)
            if not candidate.structurally_eligible:
                continue
            if candidate.n < self.config.min_effective_sample_size:
                continue
            if candidate.observed_rate - candidate.baseline_rate < self.config.min_deviation:
                continue
            if candidate.confidence < self.config.min_confidence:
                continue
            leaks.append(
                DetectedLeak(
                    reason_id=rule.reason_id,
                    leak_type=rule.leak_type,
                    situation_key=stats.situation_key,
                    observed_rate=candidate.observed_rate,
                    baseline_rate=candidate.baseline_rate,
                    effective_sample_size=candidate.n,
                    confidence=candidate.confidence,
                    direction=rule.direction,
                )
            )
        return leaks


def _validate_rate(rate: float, field_name: str) -> None:
    if not math.isfinite(rate) or not 0.0 <= rate <= 1.0:
        raise ValueError(f"{field_name} must be finite and in [0, 1], got {rate}")


def _policy_rate(policy: dict[str, float], actions: tuple[str, ...]) -> float:
    rate = math.fsum(policy.get(action, 0.0) for action in actions)
    _validate_rate(rate, "policy action rate")
    return rate


def _validate_check_bet_strategy_table(strategy_table: StrategyTable) -> None:
    for entry in strategy_table.entries:
        unsupported = sorted(set(entry.policy) - _CHECK_BET_POLICY_ACTIONS)
        if unsupported:
            raise ValueError(
                "StrategyTable must use only CHECK/BET actions to build an "
                f"ActionBaselineTable; combo {entry.combo!r} has unsupported "
                f"actions {unsupported!r}"
            )
