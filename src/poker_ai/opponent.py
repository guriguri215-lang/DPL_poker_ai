"""Stub opponent with a hidden strategy Hero must never read (AI Spec 6.3).

The historical stub jams all-in with its whole river range. The opt-in R007
fixture uses a separate check-back stub after Hero checks. R001/R002 reuse one
frozen 0.75-pot profile, while R003/R004 reuse one finite-iteration 0.33-pot
profile; all four reveal a sampled response only after Hero bets. Each *action policy*
is a **hidden strategy** --
Hero is forbidden from conditioning on it (that would be leak detection /
exploitation, out of scope, and in general breaks the honesty of the setup, AI
Spec 6.3). The opponent's *hand range*, by contrast, is public scenario
information Hero may use for showdown EV; only the action policy is hidden.

The hidden policy is enforced with a tripwire: :attr:`StubOpponent.hidden_strategy`
raises :class:`HiddenStrategyAccessError` on any read, so a Hero code path that
tried to peek fails loudly. The environment obtains the opponent's action through
the separate, clearly-named :meth:`act` method, which Hero is never handed.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass, field
from decimal import Decimal
from functools import lru_cache
from typing import TYPE_CHECKING

from poker_core.range_model import Range

if TYPE_CHECKING:
    from opponents.ground_truth import TrueLeakMeasurement
    from opponents.synthesis import SynthesizedOpponent

JAM_ALL_OPPONENT_ID = "stub_jam_all"
CHECK_BACK_OPPONENT_ID = "stub_check_back_all"
R001_FIXTURE_OPPONENT_ID = "nl-train-r001-d016-s102"
R002_FIXTURE_OPPONENT_ID = "fixture-r002-d016-s102"
R003_FIXTURE_OPPONENT_ID = "fixture-r003-d016-finite-cfr-s20260704"
R004_FIXTURE_OPPONENT_ID = "fixture-r004-d016-finite-cfr-s20260704"
STUB_OPPONENT_VERSION = "0.1.0"
_RIVER_LARGE_BET_FIXTURE_DELTA = "0.16"
R003_FIXTURE_DELTA = "0.16"
R003_FIXTURE_PROFILE_VERSION = "finite-cfr-r003-profile-v1"
R003_FIXTURE_PROFILE_SEED = 20260704
R003_FIXTURE_PROFILE_ITERATIONS = 40
R003_FIXTURE_PROFILE_AVERAGE_DELAY = 0
R003_FIXTURE_BET_FRACTION = 0.33
R003_FIXTURE_RESPONSE_SAMPLER_VERSION = "r003-opponent-response-v1"
R004_FIXTURE_DELTA = R003_FIXTURE_DELTA
R004_FIXTURE_PROFILE_VERSION = "finite-cfr-r004-profile-v1"
R004_FIXTURE_RESPONSE_SAMPLER_VERSION = "r004-opponent-response-v1"


class HiddenStrategyAccessError(RuntimeError):
    """Raised when Hero-side code tries to read the opponent's hidden strategy."""


@dataclass(frozen=True)
class OpponentAction:
    """The opponent's realised river action (produced for the environment only)."""

    #: One of the abstract river actions produced by the selected stub fixture.
    action: str
    #: Public amount in big blinds; zero for ``CHECK`` and stack-sized for the jam.
    bet_size: float


@dataclass(frozen=True)
class OpponentAnswerKey:
    """Environment-only terminal action probabilities revealed after a session."""

    opponent_model_id: str
    action_probabilities: tuple[tuple[str, float], ...]

    def __post_init__(self) -> None:
        if not self.opponent_model_id:
            raise ValueError("opponent_model_id must not be empty")
        actions = [action for action, _probability in self.action_probabilities]
        if not actions or any(not action for action in actions):
            raise ValueError("answer-key actions must be non-empty")
        if actions != sorted(actions) or len(actions) != len(set(actions)):
            raise ValueError("answer-key actions must be unique and sorted")
        probabilities = [probability for _action, probability in self.action_probabilities]
        if any(
            not math.isfinite(probability) or not 0.0 <= probability <= 1.0
            for probability in probabilities
        ):
            raise ValueError("answer-key probabilities must be finite and in [0, 1]")
        if not math.isclose(math.fsum(probabilities), 1.0, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("answer-key probabilities must sum to 1.0")

    def action_group_rate(self, action_group: tuple[str, ...] | list[str]) -> float:
        """Return the true probability of one terminal-snapshot action group."""

        if not action_group or any(not action for action in action_group):
            raise ValueError("action_group must contain non-empty action labels")
        if len(action_group) != len(set(action_group)):
            raise ValueError("action_group must not contain duplicate actions")
        probabilities = dict(self.action_probabilities)
        return math.fsum(probabilities.get(action, 0.0) for action in action_group)


def reveal_stub_opponent_answer_key(*, opponent_model_id: str) -> OpponentAnswerKey:
    """Reveal the fixture policy for environment-side post-session evaluation.

    Session orchestration calls this only after every Hero decision has completed.
    Hero decision code is never given this value or this function.
    """

    if opponent_model_id == CHECK_BACK_OPPONENT_ID:
        action_probabilities = (("CHECK", 1.0),)
    elif opponent_model_id in {
        R001_FIXTURE_OPPONENT_ID,
        R002_FIXTURE_OPPONENT_ID,
        R003_FIXTURE_OPPONENT_ID,
        R004_FIXTURE_OPPONENT_ID,
    }:
        if opponent_model_id == R001_FIXTURE_OPPONENT_ID:
            measurement = r001_fixture_measurement()
        elif opponent_model_id == R002_FIXTURE_OPPONENT_ID:
            measurement = r002_fixture_measurement()
        elif opponent_model_id == R003_FIXTURE_OPPONENT_ID:
            measurement = r003_fixture_measurement()
        else:
            measurement = r004_fixture_measurement()
        target_probability = float(measurement.opponent_rate)
        action_probabilities = tuple(
            sorted(
                (
                    (measurement.action, target_probability),
                    (
                        "CALL" if measurement.action == "FOLD" else "FOLD",
                        1.0 - target_probability,
                    ),
                )
            )
        )
    else:
        action_probabilities = (("BET_ALL_IN", 1.0),)
    return OpponentAnswerKey(
        opponent_model_id=opponent_model_id,
        action_probabilities=action_probabilities,
    )


def load_r001_fixture_synthesis() -> SynthesizedOpponent:
    """Load the pinned Training R001 fixture through the existing catalog."""

    return _load_river_large_bet_fixture_synthesis("LEAK_R001")


def load_r002_fixture_synthesis() -> SynthesizedOpponent:
    """Build the noncatalog R002 fixture from R001's frozen node provenance."""

    return _load_river_large_bet_fixture_synthesis("LEAK_R002")


def _load_river_large_bet_fixture_synthesis(reason_id: str) -> SynthesizedOpponent:
    """Resolve only the shared frozen 0.75-pot inputs for R001 and R002."""

    from opponents.catalog import load_training_catalog
    from opponents.model import OpponentModelConfig, leak_action_mapping
    from opponents.synthesis import synthesize_opponent

    matches = tuple(
        config
        for config in load_training_catalog()
        if config.opponent_id == R001_FIXTURE_OPPONENT_ID
    )
    if len(matches) != 1:
        raise ValueError("pinned R001 fixture opponent must resolve exactly once")
    anchor = matches[0]
    if reason_id == "LEAK_R001":
        config = anchor
    elif reason_id == "LEAK_R002":
        config = OpponentModelConfig(
            opponent_id=R002_FIXTURE_OPPONENT_ID,
            opponent_version=anchor.opponent_version,
            split=anchor.split,
            equilibrium_version=anchor.equilibrium_version,
            equilibrium_artifact_sha256=anchor.equilibrium_artifact_sha256,
            opponent_position=anchor.opponent_position,
            leak_vector=((reason_id, _RIVER_LARGE_BET_FIXTURE_DELTA),),
            seed=anchor.seed,
            combo_allocation=anchor.combo_allocation,
            lock_mode=anchor.lock_mode,
            unlocked_policy_mode=anchor.unlocked_policy_mode,
        )
    else:
        raise ValueError(f"unsupported river-large-bet fixture reason {reason_id!r}")

    mapping = leak_action_mapping(reason_id)
    if mapping.phase != "vs_bet" or mapping.action not in {"FOLD", "CALL"}:
        raise ValueError("river-large-bet fixture mapping changed")
    synthesized = synthesize_opponent(config=config)
    if synthesized.config.leak_vector != ((reason_id, _RIVER_LARGE_BET_FIXTURE_DELTA),):
        raise ValueError(f"pinned {reason_id} fixture leak vector changed")
    if not math.isclose(synthesized.bet_fraction, 0.75, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError("river-large-bet fixture must remain fixed at 0.75 pot")
    return synthesized


def r001_fixture_measurement(
    synthesized: SynthesizedOpponent | None = None,
) -> TrueLeakMeasurement:
    """Derive R001 baseline and response rates through existing ground truth."""

    return _river_large_bet_fixture_measurement(
        synthesized or load_r001_fixture_synthesis(),
        reason_id="LEAK_R001",
        action="FOLD",
    )


def r002_fixture_measurement(
    synthesized: SynthesizedOpponent | None = None,
) -> TrueLeakMeasurement:
    """Derive R002 baseline and response CALL rates through existing ground truth."""

    return _river_large_bet_fixture_measurement(
        synthesized or load_r002_fixture_synthesis(),
        reason_id="LEAK_R002",
        action="CALL",
    )


def r003_fixture_measurement() -> TrueLeakMeasurement:
    """Return the fixed finite-CFR small-bet FOLD baseline and response rate."""

    measurement, _path, _sha256 = _r003_fixture_contract()
    return measurement


def r003_fixture_config_identity() -> tuple[str, str]:
    """Return the existing inline ConfigRef path/hash for the noncatalog fixture."""

    _measurement, path, sha256 = _r003_fixture_contract()
    return path, sha256


def r004_fixture_measurement() -> TrueLeakMeasurement:
    """Return the fixed finite-CFR small-bet CALL baseline and response rate."""

    measurement, _path, _sha256 = _r004_fixture_contract()
    return measurement


def r004_fixture_config_identity() -> tuple[str, str]:
    """Return R004's content-hashed inline noncatalog ConfigRef identity."""

    _measurement, path, sha256 = _r004_fixture_contract()
    return path, sha256


@lru_cache(maxsize=1)
def _r003_fixture_contract() -> tuple[TrueLeakMeasurement, str, str]:
    """Build one deterministic 0.33-pot finite-CFR opponent contract in memory."""

    from opponents.ground_truth import TrueLeakMeasurement
    from opponents.model import leak_action_mapping
    from poker_ai.scenario import Scenario, generate_scenarios
    from poker_solver.nodelock import (
        NodeLockConfig,
        NodeLockRule,
        apply_node_locks,
        river_infoset_reach_weights,
    )
    from poker_solver.river_solve import solve_frozen_river_scenario
    from poker_solver.river_tree import RiverBettingConfig, build_river_game

    generated = next(generate_scenarios(R003_FIXTURE_PROFILE_SEED, 1))
    scenario_payload = generated.model_dump(mode="python")
    scenario_payload["position"] = "OOP"
    scenario_payload["effective_stack"] = max(
        generated.effective_stack,
        generated.pot * R003_FIXTURE_BET_FRACTION,
    )
    scenario = Scenario.model_validate(scenario_payload)
    result = solve_frozen_river_scenario(
        scenario,
        bet_fraction=R003_FIXTURE_BET_FRACTION,
        iterations=R003_FIXTURE_PROFILE_ITERATIONS,
        checkpoints=(),
        average_delay=R003_FIXTURE_PROFILE_AVERAGE_DELAY,
    )
    game = build_river_game(
        RiverBettingConfig(
            pot=scenario.pot,
            bet_fraction=R003_FIXTURE_BET_FRACTION,
        ),
        scenario.hero_range_obj(),
        scenario.opponent_range_obj(),
        scenario.board_cards(),
    )
    # Keep generic synthesis closed to R003; this fixture needs only the existing
    # R001 vs_bet/FOLD semantics inside its bounded noncatalog contract.
    mapping = leak_action_mapping("LEAK_R001")
    target_infosets = tuple(
        infoset
        for infoset in game.infosets
        if infoset.startswith("IP:")
        and infoset.endswith(f":{mapping.phase}")
        and mapping.action in game.actions_of(infoset)
    )
    if not target_infosets:
        raise ValueError("R003 finite-CFR profile has no IP vs_bet FOLD infosets")
    reach_weights = river_infoset_reach_weights(game, result.strategy)
    denominator = math.fsum(reach_weights[infoset] for infoset in target_infosets)
    if denominator <= 0.0:
        raise ValueError("R003 finite-CFR profile has zero small-bet response reach")
    baseline_rate = (
        math.fsum(
            reach_weights[infoset] * result.strategy[infoset][mapping.action]
            for infoset in target_infosets
        )
        / denominator
    )
    target_rate = baseline_rate + float(Decimal(R003_FIXTURE_DELTA))
    if not 0.0 < target_rate < 1.0:
        raise ValueError("R003 fixture delta exceeds the finite-CFR probability headroom")

    application = apply_node_locks(
        game,
        result.strategy,
        NodeLockConfig(
            rules=(
                NodeLockRule(
                    actor="IP",
                    phase=mapping.phase,
                    action=mapping.action,
                    target_frequency=target_rate,
                    combo_allocation="baseline_scaled",
                    rule_id="LEAK_R003_synthetic_opponent",
                ),
            ),
            lock_mode="HARD",
            unlocked_policy_mode="fix_to_baseline",
        ),
        reach_weights=reach_weights,
    )
    if len(application.applied_locks) != 1:
        raise ValueError("R003 fixture must apply exactly one FOLD node lock")
    achieved_rate = application.applied_locks[0].achieved_frequency
    if not math.isclose(achieved_rate, target_rate, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError("R003 fixture did not achieve its requested overfold rate")
    baseline_decimal = Decimal(str(baseline_rate))
    opponent_decimal = Decimal(str(achieved_rate))
    true_leak = opponent_decimal - baseline_decimal
    if abs(true_leak - Decimal(R003_FIXTURE_DELTA)) > Decimal("1e-12"):
        raise ValueError("R003 fixture overfold delta changed")
    measurement = TrueLeakMeasurement(
        reason_id="LEAK_R003",
        action=mapping.action,
        phase=mapping.phase,
        baseline_rate=baseline_decimal,
        opponent_rate=opponent_decimal,
        true_leak=true_leak,
    )

    baseline_profile_sha256 = _strategy_profile_sha256(result.strategy)
    locked_profile_sha256 = _strategy_profile_sha256(application.profile)
    provenance_payload = {
        "fixture_version": R003_FIXTURE_PROFILE_VERSION,
        "profile_kind": "finite_iteration_cfr",
        "profile_source": "poker_solver.solve_frozen_river_scenario",
        "equilibrium_or_gto_claim": False,
        "reference_seed": R003_FIXTURE_PROFILE_SEED,
        "reference_scenario_index": 0,
        "reference_scenario": scenario.model_dump(mode="json"),
        "solver": "cfr_plus",
        "bet_fraction": R003_FIXTURE_BET_FRACTION,
        "iterations": R003_FIXTURE_PROFILE_ITERATIONS,
        "average_delay": R003_FIXTURE_PROFILE_AVERAGE_DELAY,
        "solve_config_digest": result.solve_config_digest,
        "baseline_profile_sha256": baseline_profile_sha256,
        "locked_profile_sha256": locked_profile_sha256,
        "reason_id": measurement.reason_id,
        "action": measurement.action,
        "phase": measurement.phase,
        "delta": R003_FIXTURE_DELTA,
        "baseline_rate": str(measurement.baseline_rate),
        "opponent_rate": str(measurement.opponent_rate),
        "combo_allocation": "baseline_scaled",
        "lock_mode": application.lock_mode,
        "unlocked_policy_mode": application.unlocked_policy_mode,
        "response_sampler": R003_FIXTURE_RESPONSE_SAMPLER_VERSION,
    }
    encoded = json.dumps(
        provenance_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    config_sha256 = hashlib.sha256(encoded).hexdigest()
    inline_path = (
        f"inline:noncatalog:{R003_FIXTURE_PROFILE_VERSION}:reason=LEAK_R003:"
        f"delta={R003_FIXTURE_DELTA}:profile=finite_iteration_cfr:"
        f"source=poker_solver.solve_frozen_river_scenario:"
        f"seed={R003_FIXTURE_PROFILE_SEED}:scenario_index=0:"
        f"public_bet=BET_33:bet_fraction={R003_FIXTURE_BET_FRACTION:g}:"
        f"iterations={R003_FIXTURE_PROFILE_ITERATIONS}:"
        f"average_delay={R003_FIXTURE_PROFILE_AVERAGE_DELAY}:"
        f"solve_config={result.solve_config_digest}:"
        f"baseline_profile={baseline_profile_sha256}:"
        f"locked_profile={locked_profile_sha256}:allocation=baseline_scaled:"
        f"lock_mode={application.lock_mode}:"
        f"unlocked_policy_mode={application.unlocked_policy_mode}:"
        f"response_sampler={R003_FIXTURE_RESPONSE_SAMPLER_VERSION}"
    )
    return measurement, inline_path, config_sha256


@lru_cache(maxsize=1)
def _r004_fixture_contract() -> tuple[TrueLeakMeasurement, str, str]:
    """Build R004 by CALL-locking R003's deterministic 0.33-pot profile."""

    from opponents.ground_truth import TrueLeakMeasurement
    from opponents.model import leak_action_mapping
    from poker_ai.scenario import Scenario, generate_scenarios
    from poker_solver.nodelock import (
        NodeLockConfig,
        NodeLockRule,
        apply_node_locks,
        river_infoset_reach_weights,
    )
    from poker_solver.river_solve import solve_frozen_river_scenario
    from poker_solver.river_tree import RiverBettingConfig, build_river_game

    generated = next(generate_scenarios(R003_FIXTURE_PROFILE_SEED, 1))
    scenario_payload = generated.model_dump(mode="python")
    scenario_payload["position"] = "OOP"
    scenario_payload["effective_stack"] = max(
        generated.effective_stack,
        generated.pot * R003_FIXTURE_BET_FRACTION,
    )
    scenario = Scenario.model_validate(scenario_payload)
    result = solve_frozen_river_scenario(
        scenario,
        bet_fraction=R003_FIXTURE_BET_FRACTION,
        iterations=R003_FIXTURE_PROFILE_ITERATIONS,
        checkpoints=(),
        average_delay=R003_FIXTURE_PROFILE_AVERAGE_DELAY,
    )
    game = build_river_game(
        RiverBettingConfig(
            pot=scenario.pot,
            bet_fraction=R003_FIXTURE_BET_FRACTION,
        ),
        scenario.hero_range_obj(),
        scenario.opponent_range_obj(),
        scenario.board_cards(),
    )
    # R004 stays outside generic synthesis and borrows only R002's CALL meaning.
    mapping = leak_action_mapping("LEAK_R002")
    target_infosets = tuple(
        infoset
        for infoset in game.infosets
        if infoset.startswith("IP:")
        and infoset.endswith(f":{mapping.phase}")
        and mapping.action in game.actions_of(infoset)
    )
    if not target_infosets:
        raise ValueError("R004 finite-CFR profile has no IP vs_bet CALL infosets")
    reach_weights = river_infoset_reach_weights(game, result.strategy)
    denominator = math.fsum(reach_weights[infoset] for infoset in target_infosets)
    if denominator <= 0.0:
        raise ValueError("R004 finite-CFR profile has zero small-bet response reach")
    baseline_rate = (
        math.fsum(
            reach_weights[infoset] * result.strategy[infoset][mapping.action]
            for infoset in target_infosets
        )
        / denominator
    )
    target_rate = baseline_rate + float(Decimal(R004_FIXTURE_DELTA))
    if not 0.0 < target_rate < 1.0:
        raise ValueError("R004 fixture delta exceeds the finite-CFR probability headroom")

    application = apply_node_locks(
        game,
        result.strategy,
        NodeLockConfig(
            rules=(
                NodeLockRule(
                    actor="IP",
                    phase=mapping.phase,
                    action=mapping.action,
                    target_frequency=target_rate,
                    combo_allocation="baseline_scaled",
                    rule_id="LEAK_R004_synthetic_opponent",
                ),
            ),
            lock_mode="HARD",
            unlocked_policy_mode="fix_to_baseline",
        ),
        reach_weights=reach_weights,
    )
    if len(application.applied_locks) != 1:
        raise ValueError("R004 fixture must apply exactly one CALL node lock")
    achieved_rate = application.applied_locks[0].achieved_frequency
    if not math.isclose(achieved_rate, target_rate, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError("R004 fixture did not achieve its requested overcall rate")
    baseline_decimal = Decimal(str(baseline_rate))
    opponent_decimal = Decimal(str(achieved_rate))
    true_leak = opponent_decimal - baseline_decimal
    if abs(true_leak - Decimal(R004_FIXTURE_DELTA)) > Decimal("1e-12"):
        raise ValueError("R004 fixture overcall delta changed")
    measurement = TrueLeakMeasurement(
        reason_id="LEAK_R004",
        action=mapping.action,
        phase=mapping.phase,
        baseline_rate=baseline_decimal,
        opponent_rate=opponent_decimal,
        true_leak=true_leak,
    )

    baseline_profile_sha256 = _strategy_profile_sha256(result.strategy)
    locked_profile_sha256 = _strategy_profile_sha256(application.profile)
    provenance_payload = {
        "fixture_version": R004_FIXTURE_PROFILE_VERSION,
        "profile_kind": "finite_iteration_cfr",
        "profile_source": "poker_solver.solve_frozen_river_scenario",
        "equilibrium_or_gto_claim": False,
        "reference_seed": R003_FIXTURE_PROFILE_SEED,
        "reference_scenario_index": 0,
        "reference_scenario": scenario.model_dump(mode="json"),
        "solver": "cfr_plus",
        "bet_fraction": R003_FIXTURE_BET_FRACTION,
        "iterations": R003_FIXTURE_PROFILE_ITERATIONS,
        "average_delay": R003_FIXTURE_PROFILE_AVERAGE_DELAY,
        "solve_config_digest": result.solve_config_digest,
        "baseline_profile_sha256": baseline_profile_sha256,
        "locked_profile_sha256": locked_profile_sha256,
        "reason_id": measurement.reason_id,
        "action": measurement.action,
        "phase": measurement.phase,
        "delta": R004_FIXTURE_DELTA,
        "baseline_rate": str(measurement.baseline_rate),
        "opponent_rate": str(measurement.opponent_rate),
        "combo_allocation": "baseline_scaled",
        "lock_mode": application.lock_mode,
        "unlocked_policy_mode": application.unlocked_policy_mode,
        "response_sampler": R004_FIXTURE_RESPONSE_SAMPLER_VERSION,
    }
    encoded = json.dumps(
        provenance_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    config_sha256 = hashlib.sha256(encoded).hexdigest()
    inline_path = (
        f"inline:noncatalog:{R004_FIXTURE_PROFILE_VERSION}:reason=LEAK_R004:"
        f"action={measurement.action}:phase={measurement.phase}:"
        f"delta={R004_FIXTURE_DELTA}:profile=finite_iteration_cfr:"
        "source=poker_solver.solve_frozen_river_scenario:solver=cfr_plus:"
        f"seed={R003_FIXTURE_PROFILE_SEED}:scenario_index=0:"
        f"public_bet=BET_33:bet_fraction={R003_FIXTURE_BET_FRACTION:g}:"
        f"iterations={R003_FIXTURE_PROFILE_ITERATIONS}:"
        f"average_delay={R003_FIXTURE_PROFILE_AVERAGE_DELAY}:"
        f"solve_config={result.solve_config_digest}:"
        f"baseline_profile={baseline_profile_sha256}:"
        f"locked_profile={locked_profile_sha256}:allocation=baseline_scaled:"
        f"lock_mode={application.lock_mode}:"
        f"unlocked_policy_mode={application.unlocked_policy_mode}:"
        f"response_sampler={R004_FIXTURE_RESPONSE_SAMPLER_VERSION}"
    )
    return measurement, inline_path, config_sha256


def _strategy_profile_sha256(profile: dict[str, dict[str, float]]) -> str:
    payload = {
        infoset: {action: distribution[action] for action in sorted(distribution)}
        for infoset, distribution in sorted(profile.items())
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _river_large_bet_fixture_measurement(
    fixture: SynthesizedOpponent,
    *,
    reason_id: str,
    action: str,
) -> TrueLeakMeasurement:
    """Measure one shared river-large-bet node without synthesis metadata."""

    from opponents.ground_truth import extract_true_leaks

    measurements = extract_true_leaks(
        fixture.game,
        fixture.equilibrium_strategy,
        fixture.strategy,
        fixture.config,
    )
    if len(measurements) != 1:
        raise ValueError(f"pinned {reason_id} fixture must expose exactly one leak measurement")
    measurement = measurements[0]
    if (
        measurement.reason_id != reason_id
        or measurement.phase != "vs_bet"
        or measurement.action != action
    ):
        raise ValueError(f"pinned {reason_id} fixture mapping changed")
    return measurement


def sample_river_large_bet_fixture_response(
    *,
    target_action: str,
    target_probability: float,
    rng: random.Random,
) -> OpponentAction:
    """Environment-only FOLD/CALL sample after a realised fixed Hero river bet."""

    if target_action not in {"FOLD", "CALL"}:
        raise ValueError("river-large-bet target_action must be FOLD or CALL")
    if not math.isfinite(target_probability) or not 0.0 <= target_probability <= 1.0:
        raise ValueError("target_probability must be finite and in [0, 1]")
    other_action = "CALL" if target_action == "FOLD" else "FOLD"
    action = target_action if rng.random() < target_probability else other_action
    return OpponentAction(action=action, bet_size=0.0)


@dataclass
class StubOpponent:
    """A fixed synthetic river opponent (AI Spec 6.3; ADR-0007 stub boundary).

    ``assumed_range`` is the public river range Hero is told to assume. ``_policy``
    is the hidden action strategy; reading it via :attr:`hidden_strategy` raises.
    """

    opponent_id: str
    opponent_version: str
    assumed_range: Range
    #: Hidden action policy label; never exposed to Hero (read via `act` only).
    _policy: str = field(default="jam_all", repr=False)

    @property
    def hidden_strategy(self) -> str:
        """Tripwire: reading the hidden action strategy is forbidden (AI Spec 6.3)."""
        raise HiddenStrategyAccessError(
            "Hero must not read the opponent's hidden strategy (AI Spec 6.3); "
            "use the public assumed_range for EV and let the environment call act()"
        )

    def act(self, *, effective_stack: float) -> OpponentAction:
        """Environment-only: the opponent's river action under its hidden policy.

        The stub jams all-in for the effective stack. This method is called by the
        session/environment, never by Hero, so Hero never observes the policy.
        """
        if self._policy != "jam_all":
            raise ValueError(f"unknown stub opponent policy {self._policy!r}")
        if not effective_stack > 0:
            raise ValueError(f"effective_stack must be positive, got {effective_stack}")
        return OpponentAction(action="BET_ALL_IN", bet_size=effective_stack)

    def respond_to_check(self, *, effective_stack: float) -> OpponentAction:
        """Environment-only response at IP ``vs_check`` for the R007 fixture."""
        if self._policy != "check_back_all":
            raise ValueError(f"unknown check-back stub opponent policy {self._policy!r}")
        if not effective_stack > 0:
            raise ValueError(f"effective_stack must be positive, got {effective_stack}")
        return OpponentAction(action="CHECK", bet_size=0.0)
