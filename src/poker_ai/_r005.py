"""R005's private, fully polarized, fixed river-raise experiment.

The estimand is P(bluff | RAISE_ALL_IN, this fixed public context). Only
normally revealed, completed CALL showdowns enter the detector. A fixed Hero
combo and independent current opponent deal make CALL selection independent of
the current hidden combo, conditional on this context and prior observations.
No uncalled cards, fixture answer key, or hidden action policy enter this module.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from functools import lru_cache

from poker_core.card import parse_cards
from poker_core.combo import Combo
from poker_core.dpl_schema import DetectedLeak
from poker_core.hand_evaluator import evaluate_best
from poker_core.range_model import Range
from poker_core.run_manifest import ConfigRef
from poker_core.state_cluster import classify_board, cluster_def_version
from poker_core.strategy_table import StrategyEntry, StrategyTable
from poker_solver.cfr_plus import CFRPlus
from poker_solver.evaluate import expected_value
from poker_solver.game import Chance, Game
from poker_solver.nodelock import NodeLockConfig, NodeLockRule, apply_node_locks
from poker_solver.river_tree import _build_r005_raise_game

from .base_policy import BasePolicySelection
from .cfr_policy import CfrRiverPolicyConfig
from .exploit import RuleExploitResult, _per_combo_best_response_policy
from .leak import ActionBaselineTable, LeakDetector, LeakDetectorConfig, beta_binomial_upper_tail
from .scenario import Scenario

_MODE = "r005_fixed_raise"
_OPPONENT_ID = "fixture-r005-polarized-raise-v1"
_VERSION = "r005-public-showdown-v1"
_BOARD = ("2c", "4d", "7h", "9s", "Jc")
_HERO = "QhQd"
_HERO_RANGE = {"QhQd": 1.0, "QsQc": 1.0}
_OPPONENT_RANGE = {"AsAd": 1.0, "KsKd": 1.0, "6c5c": 1.0, "8c6d": 1.0}
_CONTEXT = f"{classify_board(parse_cards(_BOARD))}:OOP:river_vs_raise:r005_fixed"
_MIN_DEVIATION = 0.08
_HISTORY = (
    {"actor": "OOP", "action": "BET_33", "amount": 3.3, "source": "fixture_precondition"},
    {"actor": "IP", "action": "RAISE_ALL_IN", "raise_to": 10.0},
)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _scenario(hand_id: str) -> Scenario:
    return Scenario(
        scenario_id=hand_id,
        board=_BOARD,
        position="OOP",
        pot=16.6,
        effective_stack=6.7,
        hero_combo=_HERO,
        hero_range=dict(_HERO_RANGE),
        opponent_range=dict(_OPPONENT_RANGE),
    )


def _classify_revealed(combo: str) -> str:
    """Structural pure value/air classification over the whole public Hero support."""
    actual = Combo.from_str(combo)
    if actual.canonical() not in _OPPONENT_RANGE or combo != actual.canonical():
        raise ValueError("R005 reveal must be a canonical combo in the fixed public support")
    board = parse_cards(_BOARD)
    strength = evaluate_best((*actual.cards, *board))
    hero_strengths = [evaluate_best((*Combo.from_str(hero).cards, *board)) for hero in _HERO_RANGE]
    if strength > max(hero_strengths):
        return "value"
    if strength < min(hero_strengths):
        return "bluff"
    raise ValueError("R005 requires strictly polarized support without ties or marginal hands")


def _validate_observation(obs) -> None:
    expected = _scenario(obs.hand_id)
    if (
        tuple(str(card) for card in obs.board) != _BOARD
        or obs.position != "OOP"
        or obs.hero_combo.canonical() != _HERO
        or obs.hero_range.weights != _HERO_RANGE
        or obs.opponent_assumed_range.weights != _OPPONENT_RANGE
        or not math.isclose(obs.pot, expected.pot, abs_tol=1e-12, rel_tol=0)
        or not math.isclose(obs.facing_bet, 6.7, abs_tol=1e-12, rel_tol=0)
        or not math.isclose(obs.effective_stack, 6.7, abs_tol=1e-12, rel_tol=0)
    ):
        raise ValueError("R005 provider requires the exact fixed public raise context")


@lru_cache(maxsize=16)
def _solve(iterations: int, average_delay: int):
    if iterations <= average_delay or average_delay < 0:
        raise ValueError("invalid R005 finite-CFR budget")
    game = _build_r005_raise_game(Range(_HERO_RANGE), Range(_OPPONENT_RANGE), parse_cards(_BOARD))
    profile = CFRPlus(game, average_delay=average_delay).run(iterations).average_strategy()
    return game, profile


def _raise_masses(game, profile) -> dict[str, float]:
    """Joint chance/raise reach, conditioned on Hero's actual fixed combo."""
    masses = {}
    for probability, response, label in game.root.branches:
        hero, opponent = label.split("|")
        if hero == _HERO:
            masses[opponent] = probability * profile[response.infoset]["RAISE_ALL_IN"]
    if math.fsum(masses.values()) <= 0:
        raise ValueError("R005 baseline has no raise reach")
    return masses


def _bluff_share(game, profile) -> float:
    masses = _raise_masses(game, profile)
    return math.fsum(
        mass for combo, mass in masses.items() if _classify_revealed(combo) == "bluff"
    ) / math.fsum(masses.values())


def _action_evs(game, profile) -> dict[str, float]:
    masses = _raise_masses(game, profile)
    total = math.fsum(masses.values())
    result = {}
    for action in ("CALL", "FOLD"):
        branches = tuple(
            (
                masses[label.split("|")[1]] / total,
                response.child_of("RAISE_ALL_IN").child_of(action),
                label,
            )
            for _probability, response, label in game.root.branches
            if label.split("|")[0] == _HERO and masses[label.split("|")[1]] > 0
        )
        # Solver net stake includes Hero's sunk half-pot and opening bet.
        result[action] = expected_value(Game(Chance(branches)), profile, validate=False) + 8.3
    return result


class _R005BasePolicy:
    source = "poker_solver.river_r005_fixed_raise"

    def __init__(self, config: CfrRiverPolicyConfig):
        self.config = config

    def _identity(self):
        return {
            "version": _VERSION,
            "board": _BOARD,
            "hero_combo": _HERO,
            "hero_range": _HERO_RANGE,
            "opponent_range": _OPPONENT_RANGE,
            "pot": 10.0,
            "bet": 3.3,
            "raise_to": 10.0,
            "condition": "OOP fixed opening BET_33",
            "solver": self.config.model_dump(mode="json"),
        }

    @property
    def strategy_version(self):
        return f"r005-finite-cfr-{_digest(self._identity())[:16]}"

    def config_ref(self):
        return ConfigRef(
            name="cfr_river_policy",
            role="solver",
            path=f"inline:{_VERSION}:iterations={self.config.iterations}:"
            f"average_delay={self.config.average_delay}",
            sha256=_digest(self._identity()),
        )

    def policy_for(self, observation, *, state_cluster):
        _validate_observation(observation)
        if state_cluster != classify_board(parse_cards(_BOARD)):
            raise ValueError("R005 state cluster mismatch")
        game, profile = _solve(self.config.iterations, self.config.average_delay)
        table = StrategyTable(
            table_version=self.strategy_version,
            situation_key=_CONTEXT,
            cluster_def_version=cluster_def_version(),
            source=self.source,
            entries=(
                StrategyEntry(
                    combo=_HERO, policy=dict(profile[f"OOP:{_HERO}:vs_raise"]), reach_prob=1.0
                ),
            ),
        )
        return BasePolicySelection(table, self.config_ref().sha256, _action_evs(game, profile))


@dataclass(frozen=True)
class _ShowdownStats:
    raises: int = 0
    revealed: int = 0
    bluffs: int = 0

    def __post_init__(self):
        if any(
            isinstance(x, bool) or not isinstance(x, int)
            for x in (self.raises, self.revealed, self.bluffs)
        ):
            raise ValueError("R005 counts must be integers")
        if not 0 <= self.bluffs <= self.revealed <= self.raises:
            raise ValueError("R005 counts must satisfy bluffs <= revealed <= raises")

    def after(self, *, selected_action: str, revealed_combo: str | None):
        if selected_action == "FOLD" and revealed_combo is None:
            return _ShowdownStats(self.raises + 1, self.revealed, self.bluffs)
        if selected_action != "CALL" or revealed_combo is None:
            raise ValueError("R005 cards are revealed exactly after a completed CALL")
        classification = _classify_revealed(revealed_combo)
        return _ShowdownStats(
            self.raises + 1,
            self.revealed + 1,
            self.bluffs + (classification == "bluff"),
        )


class _R005Detector(LeakDetector):
    """Separate showdown statistic; never put classifications in action_counts."""

    def __init__(self, solver_config, config=None):
        super().__init__(
            ActionBaselineTable(_VERSION, ()),
            config or LeakDetectorConfig(min_deviation=_MIN_DEVIATION),
        )
        self.solver_config = solver_config
        game, profile = _solve(solver_config.iterations, solver_config.average_delay)
        self.baseline_bluff_rate = _bluff_share(game, profile)

    def _score(self, stats: _ShowdownStats):
        n = stats.revealed
        observed = stats.bluffs / n if n else None
        # Underbluff is exactly the upper tail of the complementary value share.
        confidence = beta_binomial_upper_tail(
            k=n - stats.bluffs,
            n=n,
            baseline_rate=1 - self.baseline_bluff_rate,
            tau=self.config.min_deviation,
        )
        eligible = (
            n >= self.config.min_effective_sample_size
            and observed is not None
            and self.baseline_bluff_rate - observed >= self.config.min_deviation
            and confidence >= self.config.min_confidence
            and self.baseline_bluff_rate > self.config.min_deviation
        )
        return {
            "raises": stats.raises,
            "revealed": n,
            "bluffs": stats.bluffs,
            "unknown": stats.raises - n,
            "observed_bluff_rate": observed,
            "baseline_bluff_rate": self.baseline_bluff_rate,
            "posterior_confidence": confidence,
            "detected": eligible,
        }

    def _detect_public(self, stats: _ShowdownStats):
        score = self._score(stats)
        if not score["detected"]:
            return []
        return [
            DetectedLeak(
                reason_id="LEAK_R005",
                leak_type="river_raise_underbluff",
                situation_key=_CONTEXT,
                observed_rate=score["observed_bluff_rate"],
                baseline_rate=self.baseline_bluff_rate,
                effective_sample_size=stats.revealed,
                confidence=score["posterior_confidence"],
                direction="decrease_call_frequency_facing_fixed_river_raise",
            )
        ]


class _R005ExploitProvider:
    """Hard-lock only bluff raises to the observed conditional composition."""

    def __init__(self, solver_config, confidence_config):
        self.solver_config = solver_config
        self.confidence_config = confidence_config

    def build(self, *, base_policy, detected_leaks, legal_actions, action_ev, observation=None):
        fallback = RuleExploitResult(policy=dict(base_policy))
        if observation is None:
            return fallback
        _validate_observation(observation)
        if set(legal_actions) != {"CALL", "FOLD"} or set(base_policy) != set(legal_actions):
            raise ValueError("R005 supports only CALL/FOLD facing the fixed raise")
        leaks = [
            leak
            for leak in detected_leaks
            if leak.reason_id == "LEAK_R005"
            and leak.situation_key == _CONTEXT
            and leak.confidence >= self.confidence_config.nodelock_exploit_min_confidence
        ]
        if len(leaks) != 1:
            return fallback
        leak = leaks[0]
        game, profile = _solve(self.solver_config.iterations, self.solver_config.average_delay)
        baseline = _bluff_share(game, profile)
        if (
            not math.isclose(leak.baseline_rate, baseline, rel_tol=0, abs_tol=1e-12)
            or not 0 <= leak.observed_rate < baseline < 1
        ):
            return fallback
        target = leak.observed_rate
        scale = target * (1 - baseline) / ((1 - target) * baseline)
        rules = tuple(
            NodeLockRule(
                action="RAISE_ALL_IN",
                target_frequency=dist["RAISE_ALL_IN"] * scale,
                infoset=infoset,
                rule_id="LEAK_R005_opponent_bluff_raise",
            )
            for infoset, dist in profile.items()
            if infoset.startswith("IP:") and _classify_revealed(infoset.split(":")[1]) == "bluff"
        )
        application = apply_node_locks(
            game,
            profile,
            NodeLockConfig(rules=rules, lock_mode="HARD", unlocked_policy_mode="fix_to_baseline"),
        )
        if not math.isclose(_bluff_share(game, application.profile), target, abs_tol=1e-12):
            raise ValueError("R005 hard lock failed to achieve the conditional bluff share")
        evs = _action_evs(game, application.profile)
        policy = _per_combo_best_response_policy(
            game, application.profile, hero_actor="OOP", hero_combo=_HERO, phase="vs_raise"
        )
        gain = math.fsum((policy[a] - base_policy[a]) * evs[a] for a in legal_actions)
        if gain <= 1e-12 or policy["CALL"] > base_policy["CALL"]:
            return fallback
        identity = {
            "version": _VERSION,
            "solver": self.solver_config.model_dump(mode="json"),
            "target_bluff_rate": target,
            "locked_profile": application.profile,
        }
        return RuleExploitResult(
            policy=policy,
            applied_leak_reason_ids=("LEAK_R005",),
            trigger_reasons=("TRG_R001", "TRG_R002"),
            exploit_source="nodelock_solver",
            solver_result_id="nodelock_solver:r005:allocation=baseline_scaled:"
            "lock_mode=HARD:unlocked_policy_mode=fix_to_baseline:"
            f"digest={_digest(identity)[:16]}",
            decision_action_ev=evs,
        )
