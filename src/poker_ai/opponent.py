"""Stub opponent with a hidden strategy Hero must never read (AI Spec 6.3).

The historical stub jams all-in with its whole river range. The opt-in R007
fixture uses a separate check-back stub after Hero checks. The R001/R002
fixtures synthesize one frozen 0.75-pot opponent and reveal a sampled response
only after Hero bets. Each *action policy* is a **hidden strategy** --
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

import math
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from poker_core.range_model import Range

if TYPE_CHECKING:
    from opponents.ground_truth import TrueLeakMeasurement
    from opponents.synthesis import SynthesizedOpponent

JAM_ALL_OPPONENT_ID = "stub_jam_all"
CHECK_BACK_OPPONENT_ID = "stub_check_back_all"
R001_FIXTURE_OPPONENT_ID = "nl-train-r001-d016-s102"
R002_FIXTURE_OPPONENT_ID = "fixture-r002-d016-s102"
STUB_OPPONENT_VERSION = "0.1.0"
_RIVER_LARGE_BET_FIXTURE_DELTA = "0.16"


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
    elif opponent_model_id in {R001_FIXTURE_OPPONENT_ID, R002_FIXTURE_OPPONENT_ID}:
        measurement = (
            r001_fixture_measurement()
            if opponent_model_id == R001_FIXTURE_OPPONENT_ID
            else r002_fixture_measurement()
        )
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
    """Environment-only FOLD/CALL sample after a realised Hero BET_75."""

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
