"""Stub opponent with a hidden strategy Hero must never read (AI Spec 6.3).

The historical stub jams all-in with its whole river range. The opt-in R007
fixture uses a separate check-back stub after Hero checks. Each *action policy*
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

import math
from dataclasses import dataclass, field

from poker_core.range_model import Range

JAM_ALL_OPPONENT_ID = "stub_jam_all"
CHECK_BACK_OPPONENT_ID = "stub_check_back_all"
STUB_OPPONENT_VERSION = "0.1.0"


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
    """Reveal the fixed stub policy for environment-side post-session evaluation.

    Session orchestration calls this only after every Hero decision has completed.
    Hero decision code is never given this value or this function.
    """

    action_probabilities = (
        (("CHECK", 1.0),) if opponent_model_id == CHECK_BACK_OPPONENT_ID else (("BET_ALL_IN", 1.0),)
    )
    return OpponentAnswerKey(
        opponent_model_id=opponent_model_id,
        action_probabilities=action_probabilities,
    )


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
