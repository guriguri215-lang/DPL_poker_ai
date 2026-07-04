"""Stub opponent with a hidden strategy Hero must never read (AI Spec 6.3).

Task 3 uses a single fixed-strategy stub opponent: on the river it jams all-in
with its whole range (``jam_all``). Its *action policy* is a **hidden strategy** --
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

from dataclasses import dataclass, field

from poker_core.range_model import Range


class HiddenStrategyAccessError(RuntimeError):
    """Raised when Hero-side code tries to read the opponent's hidden strategy."""


@dataclass(frozen=True)
class OpponentAction:
    """The opponent's realised river action (produced for the environment only)."""

    #: One of the abstract river actions; the stub always shoves ``BET_ALL_IN``.
    action: str
    #: All-in bet size in big blinds (the amount Hero must call).
    bet_size: float


@dataclass
class StubOpponent:
    """A fixed ``jam_all`` river opponent (AI Spec 6.3; ADR-0007 one stub type).

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
