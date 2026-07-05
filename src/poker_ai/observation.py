"""Public observation tracking for the Phase-2 river MVP.

The tracker records only public, environment-observed opponent actions keyed by the
same situation key used by the Hero lookup path. It never accepts an opponent object
or any hidden policy, so leak detection can be driven from action logs without
peeking at :attr:`poker_ai.opponent.StubOpponent.hidden_strategy`.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class ActionStats:
    """Aggregated public opponent actions for one situation key."""

    situation_key: str
    opportunities: int
    action_counts: Mapping[str, int]

    def count(self, action: str) -> int:
        """Return the observed count for ``action`` in this situation."""
        return self.action_counts.get(action, 0)

    def count_any(self, actions: tuple[str, ...]) -> int:
        """Return the total count for a group of public action labels."""
        return sum(self.action_counts.get(action, 0) for action in actions)

    def rate_any(self, actions: tuple[str, ...]) -> float:
        """Return the observed rate of an action group."""
        if self.opportunities <= 0:
            return 0.0
        return self.count_any(actions) / self.opportunities


class ObservationTracker:
    """Collect action-only observations from public session events."""

    def __init__(self) -> None:
        self._action_counts: dict[str, Counter[str]] = {}
        self._opportunities: Counter[str] = Counter()

    def record_opponent_action(self, *, situation_key: str, action: str) -> None:
        """Record one public opponent action opportunity.

        ``situation_key`` names the public spot being tracked and ``action`` is the
        realised public action label, such as ``"BET_ALL_IN"`` or ``"CHECK"``.
        """
        if not situation_key:
            raise ValueError("situation_key must not be empty")
        if not action:
            raise ValueError("action must not be empty")
        self._opportunities[situation_key] += 1
        self._action_counts.setdefault(situation_key, Counter())[action] += 1

    def stats_for(self, situation_key: str) -> ActionStats | None:
        """Return immutable stats for ``situation_key``, or ``None`` if unseen."""
        opportunities = self._opportunities.get(situation_key, 0)
        if opportunities == 0:
            return None
        counts = dict(self._action_counts.get(situation_key, Counter()))
        return ActionStats(
            situation_key=situation_key,
            opportunities=opportunities,
            action_counts=MappingProxyType(counts),
        )

    def snapshot(self) -> tuple[ActionStats, ...]:
        """Return a deterministic immutable snapshot for leak detection."""
        return tuple(
            stats
            for key in sorted(self._opportunities)
            if (stats := self.stats_for(key)) is not None
        )
