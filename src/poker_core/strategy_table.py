"""StrategyTable contract v1 (ADR-0006 Phase-0 freeze; REV-20260702 M-3, ADR-0005).

A StrategyTable holds the strategy for one situation as **per-combo** policies,
which are the canonical representation. The ``hand_bucket`` aggregated view is a
*derived* projection (ADR-0005), demonstrated here by :meth:`aggregate_policy`
(reach-weighted average across combos). Provenance and versions are recorded so a
table can be traced to the solve that produced it.

Combos are strings in v1; Phase 1 introduces a typed card/combo model and
strengthens this field while keeping the contract backward compatible.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .dpl_schema import Policy

#: Current StrategyTable schema version.
STRATEGY_TABLE_SCHEMA_VERSION = "1.0.0"


class StrategyEntry(BaseModel):
    """A single combo's policy and its range-reach weight."""

    model_config = ConfigDict(extra="forbid")

    combo: str = Field(min_length=1)
    policy: Policy
    reach_prob: float = Field(ge=0.0, le=1.0)


class StrategyTable(BaseModel):
    """Per-combo strategy for one situation, with provenance (canonical form)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = STRATEGY_TABLE_SCHEMA_VERSION
    table_version: str = Field(min_length=1)
    situation_key: str = Field(min_length=1)
    cluster_def_version: str = Field(min_length=1)
    source: str = Field(min_length=1)
    entries: tuple[StrategyEntry, ...]

    @field_validator("schema_version")
    @classmethod
    def _supported_schema_version(cls, value: str) -> str:
        if value != STRATEGY_TABLE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported StrategyTable schema_version {value!r}; "
                f"this build writes {STRATEGY_TABLE_SCHEMA_VERSION!r}"
            )
        return value

    @model_validator(mode="after")
    def _validate_entries(self) -> StrategyTable:
        if not self.entries:
            raise ValueError("StrategyTable must have at least one entry")
        combos = [entry.combo for entry in self.entries]
        if len(combos) != len(set(combos)):
            raise ValueError("StrategyTable contains duplicate combos")
        return self

    def aggregate_policy(self) -> dict[str, float]:
        """Reach-weighted aggregate of the per-combo policies (derived view; M-3)."""
        total_reach = math.fsum(entry.reach_prob for entry in self.entries)
        if total_reach <= 0.0:
            raise ValueError("cannot aggregate: total reach probability is zero")
        aggregate: dict[str, float] = {}
        for entry in self.entries:
            weight = entry.reach_prob / total_reach
            for action, prob in entry.policy.items():
                aggregate[action] = aggregate.get(action, 0.0) + weight * prob
        return aggregate
