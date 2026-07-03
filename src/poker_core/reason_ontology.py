"""Loader and accessor for the Reason Ontology (ADR-0001).

The ontology is the single source of truth for every ``reason_id`` that may
appear in a Decision Provenance Log or in a generated explanation. It defines
three disjoint namespaces -- ``LEAK_`` (opponent leak hypotheses), ``TRG_``
(adjustment trigger conditions) and ``MIX_`` (policy execution reasons).

The DPL schema (``dpl_schema``), the future explanation generator and the
Explanation Verifier all resolve reason ids through :func:`get_ontology`, so
that faithfulness (Reason Validity) is measured against one shared definition.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

#: The three permitted reason-id namespaces (ADR-0001).
VALID_NAMESPACES: tuple[str, ...] = ("LEAK", "TRG", "MIX")

Namespace = Literal["LEAK", "TRG", "MIX"]

#: Location of the packaged ontology definition.
ONTOLOGY_PATH: Path = Path(__file__).with_name("reason_ontology.yaml")


def namespace_of(reason_id: str) -> str:
    """Return the namespace prefix of ``reason_id`` (text before the first ``_``).

    ``"LEAK_R001"`` -> ``"LEAK"``. Returns ``""`` when there is no underscore.
    """
    prefix, sep, _tail = reason_id.partition("_")
    return prefix if sep else ""


class NamespaceDef(BaseModel):
    """Human-readable definition of one namespace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    description: str


class ReasonEntry(BaseModel):
    """A single reason definition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    namespace: Namespace
    label: str
    description: str
    source_ref: str

    @model_validator(mode="after")
    def _prefix_matches_namespace(self) -> ReasonEntry:
        expected = f"{self.namespace}_"
        if not self.id.startswith(expected):
            raise ValueError(
                f"reason id {self.id!r} does not start with its namespace prefix {expected!r}"
            )
        return self


class ReasonOntology(BaseModel):
    """Parsed and validated Reason Ontology."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str
    ontology_version: str
    namespaces: dict[str, NamespaceDef]
    reasons: tuple[ReasonEntry, ...]

    @model_validator(mode="after")
    def _validate_consistency(self) -> ReasonOntology:
        for name in self.namespaces:
            if name not in VALID_NAMESPACES:
                raise ValueError(f"undeclared namespace {name!r}; allowed: {VALID_NAMESPACES}")
        seen: set[str] = set()
        for entry in self.reasons:
            if entry.id in seen:
                raise ValueError(f"duplicate reason id {entry.id!r}")
            seen.add(entry.id)
            if entry.namespace not in self.namespaces:
                raise ValueError(
                    f"reason {entry.id!r} uses namespace {entry.namespace!r} "
                    f"which is not declared in `namespaces`"
                )
        return self

    @property
    def by_id(self) -> dict[str, ReasonEntry]:
        """Map of ``reason_id`` -> :class:`ReasonEntry`."""
        return {entry.id: entry for entry in self.reasons}

    def has(self, reason_id: str) -> bool:
        """True if ``reason_id`` is defined in the ontology."""
        return reason_id in self.by_id

    def get(self, reason_id: str) -> ReasonEntry:
        """Return the :class:`ReasonEntry` for ``reason_id`` (KeyError if absent)."""
        return self.by_id[reason_id]

    def ids_in(self, namespace: str) -> tuple[str, ...]:
        """All reason ids belonging to ``namespace`` (declaration order)."""
        return tuple(e.id for e in self.reasons if e.namespace == namespace)

    def is_valid(self, reason_id: str, namespace: str | None = None) -> bool:
        """True if ``reason_id`` exists and (optionally) is in ``namespace``.

        When ``namespace`` is given, the id must both be defined and belong to
        that namespace -- this is how the DPL enforces per-field namespace
        separation (e.g. ``detected_leaks[].reason_id`` must be ``LEAK_*``).
        """
        entry = self.by_id.get(reason_id)
        if entry is None:
            return False
        return namespace is None or entry.namespace == namespace


def load_ontology(path: Path | str | None = None) -> ReasonOntology:
    """Load and validate the ontology from ``path`` (defaults to the packaged file)."""
    target = Path(path) if path is not None else ONTOLOGY_PATH
    with target.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return ReasonOntology.model_validate(raw)


@lru_cache(maxsize=1)
def get_ontology() -> ReasonOntology:
    """Return the process-wide cached ontology loaded from the packaged file."""
    return load_ontology()
