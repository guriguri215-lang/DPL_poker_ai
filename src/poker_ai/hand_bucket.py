"""Hand-bucket classifier: Hero's combo -> one of five strength classes (ADR-0005).

ADR-0005 subdivides the Hero strategy key by ``hand_bucket`` so a river policy can
depend on hand strength. On the river the class is deterministic: it is the combo's
relative-strength *percentile within Hero's own range* on the board. This module
computes that percentile with the exact hand evaluator and maps it to a class via a
declarative, versioned band definition (:mod:`hand_bucket.yaml`).

The band definition is a **draft** (``bucket_def_version`` ends with ``-draft``,
Q5); its thresholds are provisional and must be frozen via an ADR before any
persisted table is keyed on them. The five class names are kept identical to the
frozen DPL ``hand_bucket`` enum so the two cannot drift.
"""

from __future__ import annotations

import math
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from poker_core.card import Card
from poker_core.combo import Combo
from poker_core.dpl_schema import HandBucket
from poker_core.hand_evaluator import hand_strength
from poker_core.range_model import Range

#: Location of the packaged hand-bucket band definition.
BUCKET_DEF_PATH: Path = Path(__file__).with_name("hand_bucket.yaml")

#: The frozen DPL ``hand_bucket`` class names, ordered weakest -> strongest. The
#: band definition must list exactly these, in this order (checked at load time).
BUCKET_NAMES_WEAK_TO_STRONG: tuple[str, ...] = (
    "air",
    "weak_showdown",
    "marginal",
    "strong_value",
    "nuts",
)


class BucketBand(BaseModel):
    """One named strength class and the exclusive upper percentile bound."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    #: Exclusive upper percentile bound; ``None`` only for the strongest band.
    max_percentile: float | None

    @model_validator(mode="after")
    def _validate_bound(self) -> BucketBand:
        if self.max_percentile is not None and not 0.0 < self.max_percentile <= 1.0:
            raise ValueError(
                f"band {self.name!r} max_percentile must be in (0, 1] or null, "
                f"got {self.max_percentile}"
            )
        return self


class BucketDefinition(BaseModel):
    """An ordered, versioned set of percentile bands (weakest -> strongest)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    bucket_def_version: str
    description: str
    buckets: tuple[BucketBand, ...]

    @model_validator(mode="after")
    def _validate_definition(self) -> BucketDefinition:
        names = tuple(band.name for band in self.buckets)
        if names != BUCKET_NAMES_WEAK_TO_STRONG:
            raise ValueError(
                f"bucket names {names} must equal the frozen DPL hand_bucket enum "
                f"{BUCKET_NAMES_WEAK_TO_STRONG} in weakest->strongest order"
            )
        # Bounds must strictly increase, and only the last band may be open.
        bounds = [band.max_percentile for band in self.buckets]
        if bounds[-1] is not None:
            raise ValueError("the strongest band (nuts) must have max_percentile: null")
        finite = bounds[:-1]
        if any(bound is None for bound in finite):
            raise ValueError("only the strongest band may have a null max_percentile")
        if any(a >= b for a, b in zip(finite, finite[1:], strict=False)):
            raise ValueError(f"band max_percentile bounds must strictly increase, got {finite}")
        return self

    def classify(self, percentile: float) -> HandBucket:
        """Map a strength percentile in ``[0, 1)`` to its band name."""
        if not 0.0 <= percentile < 1.0:
            raise ValueError(f"percentile must be in [0, 1), got {percentile}")
        for band in self.buckets:
            if band.max_percentile is None or percentile < band.max_percentile:
                return band.name  # type: ignore[return-value]
        # Unreachable: the strongest band is open (max_percentile is None).
        raise RuntimeError("no band matched; definition is missing an open top band")


def load_bucket_definition(path: Path | str | None = None) -> BucketDefinition:
    """Load and validate the bucket definition (defaults to the packaged file)."""
    target = Path(path) if path is not None else BUCKET_DEF_PATH
    with target.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return BucketDefinition.model_validate(raw)


@lru_cache(maxsize=1)
def get_bucket_definition() -> BucketDefinition:
    """Return the process-wide cached bucket definition from the packaged file."""
    return load_bucket_definition()


def bucket_def_version() -> str:
    """The packaged bucket definition's version (ends with ``-draft`` for Q5)."""
    return get_bucket_definition().bucket_def_version


def strength_percentile(
    combo: Combo,
    hero_range: Range,
    board: tuple[Card, ...] | list[Card],
) -> float:
    """Reach-weighted fraction of ``hero_range`` strictly weaker than ``combo``.

    Combos in ``hero_range`` that are blocked by the board are ignored (they are
    not real holdings on this board). ``combo`` must itself be board-legal and
    present in ``hero_range``. The result lies in ``[0, 1)``.
    """
    board = tuple(board)
    board_mask = 0
    for card in board:
        board_mask |= card.mask
    if combo.mask & board_mask:
        raise ValueError(f"combo {combo} is blocked by the board")

    target = hand_strength(combo, board)
    weaker = 0.0
    total = 0.0
    seen_target = False
    for other, weight in hero_range:
        if weight <= 0 or (other.mask & board_mask):
            continue
        total += weight
        strength = hand_strength(other, board)
        if strength < target:
            weaker += weight
        if other.canonical() == combo.canonical():
            seen_target = True
    if not seen_target:
        raise ValueError(f"combo {combo} is not a board-legal member of hero_range")
    if total <= 0:
        raise ValueError("hero_range has no board-legal, positive-weight combos")
    return weaker / total


def classify_combo(
    combo: Combo,
    hero_range: Range,
    board: tuple[Card, ...] | list[Card],
) -> HandBucket:
    """Return the ``hand_bucket`` class of ``combo`` within ``hero_range``."""
    percentile = strength_percentile(combo, hero_range, board)
    # Guard against a percentile of exactly 1.0 from floating error (impossible by
    # definition, but classify() requires [0, 1)).
    percentile = min(percentile, math.nextafter(1.0, 0.0))
    return get_bucket_definition().classify(percentile)
