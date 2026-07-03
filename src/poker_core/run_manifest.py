"""RunManifest -- the reproducibility contract for a session or experiment.

A manifest bundles every version, seed and config reference needed to reproduce
a run exactly (REV-20260702 M-7). Sessions and experiments are expected to be
launched *through* a manifest so that a run can always be replayed and audited,
and so the paper's results are traceable to a frozen configuration.

Raw logs and solver outputs live outside git; the manifest plus summary stats
are the tracked, portable record of what produced them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .dpl_schema import DPL_SCHEMA_VERSION
from .reason_ontology import get_ontology

#: Current RunManifest schema version.
MANIFEST_SCHEMA_VERSION = "1.0.0"

#: Train / validation / test split of the opponent-parameter space (REV 5.3).
DataSplit = Literal["training", "validation", "test"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CodeProvenance(BaseModel):
    """Identifies the exact code that produced a run."""

    model_config = ConfigDict(extra="forbid")

    git_commit: str = Field(min_length=1)
    git_dirty: bool = False
    package_version: str = Field(min_length=1)
    python_version: str = Field(min_length=1)


class ComponentVersions(BaseModel):
    """Versions of every contract/definition a run depends on.

    Any mismatch between these and the versions stamped on emitted DPL / solver
    artefacts means the run is not reproducible, so they are all required.
    """

    model_config = ConfigDict(extra="forbid")

    dpl_schema_version: str = DPL_SCHEMA_VERSION
    reason_ontology_version: str = Field(min_length=1)
    cluster_def_version: str = Field(min_length=1)
    strategy_table_version: str = Field(min_length=1)
    baseline_table_version: str = Field(min_length=1)

    @field_validator("reason_ontology_version")
    @classmethod
    def _ontology_version_matches(cls, value: str) -> str:
        current = get_ontology().ontology_version
        if value != current:
            raise ValueError(
                f"reason_ontology_version {value!r} does not match the loaded "
                f"ontology version {current!r}"
            )
        return value


class ConfigRef(BaseModel):
    """A pinned reference to a config file (path + content hash)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class OpponentRef(BaseModel):
    """The opponent model a run was played against, and its split."""

    model_config = ConfigDict(extra="forbid")

    opponent_id: str = Field(min_length=1)
    opponent_version: str = Field(min_length=1)
    split: DataSplit
    config: ConfigRef | None = None


class RunManifest(BaseModel):
    """Everything required to reproduce and audit a single run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = MANIFEST_SCHEMA_VERSION
    run_id: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=_utcnow)
    description: str = ""

    code: CodeProvenance
    versions: ComponentVersions
    seeds: dict[str, int] = Field(default_factory=dict)
    configs: list[ConfigRef] = Field(default_factory=list)
    opponents: list[OpponentRef] = Field(default_factory=list)

    @field_validator("schema_version")
    @classmethod
    def _supported_schema_version(cls, value: str) -> str:
        if value != MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported manifest schema_version {value!r}; "
                f"this build writes {MANIFEST_SCHEMA_VERSION!r}"
            )
        return value

    @field_validator("seeds")
    @classmethod
    def _seed_names_non_empty(cls, value: dict[str, int]) -> dict[str, int]:
        if any(not name for name in value):
            raise ValueError("seed names must be non-empty")
        return value
