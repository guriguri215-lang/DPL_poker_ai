"""RunManifest -- the reproducibility contract for a session or experiment.

A manifest bundles every version, seed and config reference needed to reproduce
a run exactly (REV-20260702 M-7). Sessions and experiments are expected to be
launched *through* a manifest so that a run can always be replayed and audited,
and so the paper's results are traceable to a frozen configuration.

Structural validation is kept separate from *compatibility* checking: a manifest
records the ontology/version strings it ran under and always parses, so old
manifests stay auditable; :meth:`RunManifest.ontology_matches_current` reports
whether it lines up with the currently loaded ontology.

Raw logs and solver outputs live outside git; the manifest plus summary stats
are the tracked, portable record of what produced them.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .dpl_schema import DPL_SCHEMA_VERSION
from .reason_ontology import get_ontology

#: Current RunManifest schema version.
MANIFEST_SCHEMA_VERSION = "1.0.0"

#: Sentinel allowed in place of a real commit SHA (e.g. an uncommitted dev run).
UNKNOWN_COMMIT = "unknown"

#: Seed names every reproducible run must pin (the root seed all others derive from).
REQUIRED_SEEDS: tuple[str, ...] = ("master",)

#: Train / validation / test split of the opponent-parameter space (REV 5.3).
DataSplit = Literal["training", "validation", "test"]

#: Role a referenced config plays in a run (auditable per phase).
ConfigRole = Literal[
    "scenario", "cluster_def", "strategy_table", "baseline_table", "solver", "other"
]

#: A lowercase hex SHA-256 digest.
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CodeProvenance(BaseModel):
    """Identifies the exact code and invocation that produced a run."""

    model_config = ConfigDict(extra="forbid")

    git_commit: str
    git_dirty: bool = False
    package_version: str = Field(min_length=1)
    python_version: str = Field(min_length=1)
    entrypoint: str = Field(min_length=1)
    argv: list[str] = Field(default_factory=list)

    @field_validator("git_commit")
    @classmethod
    def _valid_git_commit(cls, value: str) -> str:
        if value == UNKNOWN_COMMIT or re.fullmatch(r"[0-9a-f]{40}", value):
            return value
        raise ValueError(
            f"git_commit must be a 40-char hex SHA or {UNKNOWN_COMMIT!r}, got {value!r}"
        )


class ComponentVersions(BaseModel):
    """Versions of every contract/definition a run depends on.

    These are recorded verbatim (any version string is accepted) so that old
    manifests remain loadable; compatibility with the current build is checked
    separately via :meth:`RunManifest.ontology_matches_current`.
    """

    model_config = ConfigDict(extra="forbid")

    dpl_schema_version: str = DPL_SCHEMA_VERSION
    reason_ontology_version: str = Field(min_length=1)
    cluster_def_version: str = Field(min_length=1)
    strategy_table_version: str = Field(min_length=1)
    baseline_table_version: str = Field(min_length=1)


class ConfigRef(BaseModel):
    """A pinned reference to a config file (role + path + content hash)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    role: ConfigRole
    path: str = Field(min_length=1)
    sha256: Sha256


class ArtifactRef(BaseModel):
    """A reference to an output artefact produced by the run.

    ``sha256`` is optional because it is only known once the artefact exists.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    path: str = Field(min_length=1)
    sha256: Sha256 | None = None


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
    seeds: dict[str, int]
    configs: list[ConfigRef] = Field(default_factory=list)
    opponents: list[OpponentRef] = Field(default_factory=list)
    outputs: list[ArtifactRef] = Field(default_factory=list)

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
    def _validate_seeds(cls, value: dict[str, int]) -> dict[str, int]:
        if any(not name for name in value):
            raise ValueError("seed names must be non-empty")
        missing = [name for name in REQUIRED_SEEDS if name not in value]
        if missing:
            raise ValueError(f"seeds must include required seed(s): {missing}")
        return value

    def ontology_matches_current(self) -> bool:
        """True if the recorded ontology version matches the loaded ontology.

        Use this for compatibility checks; it is intentionally separate from
        (structural) parsing so historical manifests can still be inspected.
        """
        return self.versions.reason_ontology_version == get_ontology().ontology_version
