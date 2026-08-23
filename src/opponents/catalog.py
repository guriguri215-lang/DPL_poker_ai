"""Physically separated Training/Validation catalog loader for P6-3."""

from __future__ import annotations

import json
from importlib import metadata
from pathlib import Path

from .model import OpponentModelConfig, OpponentSplit

_DISTRIBUTION_NAME = "poker-xai"
_CATALOG_ANCHOR = "configs/opponents/training/nl-train-r001-d016-s102.opponent.json"


def _default_catalog_root() -> Path:
    """Resolve the tracked catalog in a source tree, sdist, wheel, or installation."""

    repository_root = Path(__file__).resolve().parents[2] / "configs" / "opponents"
    if repository_root.is_dir():
        return repository_root

    try:
        distribution = metadata.distribution(_DISTRIBUTION_NAME)
    except metadata.PackageNotFoundError:
        return repository_root
    anchors = [
        Path(distribution.locate_file(entry)).resolve()
        for entry in distribution.files or ()
        if entry.as_posix().endswith(_CATALOG_ANCHOR)
    ]
    if len(anchors) == 1 and anchors[0].is_file():
        return anchors[0].parents[1]
    return repository_root


DEFAULT_CATALOG_ROOT = _default_catalog_root()


class TestPoolAccessError(RuntimeError):
    """Raised before a normal development path can inspect the Test pool."""


def load_development_catalog(
    split: OpponentSplit,
    *,
    catalog_root: Path | str = DEFAULT_CATALOG_ROOT,
) -> tuple[OpponentModelConfig, ...]:
    """Load Training or Validation configs, rejecting Test before any I/O."""
    if split == "test":
        raise TestPoolAccessError(
            "Test opponent pool is unavailable to normal Training/Validation loaders"
        )
    if split not in ("training", "validation"):
        raise ValueError(f"unknown development split {split!r}")

    split_dir = Path(catalog_root) / split
    if not split_dir.is_dir():
        raise FileNotFoundError(f"opponent catalog split directory does not exist: {split_dir}")
    paths = tuple(sorted(split_dir.glob("*.opponent.json")))
    if not paths:
        raise ValueError(f"opponent catalog split {split!r} is empty")

    configs: list[OpponentModelConfig] = []
    seen_ids: set[str] = set()
    seen_identities: set[tuple[object, ...]] = set()
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot load opponent config {path.name!r}") from exc
        config = OpponentModelConfig.from_payload(payload)
        if config.split != split:
            raise ValueError(
                f"opponent config {path.name!r} declares split {config.split!r}, expected {split!r}"
            )
        if config.opponent_id in seen_ids:
            raise ValueError(f"duplicate opponent_id {config.opponent_id!r} in {split} catalog")
        if config.model_identity in seen_identities:
            raise ValueError(f"duplicate model identity in {split} catalog")
        seen_ids.add(config.opponent_id)
        seen_identities.add(config.model_identity)
        configs.append(config)
    return tuple(configs)


def load_training_catalog(
    *, catalog_root: Path | str = DEFAULT_CATALOG_ROOT
) -> tuple[OpponentModelConfig, ...]:
    """Load the physically isolated Training catalog."""
    return load_development_catalog("training", catalog_root=catalog_root)


def load_validation_catalog(
    *, catalog_root: Path | str = DEFAULT_CATALOG_ROOT
) -> tuple[OpponentModelConfig, ...]:
    """Load the physically isolated Validation catalog."""
    return load_development_catalog("validation", catalog_root=catalog_root)
