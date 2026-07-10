"""Deterministic synthetic opponents and split catalog access (P6-3)."""

from .catalog import (
    DEFAULT_CATALOG_ROOT,
    TestPoolAccessError,
    load_development_catalog,
    load_training_catalog,
    load_validation_catalog,
)
from .equilibrium import (
    DEFAULT_EQUILIBRIUM_ROOT,
    FrozenEquilibrium,
    equilibrium_artifact_sha256,
    load_frozen_equilibrium,
)
from .ground_truth import TrueLeakMeasurement, extract_true_leaks
from .model import MODEL_CONFIG_VERSION, OpponentModelConfig, OpponentSplit
from .synthesis import LeakTarget, SynthesizedOpponent, synthesize_opponent

__all__ = [
    "DEFAULT_CATALOG_ROOT",
    "DEFAULT_EQUILIBRIUM_ROOT",
    "FrozenEquilibrium",
    "LeakTarget",
    "MODEL_CONFIG_VERSION",
    "OpponentModelConfig",
    "OpponentSplit",
    "SynthesizedOpponent",
    "TestPoolAccessError",
    "TrueLeakMeasurement",
    "extract_true_leaks",
    "equilibrium_artifact_sha256",
    "load_development_catalog",
    "load_frozen_equilibrium",
    "load_training_catalog",
    "load_validation_catalog",
    "synthesize_opponent",
]
