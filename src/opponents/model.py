"""Frozen opponent-model generation configuration (ADR-0003)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal, NamedTuple

from ._canonical import parse_canonical_decimal

OpponentSplit = Literal["training", "validation", "test"]

MODEL_CONFIG_SCHEMA_VERSION = "1.0.0"
MODEL_CONFIG_VERSION = "nodelock-opponent-config-v1"
SUPPORTED_SPLITS: tuple[str, ...] = ("training", "validation", "test")
SUPPORTED_LEAK_REASONS: tuple[str, ...] = (
    "LEAK_R001",
    "LEAK_R002",
    "LEAK_R007",
    "LEAK_R008",
)
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class LeakActionMapping(NamedTuple):
    """Canonical action/phase semantics shared by synthesis and consumers."""

    phase: str
    action: str


LEAK_ACTION_MAPPINGS: dict[str, LeakActionMapping] = {
    "LEAK_R001": LeakActionMapping(phase="vs_bet", action="FOLD"),
    "LEAK_R002": LeakActionMapping(phase="vs_bet", action="CALL"),
    "LEAK_R007": LeakActionMapping(phase="vs_check", action="CHECK"),
    "LEAK_R008": LeakActionMapping(phase="vs_check", action="BET"),
}


def leak_action_mapping(reason_id: str) -> LeakActionMapping:
    """Return the single canonical river action mapping for a supported leak."""

    try:
        return LEAK_ACTION_MAPPINGS[reason_id]
    except KeyError as exc:
        raise ValueError(f"unsupported synthetic leak reason {reason_id!r}") from exc


@dataclass(frozen=True, slots=True)
class OpponentModelConfig:
    """Canonical inputs that identify one deterministic synthetic opponent."""

    opponent_id: str
    opponent_version: str
    split: OpponentSplit
    equilibrium_version: str
    equilibrium_artifact_sha256: str
    opponent_position: Literal["OOP", "IP"]
    leak_vector: tuple[tuple[str, str], ...]
    seed: int
    combo_allocation: str = "baseline_scaled"
    lock_mode: str = "HARD"
    unlocked_policy_mode: str = "fix_to_baseline"
    schema_version: str = MODEL_CONFIG_SCHEMA_VERSION
    generator_version: str = MODEL_CONFIG_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "leak_vector", tuple(sorted(self.leak_vector)))
        if self.schema_version != MODEL_CONFIG_SCHEMA_VERSION:
            raise ValueError(f"unsupported opponent config schema_version {self.schema_version!r}")
        if self.generator_version != MODEL_CONFIG_VERSION:
            raise ValueError(f"unsupported opponent generator_version {self.generator_version!r}")
        for name in ("opponent_id", "opponent_version", "equilibrium_version"):
            value = getattr(self, name)
            if not value or not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"{name} must be a lowercase stable identifier")
        if not isinstance(self.equilibrium_artifact_sha256, str) or not _SHA256.fullmatch(
            self.equilibrium_artifact_sha256
        ):
            raise ValueError("equilibrium_artifact_sha256 must be lowercase hexadecimal")
        if self.split not in SUPPORTED_SPLITS:
            raise ValueError(f"unknown opponent split {self.split!r}")
        if self.opponent_position not in ("OOP", "IP"):
            raise ValueError("opponent_position must be 'OOP' or 'IP'")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        if self.combo_allocation != "baseline_scaled":
            raise ValueError("ADR-0003 catalog models require baseline_scaled allocation")
        if self.lock_mode != "HARD":
            raise ValueError("P6-3 catalog models require HARD node locks")
        if self.unlocked_policy_mode != "fix_to_baseline":
            raise ValueError("P6-3 catalog models require fix_to_baseline")

        seen: set[str] = set()
        for reason_id, amount in self.leak_vector:
            if reason_id in seen:
                raise ValueError(f"duplicate leak reason {reason_id!r}")
            seen.add(reason_id)
            if reason_id not in SUPPORTED_LEAK_REASONS:
                raise ValueError(f"unsupported synthetic leak reason {reason_id!r}")
            value = _decimal_amount(amount)
            if not Decimal(0) < value < Decimal(1):
                raise ValueError("leak amounts must be canonical decimal strings in (0, 1)")

    @property
    def leak_amounts(self) -> dict[str, Decimal]:
        """Return the configured positive deltas as exact decimal values."""
        return {reason_id: _decimal_amount(amount) for reason_id, amount in self.leak_vector}

    def canonical_payload(self) -> dict[str, object]:
        """Return the closed-world JSON payload used for identity hashing."""
        return {
            "schema_version": self.schema_version,
            "generator_version": self.generator_version,
            "opponent_id": self.opponent_id,
            "opponent_version": self.opponent_version,
            "split": self.split,
            "equilibrium_version": self.equilibrium_version,
            "equilibrium_artifact_sha256": self.equilibrium_artifact_sha256,
            "opponent_position": self.opponent_position,
            "leak_vector": {reason_id: amount for reason_id, amount in self.leak_vector},
            "combo_allocation": self.combo_allocation,
            "lock_mode": self.lock_mode,
            "unlocked_policy_mode": self.unlocked_policy_mode,
            "seed": self.seed,
        }

    @property
    def config_sha256(self) -> str:
        """Hash the canonical generation config for exact reproduction."""
        encoded = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def model_identity(self) -> tuple[object, ...]:
        """Return the ADR-0003 model identity tuple plus its physical split."""
        return (
            self.equilibrium_version,
            self.equilibrium_artifact_sha256,
            tuple((reason_id, _decimal_amount(amount)) for reason_id, amount in self.leak_vector),
            self.combo_allocation,
            self.seed,
            self.split,
        )

    @classmethod
    def from_payload(cls, payload: object) -> OpponentModelConfig:
        """Strictly parse one catalog JSON object without accepting extra fields."""
        if not isinstance(payload, dict):
            raise ValueError("opponent model config must be a JSON object")
        expected = {
            "schema_version",
            "generator_version",
            "opponent_id",
            "opponent_version",
            "split",
            "equilibrium_version",
            "equilibrium_artifact_sha256",
            "opponent_position",
            "leak_vector",
            "combo_allocation",
            "lock_mode",
            "unlocked_policy_mode",
            "seed",
        }
        if set(payload) != expected:
            raise ValueError(
                "opponent model config fields mismatch: "
                f"missing={sorted(expected - set(payload))}, "
                f"extra={sorted(set(payload) - expected)}"
            )
        leak_vector = payload["leak_vector"]
        if not isinstance(leak_vector, dict) or any(
            not isinstance(reason_id, str) or not isinstance(amount, str)
            for reason_id, amount in leak_vector.items()
        ):
            raise ValueError("leak_vector must map reason IDs to canonical decimal strings")
        return cls(
            schema_version=payload["schema_version"],
            generator_version=payload["generator_version"],
            opponent_id=payload["opponent_id"],
            opponent_version=payload["opponent_version"],
            split=payload["split"],
            equilibrium_version=payload["equilibrium_version"],
            equilibrium_artifact_sha256=payload["equilibrium_artifact_sha256"],
            opponent_position=payload["opponent_position"],
            leak_vector=tuple(leak_vector.items()),
            combo_allocation=payload["combo_allocation"],
            lock_mode=payload["lock_mode"],
            unlocked_policy_mode=payload["unlocked_policy_mode"],
            seed=payload["seed"],
        )


def _decimal_amount(value: str) -> Decimal:
    return parse_canonical_decimal(value, field="leak amount")
