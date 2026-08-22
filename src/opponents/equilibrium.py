"""Strict frozen-equilibrium artifact registry for opponent synthesis."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from poker_core.range_model import Range
from poker_solver.game import Game
from poker_solver.river_tree import RiverBettingConfig, build_river_game
from poker_solver.strategy import StrategyProfile, validate_profile

from ._canonical import parse_canonical_decimal

EQUILIBRIUM_ARTIFACT_SCHEMA_VERSION = "1.0.0"
EQUILIBRIUM_ARTIFACT_TYPE = "frozen-equilibrium"
DEFAULT_EQUILIBRIUM_ROOT = (
    Path(__file__).resolve().parents[2] / "configs" / "opponents" / "equilibria"
)

_VERSION = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_FIELDS = {
    "schema_version",
    "artifact_type",
    "equilibrium_version",
    "game",
    "strategy",
    "solver",
    "artifact_sha256",
}
_GAME_FIELDS = {
    "builder",
    "builder_version",
    "pot",
    "bet_fraction",
    "board",
    "oop_range",
    "ip_range",
}
_SOLVER_FIELDS = {
    "algorithm",
    "implementation",
    "iterations",
    "average_delay",
}


@dataclass(frozen=True, slots=True)
class FrozenEquilibrium:
    """A content-addressed game/profile pair resolved from a stable version."""

    equilibrium_version: str
    artifact_sha256: str
    bet_fraction: float
    game: Game
    strategy: StrategyProfile
    solver_provenance: dict[str, object]


def equilibrium_artifact_sha256(payload: object) -> str:
    """Hash all artifact content except the self-declared digest field."""
    if not isinstance(payload, dict):
        raise ValueError("equilibrium artifact must be a JSON object")
    content = {key: value for key, value in payload.items() if key != "artifact_sha256"}
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


def load_frozen_equilibrium(
    equilibrium_version: str,
    *,
    expected_sha256: str,
    equilibrium_root: Path | str = DEFAULT_EQUILIBRIUM_ROOT,
) -> FrozenEquilibrium:
    """Resolve one version and reject any artifact whose content digest differs."""
    if not isinstance(equilibrium_version, str) or not _VERSION.fullmatch(equilibrium_version):
        raise ValueError("equilibrium_version must be a lowercase stable identifier")
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise ValueError("expected equilibrium artifact SHA-256 must be lowercase hexadecimal")

    path = Path(equilibrium_root) / f"{equilibrium_version}.equilibrium.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load equilibrium artifact {path.name!r}") from exc
    _require_fields(payload, _ARTIFACT_FIELDS, "equilibrium artifact")

    if payload["schema_version"] != EQUILIBRIUM_ARTIFACT_SCHEMA_VERSION:
        raise ValueError("unsupported equilibrium artifact schema_version")
    if payload["artifact_type"] != EQUILIBRIUM_ARTIFACT_TYPE:
        raise ValueError("unsupported equilibrium artifact type")
    if payload["equilibrium_version"] != equilibrium_version:
        raise ValueError("equilibrium artifact version does not match registry path")
    declared_sha256 = payload["artifact_sha256"]
    if not isinstance(declared_sha256, str) or not _SHA256.fullmatch(declared_sha256):
        raise ValueError("equilibrium artifact SHA-256 must be lowercase hexadecimal")
    actual_sha256 = equilibrium_artifact_sha256(payload)
    if declared_sha256 != actual_sha256:
        raise ValueError("equilibrium artifact content does not match its declared SHA-256")
    if actual_sha256 != expected_sha256:
        raise ValueError("equilibrium artifact content does not match opponent config SHA-256")

    game, bet_fraction = _build_game(payload["game"])
    strategy = _parse_strategy(payload["strategy"])
    validate_profile(game, strategy)
    solver = payload["solver"]
    _require_fields(solver, _SOLVER_FIELDS, "equilibrium solver provenance")
    if not all(
        isinstance(solver[key], str) and solver[key] for key in ("algorithm", "implementation")
    ):
        raise ValueError("equilibrium solver identifiers must be non-empty strings")
    for key in ("iterations", "average_delay"):
        if isinstance(solver[key], bool) or not isinstance(solver[key], int) or solver[key] < 0:
            raise ValueError(f"equilibrium solver {key} must be a non-negative integer")

    return FrozenEquilibrium(
        equilibrium_version=equilibrium_version,
        artifact_sha256=actual_sha256,
        bet_fraction=bet_fraction,
        game=game,
        strategy=strategy,
        solver_provenance=dict(solver),
    )


def _build_game(payload: object) -> tuple[Game, float]:
    _require_fields(payload, _GAME_FIELDS, "equilibrium game")
    if payload["builder"] != "poker_solver.river_tree.build_river_game":
        raise ValueError("unsupported equilibrium game builder")
    if payload["builder_version"] != "river-single-bet-v1":
        raise ValueError("unsupported equilibrium game builder_version")
    if not isinstance(payload["board"], str) or not payload["board"]:
        raise ValueError("equilibrium game board must be a non-empty string")
    pot = parse_canonical_decimal(payload["pot"], field="equilibrium game pot")
    bet_fraction = parse_canonical_decimal(
        payload["bet_fraction"], field="equilibrium game bet_fraction"
    )
    if pot <= 0 or bet_fraction <= 0:
        raise ValueError("equilibrium game pot and bet_fraction must be positive")
    parsed_bet_fraction = float(bet_fraction)
    return (
        build_river_game(
            RiverBettingConfig(pot=float(pot), bet_fraction=parsed_bet_fraction),
            _parse_range(payload["oop_range"], field="equilibrium game oop_range"),
            _parse_range(payload["ip_range"], field="equilibrium game ip_range"),
            payload["board"],
        ),
        parsed_bet_fraction,
    )


def _parse_range(payload: object, *, field: str) -> Range:
    if not isinstance(payload, dict) or not payload:
        raise ValueError(f"{field} must be a non-empty JSON object")
    weights: dict[str, float] = {}
    for combo, token in payload.items():
        if not isinstance(combo, str) or not combo:
            raise ValueError(f"{field} combo IDs must be non-empty strings")
        weight = parse_canonical_decimal(token, field=f"{field} weight")
        if weight <= 0:
            raise ValueError(f"{field} weights must be positive")
        weights[combo] = float(weight)
    range_ = Range(weights)
    if set(range_.weights) != set(weights):
        raise ValueError(f"{field} combo IDs must use canonical spelling")
    return range_


def _parse_strategy(payload: object) -> StrategyProfile:
    if not isinstance(payload, dict) or not payload:
        raise ValueError("equilibrium strategy must be a non-empty JSON object")
    profile: StrategyProfile = {}
    for infoset, distribution in payload.items():
        if not isinstance(infoset, str) or not infoset:
            raise ValueError("equilibrium strategy infosets must be non-empty strings")
        if not isinstance(distribution, dict) or not distribution:
            raise ValueError("equilibrium strategy distributions must be non-empty objects")
        parsed_distribution: dict[str, float] = {}
        for action, token in distribution.items():
            if not isinstance(action, str) or not action:
                raise ValueError("equilibrium strategy actions must be non-empty strings")
            probability = parse_canonical_decimal(token, field="equilibrium strategy probability")
            if not 0 <= probability <= 1:
                raise ValueError("equilibrium strategy probabilities must be in [0, 1]")
            parsed_distribution[action] = float(probability)
        profile[infoset] = parsed_distribution
    return profile


def _require_fields(payload: object, expected: set[str], label: str) -> None:
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    if set(payload) != expected:
        raise ValueError(
            f"{label} fields mismatch: missing={sorted(expected - set(payload))}, "
            f"extra={sorted(set(payload) - expected)}"
        )
