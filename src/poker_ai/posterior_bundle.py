"""Canonical provenance bundle for ADR-0019 posterior-confidence runs.

The checks in this module are contextual hard gates for posterior DPL v2 runs.
They intentionally do not change the generic :mod:`poker_core.run_manifest`
schema or validators.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from poker_core.dpl_schema import DPL_SCHEMA_VERSION
from poker_core.run_manifest import ArtifactRef, ConfigRef, RunManifest

from .leak import (
    ActionBaselineTable,
    LeakDetector,
    action_baseline_table_payload,
    beta_binomial_upper_tail,
    load_action_baseline_table_payload,
    score_action_leak_candidate,
)
from .observation import ActionStats

ESTIMATOR_CONFIG_NAME = "leak_confidence_estimator"
BASELINE_CONFIG_NAME = "action_baseline_table"
SNAPSHOT_ARTIFACT_NAME = "action_stats_terminal_snapshots"

ESTIMATOR_CONFIG_PATH = "provenance/leak_confidence_estimator.json"
BASELINE_CONFIG_PATH = "provenance/action_baseline_table.json"
SNAPSHOT_ARTIFACT_PATH = "provenance/action_stats_terminal_snapshots.json"


@dataclass(frozen=True)
class PosteriorBundleParts:
    """Canonical bytes and manifest references for one posterior run."""

    artifacts: dict[str, bytes]
    estimator_ref: ConfigRef
    baseline_ref: ConfigRef
    snapshot_ref: ArtifactRef


@dataclass(frozen=True)
class ValidatedPosteriorBundle:
    """Payloads returned after all contextual hard-gate checks pass."""

    manifest: RunManifest
    estimator: dict[str, Any]
    baseline_table: dict[str, Any]
    terminal_snapshots: dict[str, Any]


def canonical_json_bytes(payload: object) -> bytes:
    """Serialize immutable bundle payloads with one canonical byte representation."""
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest of exact stored bytes."""
    return hashlib.sha256(payload).hexdigest()


def build_posterior_bundle_parts(
    detector: LeakDetector,
    stats: tuple[ActionStats, ...] | list[ActionStats],
    *,
    opponent_id: str,
    horizon: int,
    seed: int,
) -> PosteriorBundleParts:
    """Build canonical estimator, baseline, and all-candidate terminal snapshots."""
    if not opponent_id:
        raise ValueError("opponent_id must not be empty")
    if horizon <= 0:
        raise ValueError("horizon must be positive")

    baseline_payload = action_baseline_table_payload(detector.baseline_table)
    baseline_bytes = canonical_json_bytes(baseline_payload)
    baseline_sha = sha256_bytes(baseline_bytes)
    config = detector.config
    estimator_payload = {
        "method_version": config.method_version,
        "alpha0": config.alpha0,
        "beta0": config.beta0,
        "tail": config.tail,
        "tau": config.min_deviation,
        "min_effective_sample_size": config.min_effective_sample_size,
        "detector_min_confidence": config.min_confidence,
        "rule_exploit_min_confidence": config.rule_exploit_min_confidence,
        "nodelock_exploit_min_confidence": config.nodelock_exploit_min_confidence,
        "run_identity": {
            "opponent_ids": [opponent_id],
            "seeds": [seed],
            "horizon": horizon,
            "situation_keys": sorted({item.situation_key for item in stats}),
        },
        "baseline_table": {
            "name": BASELINE_CONFIG_NAME,
            "table_version": detector.baseline_table_version,
            "sha256": baseline_sha,
        },
    }
    estimator_bytes = canonical_json_bytes(estimator_payload)

    records: list[dict[str, Any]] = []
    for item in sorted(stats, key=lambda value: value.situation_key):
        action_counts = dict(sorted(item.action_counts.items()))
        for rule in detector.baseline_table.rules:
            candidate = score_action_leak_candidate(item, rule, config)
            sample_gate = candidate.n >= config.min_effective_sample_size
            deviation_gate = (
                candidate.observed_rate - candidate.baseline_rate >= config.min_deviation
            )
            confidence_gate = candidate.confidence >= config.min_confidence
            records.append(
                {
                    "opponent_id": opponent_id,
                    "rule_id": rule.reason_id,
                    "situation_key": item.situation_key,
                    "horizon": horizon,
                    "seed": seed,
                    "action_counts": action_counts,
                    "action_group": list(rule.action_group),
                    "n": candidate.n,
                    "k": candidate.k,
                    "baseline_rate": candidate.baseline_rate,
                    "tau": candidate.tau,
                    "q": candidate.q,
                    "posterior_confidence": candidate.confidence,
                    "candidate_eligibility": {
                        "structurally_eligible": candidate.structurally_eligible,
                        "sample_gate": sample_gate,
                        "deviation_gate": deviation_gate,
                        "confidence_gate": confidence_gate,
                        "detected": (
                            candidate.structurally_eligible
                            and sample_gate
                            and deviation_gate
                            and confidence_gate
                        ),
                    },
                }
            )
    snapshot_payload = {"schema_version": "1.0.0", "records": records}
    snapshot_bytes = canonical_json_bytes(snapshot_payload)

    return PosteriorBundleParts(
        artifacts={
            ESTIMATOR_CONFIG_PATH: estimator_bytes,
            BASELINE_CONFIG_PATH: baseline_bytes,
            SNAPSHOT_ARTIFACT_PATH: snapshot_bytes,
        },
        estimator_ref=ConfigRef(
            name=ESTIMATOR_CONFIG_NAME,
            role="other",
            path=ESTIMATOR_CONFIG_PATH,
            sha256=sha256_bytes(estimator_bytes),
        ),
        baseline_ref=ConfigRef(
            name=BASELINE_CONFIG_NAME,
            role="baseline_table",
            path=BASELINE_CONFIG_PATH,
            sha256=baseline_sha,
        ),
        snapshot_ref=ArtifactRef(
            name=SNAPSHOT_ARTIFACT_NAME,
            path=SNAPSHOT_ARTIFACT_PATH,
            sha256=sha256_bytes(snapshot_bytes),
        ),
    )


def write_posterior_artifacts(parts: PosteriorBundleParts, bundle_root: Path | str) -> None:
    """Write the three immutable canonical artifacts below ``bundle_root``."""
    root = Path(bundle_root)
    for relative_path, payload in parts.artifacts.items():
        target = _resolve_bundle_path(root, relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != payload:
            raise ValueError(f"refusing to overwrite immutable artifact {relative_path!r}")
        target.write_bytes(payload)


def validate_posterior_bundle(
    manifest: RunManifest,
    bundle_root: Path | str,
) -> ValidatedPosteriorBundle:
    """Apply the ADR-0019 contextual exactly-one, path, hash, and join hard gate."""
    if manifest.versions.dpl_schema_version != DPL_SCHEMA_VERSION:
        raise ValueError("posterior bundle requires the current DPL v2 schema version")

    estimator_ref = _exactly_one_config(manifest, ESTIMATOR_CONFIG_NAME, "other")
    baseline_ref = _exactly_one_config(manifest, BASELINE_CONFIG_NAME, "baseline_table")
    snapshot_ref = _exactly_one_output(manifest, SNAPSHOT_ARTIFACT_NAME)
    if snapshot_ref.sha256 is None:
        raise ValueError("terminal snapshot artifact must carry sha256")

    root = Path(bundle_root)
    estimator = _load_canonical_payload(root, estimator_ref.path, estimator_ref.sha256)
    baseline = _load_canonical_payload(root, baseline_ref.path, baseline_ref.sha256)
    snapshots = _load_canonical_payload(root, snapshot_ref.path, snapshot_ref.sha256)
    if not isinstance(estimator, dict) or not isinstance(baseline, dict):
        raise ValueError("posterior config artifacts must contain JSON objects")
    if not isinstance(snapshots, dict):
        raise ValueError("terminal snapshot artifact must contain a JSON object")

    baseline_table = load_action_baseline_table_payload(baseline)
    baseline_version = baseline_table.table_version
    if baseline_version != manifest.versions.baseline_table_version:
        raise ValueError("manifest and baseline artifact table versions do not match")
    baseline_link = estimator.get("baseline_table")
    expected_link = {
        "name": BASELINE_CONFIG_NAME,
        "table_version": baseline_version,
        "sha256": baseline_ref.sha256,
    }
    if baseline_link != expected_link:
        raise ValueError("estimator-to-baseline name/version/hash reference does not match")
    _validate_estimator_payload(estimator)
    _validate_snapshot_join(manifest, snapshots, baseline_table, estimator)
    return ValidatedPosteriorBundle(manifest, estimator, baseline, snapshots)


def load_posterior_run_bundle(manifest_path: Path | str) -> ValidatedPosteriorBundle:
    """Load a manifest and fail closed unless its posterior bundle is complete."""
    path = Path(manifest_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read posterior manifest {path}") from exc
    manifest = RunManifest.model_validate(payload)
    return validate_posterior_bundle(manifest, path.parent)


def _exactly_one_config(manifest: RunManifest, name: str, role: str) -> ConfigRef:
    matches = [item for item in manifest.configs if item.name == name]
    if len(matches) != 1:
        raise ValueError(f"posterior manifest requires exactly one config named {name!r}")
    if matches[0].role != role:
        raise ValueError(f"posterior config {name!r} must have role {role!r}")
    return matches[0]


def _exactly_one_output(manifest: RunManifest, name: str) -> ArtifactRef:
    matches = [item for item in manifest.outputs if item.name == name]
    if len(matches) != 1:
        raise ValueError(f"posterior manifest requires exactly one output named {name!r}")
    return matches[0]


def _resolve_bundle_path(root: Path, relative_path: str) -> Path:
    if not relative_path or "\\" in relative_path or ":" in relative_path:
        raise ValueError(f"bundle path must be a relative POSIX path, got {relative_path!r}")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise ValueError(f"bundle path escapes or is not normalized: {relative_path!r}")
    resolved_root = root.resolve()
    target = resolved_root.joinpath(*pure.parts).resolve()
    try:
        target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"bundle path escapes root: {relative_path!r}") from exc
    return target


def _load_canonical_payload(root: Path, relative_path: str, expected_sha: str) -> object:
    target = _resolve_bundle_path(root, relative_path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ValueError(f"required posterior artifact is unreadable: {relative_path!r}") from exc
    if sha256_bytes(raw) != expected_sha:
        raise ValueError(f"posterior artifact hash mismatch: {relative_path!r}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"posterior artifact is not valid JSON: {relative_path!r}") from exc
    if canonical_json_bytes(payload) != raw:
        raise ValueError(f"posterior artifact is not canonical JSON: {relative_path!r}")
    return payload


def _validate_estimator_payload(payload: dict[str, Any]) -> None:
    required = {
        "method_version": "beta-binomial-upper-tail-v1",
        "alpha0": 1.0,
        "beta0": 1.0,
        "tail": "upper",
    }
    for key, expected in required.items():
        if payload.get(key) != expected:
            raise ValueError(f"unsupported estimator artifact field {key!r}")
    tau = payload.get("tau")
    if not isinstance(tau, int | float) or not math.isfinite(tau) or not 0.0 < tau < 1.0:
        raise ValueError("estimator artifact tau must be finite and in (0, 1)")
    floor = payload.get("min_effective_sample_size")
    if isinstance(floor, bool) or not isinstance(floor, int) or floor <= 0:
        raise ValueError("estimator artifact sample floor must be positive")
    for key in (
        "detector_min_confidence",
        "rule_exploit_min_confidence",
        "nodelock_exploit_min_confidence",
    ):
        value = payload.get(key)
        if not isinstance(value, int | float) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"estimator artifact {key!r} must be in [0, 1]")


def _validate_snapshot_join(
    manifest: RunManifest,
    snapshots: dict[str, Any],
    baseline: ActionBaselineTable,
    estimator: dict[str, Any],
) -> None:
    if snapshots.get("schema_version") != "1.0.0":
        raise ValueError("unsupported terminal snapshot schema version")
    records = snapshots.get("records")
    if not isinstance(records, list):
        raise ValueError("terminal snapshot records must be a list")
    by_id = {rule.reason_id: rule for rule in baseline.rules}
    run_identity = _validate_run_identity(manifest, estimator)
    expected_opponents = run_identity["opponent_ids"]
    expected_seeds = run_identity["seeds"]
    expected_horizon = run_identity["horizon"]
    expected_situations = run_identity["situation_keys"]

    grouped: dict[tuple[object, ...], set[str]] = {}
    record_keys: set[tuple[object, ...]] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("terminal snapshot record must be an object")
        reason_id = record.get("rule_id")
        if reason_id not in by_id:
            raise ValueError("terminal snapshot rule does not join to baseline table")
        rule = by_id[reason_id]
        situation_key = record.get("situation_key")
        if not isinstance(situation_key, str) or not situation_key:
            raise ValueError("terminal snapshot situation_key must be non-empty")
        expected_group = list(rule.action_group)
        if record.get("action_group") != expected_group:
            raise ValueError("terminal snapshot action group does not match baseline rule")
        expected_baseline = rule.baseline_for(situation_key)
        if record.get("baseline_rate") != expected_baseline:
            raise ValueError("terminal snapshot baseline rate does not match baseline rule")
        counts = record.get("action_counts")
        n = record.get("n")
        k = record.get("k")
        if not isinstance(counts, dict) or any(
            not isinstance(action, str)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for action, count in counts.items()
        ):
            raise ValueError("terminal snapshot action_counts are invalid")
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            raise ValueError("terminal snapshot n must be a non-negative integer")
        if sum(counts.values()) != n:
            raise ValueError("terminal snapshot n does not match total integer action counts")
        expected_k = sum(counts.get(action, 0) for action in expected_group)
        if k != expected_k or not 0 <= expected_k <= n:
            raise ValueError("terminal snapshot k/n do not match integer action counts")

        horizon = record.get("horizon")
        seed = record.get("seed")
        opponent_id = record.get("opponent_id")
        if isinstance(horizon, bool) or not isinstance(horizon, int) or horizon <= 0 or n > horizon:
            raise ValueError("terminal snapshot horizon must be positive and at least n")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("terminal snapshot seed must be an integer")
        if not isinstance(opponent_id, str) or not opponent_id:
            raise ValueError("terminal snapshot opponent_id must be non-empty")
        if horizon != expected_horizon:
            raise ValueError("terminal snapshot horizon does not match canonical run identity")
        if seed not in expected_seeds:
            raise ValueError("terminal snapshot seed does not match manifest run identity")
        if opponent_id not in expected_opponents:
            raise ValueError("terminal snapshot opponent does not match manifest run identity")
        if situation_key not in expected_situations:
            raise ValueError("terminal snapshot situation is not in canonical run identity")

        tau = estimator["tau"]
        q = expected_baseline + tau
        confidence = beta_binomial_upper_tail(
            k=expected_k,
            n=n,
            baseline_rate=expected_baseline,
            tau=tau,
        )
        if record.get("tau") != tau or record.get("q") != q:
            raise ValueError("terminal snapshot tau/q do not match estimator and baseline")
        recorded_confidence = record.get("posterior_confidence")
        if not isinstance(recorded_confidence, int | float) or not math.isclose(
            recorded_confidence,
            confidence,
            rel_tol=0.0,
            abs_tol=1e-15,
        ):
            raise ValueError("terminal snapshot posterior confidence cannot be reconstructed")
        observed_rate = expected_k / n if n else 0.0
        expected_eligibility = {
            "structurally_eligible": 0.0 < q < 1.0,
            "sample_gate": n >= estimator["min_effective_sample_size"],
            "deviation_gate": observed_rate - expected_baseline >= tau,
            "confidence_gate": confidence >= estimator["detector_min_confidence"],
        }
        expected_eligibility["detected"] = all(expected_eligibility.values())
        if record.get("candidate_eligibility") != expected_eligibility:
            raise ValueError("terminal snapshot candidate eligibility cannot be reconstructed")

        group_key = (
            opponent_id,
            situation_key,
            horizon,
            seed,
        )
        record_key = (*group_key, reason_id)
        if record_key in record_keys:
            raise ValueError("terminal snapshot contains a duplicate candidate record")
        record_keys.add(record_key)
        grouped.setdefault(group_key, set()).add(reason_id)
    expected_rule_ids = set(by_id)
    expected_groups = {
        (opponent_id, situation_key, expected_horizon, seed)
        for opponent_id in expected_opponents
        for situation_key in expected_situations
        for seed in expected_seeds
    }
    if set(grouped) != expected_groups:
        raise ValueError("terminal snapshot is missing a canonical run candidate group")
    if any(rule_ids != expected_rule_ids for rule_ids in grouped.values()):
        raise ValueError("terminal snapshot is missing a baseline rule candidate")


def _validate_run_identity(
    manifest: RunManifest,
    estimator: dict[str, Any],
) -> dict[str, Any]:
    identity = estimator.get("run_identity")
    required_keys = {"opponent_ids", "seeds", "horizon", "situation_keys"}
    if not isinstance(identity, dict) or set(identity) != required_keys:
        raise ValueError("estimator run_identity does not match the strict contract")
    opponent_ids = identity["opponent_ids"]
    seeds = identity["seeds"]
    horizon = identity["horizon"]
    situation_keys = identity["situation_keys"]
    if (
        not isinstance(opponent_ids, list)
        or not opponent_ids
        or any(not isinstance(value, str) or not value for value in opponent_ids)
        or len(opponent_ids) != len(set(opponent_ids))
    ):
        raise ValueError("estimator run_identity opponent_ids are invalid")
    if (
        not isinstance(seeds, list)
        or not seeds
        or any(isinstance(value, bool) or not isinstance(value, int) for value in seeds)
        or len(seeds) != len(set(seeds))
    ):
        raise ValueError("estimator run_identity seeds are invalid")
    if isinstance(horizon, bool) or not isinstance(horizon, int) or horizon <= 0:
        raise ValueError("estimator run_identity horizon must be positive")
    if (
        not isinstance(situation_keys, list)
        or not situation_keys
        or any(not isinstance(value, str) or not value for value in situation_keys)
        or situation_keys != sorted(set(situation_keys))
    ):
        raise ValueError("estimator run_identity situation_keys are invalid")

    manifest_opponents = [item.opponent_id for item in manifest.opponents]
    if opponent_ids != manifest_opponents:
        raise ValueError("estimator opponents do not match manifest opponents")
    if seeds != [manifest.seeds["master"]]:
        raise ValueError("estimator seeds do not match the manifest master seed")
    return identity


__all__ = [
    "BASELINE_CONFIG_NAME",
    "ESTIMATOR_CONFIG_NAME",
    "SNAPSHOT_ARTIFACT_NAME",
    "PosteriorBundleParts",
    "ValidatedPosteriorBundle",
    "build_posterior_bundle_parts",
    "canonical_json_bytes",
    "load_posterior_run_bundle",
    "validate_posterior_bundle",
    "write_posterior_artifacts",
]
