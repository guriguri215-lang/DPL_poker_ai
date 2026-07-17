"""Fail-closed production CLI orchestration for the approved P6-7 Training run.

The CLI intentionally exposes no experiment-axis options. Candidates, opponents,
horizons, repetitions, seeds, sampling, metrics, and selection are reconstructed
from the approved versioned contracts. Production execution is only reachable
after the repository and output-directory preflight gates pass.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opponents import load_training_catalog
from opponents.ground_truth import extract_independent_action_rates
from opponents.synthesis import synthesize_opponent
from poker_ai.leak import BET_ACTIONS
from poker_core.dpl_schema import DPL_SCHEMA_VERSION
from poker_core.reason_ontology import get_ontology
from poker_solver.game import Chance, Decision, Node, Terminal

from .calibration import CALIBRATION_EVALUATOR_VERSION, EXACT_EV_INPUT_VERSION
from .contracts import (
    ROOT_MANIFEST_SCHEMA_VERSION,
    canonical_json_bytes,
    load_phase6_contract_bundle,
    sha256_bytes,
)
from .exact_ev import (
    EV_CONSISTENCY_ABS_TOLERANCE_WIRE,
    EV_DENOMINATOR_ABS_TOLERANCE_WIRE,
)
from .p6_7 import (
    EXECUTION_SAMPLER_VERSION,
    REPETITION_SEEDS,
    sampling_contract_payload,
    validate_sampling_contract,
)
from .production_inputs import (
    EXPLOIT_PROVIDER_VERSION,
    GROUND_TRUTH_EXTRACTOR_VERSION,
    PRODUCTION_INPUT_BUILDER_VERSION,
    build_production_observation_registry,
)
from .training_backend import (
    PRODUCTION_TRAINING_BACKEND_ID,
    PRODUCTION_TRAINING_BACKEND_VERSION,
    ProductionTrainingExecutionBackend,
)
from .training_runner import (
    HORIZONS,
    TRAINING_EXECUTION_ADAPTER_VERSION,
    TRAINING_RUNNER_VERSION,
    TrainingArtifactBundle,
    TrainingBatchPlan,
    build_training_batch_plan,
    run_training_execution_adapter,
    verify_training_artifact_bundle,
    write_training_artifact_bundle,
)

PRODUCTION_TRAINING_CLI_VERSION = "phase6-production-training-cli-v1"
PRODUCTION_TRAINING_RUN_SCHEMA_VERSION = "phase6-production-training-run-manifest-v1"
PRODUCTION_TRAINING_ENTRYPOINT = "cli/phase6_training_v1.py"
PRODUCTION_TRAINING_RUN_MANIFEST = "phase6_training_run_manifest.json"
CANONICALIZER_VERSION = "adr-0020-canonical-json-v1"
PRODUCTION_BASELINE_TABLE_VERSION = "phase6-frozen-r008-baseline-v1"
PRODUCTION_ESTIMATOR_VERSION = "beta-binomial-upper-tail-v1"
PRODUCTION_SAFETY_MIXER_VERSION = "phase6-linear-safety-mixer-v1"

REPO_ROOT = Path(__file__).resolve().parents[2]

_SHA256_CHARS = frozenset("0123456789abcdef")
_BUNDLE_OUTPUT_NAMES = {
    "training_batch_manifest",
    "terminal_candidate_snapshots",
    "hero_policy_snapshots",
    "exact_ev_cells",
    "calibration_cells",
    "aggregate_metrics",
    "training_selection_report",
}
_EXPECTED_CARDINALITY = {
    "candidate_count": 16,
    "opponent_count": 9,
    "horizon_count": 3,
    "repetition_count": 30,
    "session_count": 12960,
    "stream_root_count": 3240,
}


@dataclass(frozen=True, slots=True)
class RepositoryState:
    commit: str
    dirty: bool


def _sha256(value: str) -> str:
    if len(value) != 64 or any(character not in _SHA256_CHARS for character in value):
        raise argparse.ArgumentTypeError("value must be a lowercase 64-character SHA-256")
    return value


def _git_commit(value: str) -> str:
    if len(value) != 40 or any(character not in _SHA256_CHARS for character in value):
        raise argparse.ArgumentTypeError("value must be a lowercase 40-character git commit")
    return value


def _parse_args(raw_argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True, type=_git_commit)
    parser.add_argument("--phase6-contract-manifest", required=True, type=Path)
    parser.add_argument("--phase6-contract-manifest-sha256", required=True, type=_sha256)
    parser.add_argument("--dependency-lock", required=True, type=Path)
    parser.add_argument("--dependency-lock-sha256", required=True, type=_sha256)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(raw_argv)


def _git(repo_root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={repo_root.as_posix()}",
                *arguments,
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        raise RuntimeError("cannot verify the production repository state") from exc
    return completed.stdout


def _read_repository_state(repo_root: Path) -> RepositoryState:
    commit = _git(repo_root, "rev-parse", "HEAD").strip()
    _validate_git_commit(commit, "actual git commit")
    dirty = bool(_git(repo_root, "status", "--porcelain=v1", "--untracked-files=all").strip())
    return RepositoryState(commit, dirty)


def _require_repository_state(
    repo_root: Path,
    expected_commit: str,
) -> RepositoryState:
    state = _read_repository_state(repo_root)
    if state.commit != expected_commit:
        raise RuntimeError("actual git commit does not match --expected-commit")
    if state.dirty:
        raise RuntimeError("production Training requires git dirty=false")
    return state


def _resolve_repo_input(repo_root: Path, supplied: Path, label: str) -> Path:
    candidate = supplied if supplied.is_absolute() else repo_root / supplied
    resolved = candidate.resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} must remain within the repository root") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} must be an existing regular file")
    return resolved


def _input_reference(
    repo_root: Path,
    path: Path,
    expected_sha256: str,
    label: str,
) -> dict[str, str]:
    actual = sha256_bytes(path.read_bytes())
    if actual != expected_sha256:
        raise ValueError(f"{label} hash does not match its expected SHA-256")
    return {
        "path": path.relative_to(repo_root.resolve()).as_posix(),
        "sha256": actual,
    }


def _resolve_fresh_output(repo_root: Path, supplied: Path) -> Path:
    candidate = supplied if supplied.is_absolute() else repo_root / supplied
    resolved = candidate.resolve()
    if resolved == repo_root.resolve() or repo_root.resolve() / ".git" in (
        resolved,
        *resolved.parents,
    ):
        raise ValueError("output directory must not be the repository root or .git")
    if os.path.lexists(resolved):
        raise FileExistsError("production Training output directory must be fresh")
    if not resolved.parent.is_dir():
        raise ValueError("production Training output parent must already exist")
    return resolved


def _approved_sampling_contract() -> dict[str, object]:
    configs = tuple(sorted(load_training_catalog(), key=lambda item: item.opponent_id))
    if len(configs) != 9 or any(item.split != "training" for item in configs):
        raise ValueError("production CLI requires exactly nine approved Training opponents")
    registries = tuple(
        build_production_observation_registry(synthesize_opponent(config=config).game)
        for config in configs
    )
    registry = registries[0]
    if any(candidate != registry for candidate in registries[1:]):
        raise ValueError("approved Training opponents do not share one frozen river registry")
    return sampling_contract_payload(
        observation_registry_version=registry.registry_version,
        observation_registry_sha256=registry.sha256,
    )


def _validate_approved_plan(plan: TrainingBatchPlan, sampling_contract: dict[str, object]) -> None:
    validate_sampling_contract(sampling_contract)
    rebuilt = build_training_batch_plan(sampling_contract)
    if plan != rebuilt:
        raise ValueError("Training batch plan does not reconstruct from approved inputs")
    manifest = plan.manifest
    if (
        manifest.get("split") != "training"
        or manifest.get("horizons") != list(HORIZONS)
        or manifest.get("repetitions")
        != [
            {"master_seed": seed, "repetition_id": repetition_id}
            for repetition_id, seed in REPETITION_SEEDS
        ]
        or manifest.get("expected_cardinality") != _EXPECTED_CARDINALITY
        or manifest.get("performance_based_top_n") is not None
        or len(plan.candidates) != 16
        or len(plan.sessions) != 12960
    ):
        raise ValueError("Training batch plan is outside the approved 12,960-session product")


def _runtime_payload() -> dict[str, str]:
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_compiler": platform.python_compiler(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
    }


def _component_entry(name: str, version: str, content: object) -> dict[str, str]:
    return {
        "name": name,
        "version": version,
        "sha256": sha256_bytes(canonical_json_bytes(content)),
    }


def _game_sha256(node: Node, *, game_name: str) -> str:
    def payload(current: Node) -> dict[str, object]:
        if isinstance(current, Terminal):
            return {"kind": "terminal", "payoff_binary64_hex": float(current.payoff).hex()}
        if isinstance(current, Chance):
            return {
                "kind": "chance",
                "branches": [
                    {
                        "probability_binary64_hex": probability.hex(),
                        "label": label,
                        "child": payload(child),
                    }
                    for probability, child, label in current.branches
                ],
            }
        assert isinstance(current, Decision)
        return {
            "kind": "decision",
            "player": current.player,
            "infoset": current.infoset,
            "actions": list(current.actions),
            "children": [payload(child) for child in current.children],
        }

    return sha256_bytes(canonical_json_bytes({"name": game_name, "root": payload(node)}))


def _strategy_sha256(strategy: dict[str, dict[str, float]]) -> str:
    content = [
        {
            "infoset": infoset,
            "actions": [
                {"action": action, "probability_binary64_hex": probability.hex()}
                for action, probability in sorted(strategy[infoset].items())
            ],
        }
        for infoset in sorted(strategy)
    ]
    return sha256_bytes(canonical_json_bytes(content))


def _decimal_wire(value: object) -> str:
    token = format(value, "f")
    if "." in token:
        token = token.rstrip("0").rstrip(".")
    return token or "0"


def _component_provenance(
    plan: TrainingBatchPlan,
    *,
    contract_manifest_sha256: str,
) -> list[dict[str, str]]:
    _validate_sha256(contract_manifest_sha256, "Phase 6 contract manifest hash")
    ontology = get_ontology()
    configs = tuple(sorted(load_training_catalog(), key=lambda item: item.opponent_id))
    if len(configs) != 9 or any(config.split != "training" for config in configs):
        raise ValueError("component provenance requires nine approved Training opponents")
    opponents = tuple(synthesize_opponent(config=config) for config in configs)
    game_hashes = {
        _game_sha256(opponent.game.root, game_name=opponent.game.name) for opponent in opponents
    }
    if len(game_hashes) != 1:
        raise ValueError("approved Training opponents do not share one frozen game")
    equilibrium_entries = sorted(
        {
            (opponent.equilibrium_version, opponent.equilibrium_artifact_sha256)
            for opponent in opponents
        }
    )
    if len(equilibrium_entries) != 1:
        raise ValueError("approved Training opponents do not share one frozen equilibrium")
    equilibrium_version, _equilibrium_sha256 = equilibrium_entries[0]
    gto = [opponent for opponent in opponents if not opponent.config.leak_vector]
    if len(gto) != 1:
        raise ValueError("component provenance requires one GTO negative control")
    baseline = extract_independent_action_rates(
        gto[0].game,
        gto[0].equilibrium_strategy,
        gto[0].config,
        reason_ids=("LEAK_R008",),
    )[0]
    baseline_payload = {
        "table_version": PRODUCTION_BASELINE_TABLE_VERSION,
        "reason_id": "LEAK_R008",
        "situation_key": "river_vs_check",
        "action_group": list(BET_ACTIONS),
        "baseline_rate": _decimal_wire(baseline.action_rate),
    }
    estimator_index = [
        {
            "candidate_id": candidate.candidate_id,
            "method_version": PRODUCTION_ESTIMATOR_VERSION,
            "alpha0": "1",
            "beta0": "1",
            "tail": "upper",
            "tau": "0.25",
            "sample_floor": candidate.sample_floor,
            "detector_threshold": candidate.detector_confidence,
            "provider_threshold": candidate.provider_confidence,
        }
        for candidate in plan.candidates
    ]
    opponent_artifacts = [
        {
            "opponent_id": opponent.config.opponent_id,
            "opponent_version": opponent.config.opponent_version,
            "config": opponent.config.canonical_payload(),
            "config_sha256": opponent.config_sha256,
            "equilibrium_artifact_sha256": opponent.equilibrium_artifact_sha256,
            "strategy_sha256": _strategy_sha256(opponent.strategy),
        }
        for opponent in opponents
    ]
    versioned_components = [
        ("canonicalizer", CANONICALIZER_VERSION),
        ("dpl_schema", DPL_SCHEMA_VERSION),
        ("training_runner", TRAINING_RUNNER_VERSION),
        ("training_execution_adapter", TRAINING_EXECUTION_ADAPTER_VERSION),
        (PRODUCTION_TRAINING_BACKEND_ID, PRODUCTION_TRAINING_BACKEND_VERSION),
        ("execution_sampler", EXECUTION_SAMPLER_VERSION),
        ("exploit_provider", EXPLOIT_PROVIDER_VERSION),
        ("production_input_builder", PRODUCTION_INPUT_BUILDER_VERSION),
        ("ground_truth_extractor", GROUND_TRUTH_EXTRACTOR_VERSION),
        ("calibration_evaluator", CALIBRATION_EVALUATOR_VERSION),
    ]
    components = [
        _component_entry(name, version, {"name": name, "version": version})
        for name, version in versioned_components
    ]
    components.extend(
        (
            {
                "name": "phase6_evaluation_contract",
                "version": ROOT_MANIFEST_SCHEMA_VERSION,
                "sha256": contract_manifest_sha256,
            },
            _component_entry(
                "reason_ontology",
                ontology.ontology_version,
                ontology.model_dump(mode="json"),
            ),
            {
                "name": "frozen_training_game",
                "version": equilibrium_version,
                "sha256": next(iter(game_hashes)),
            },
            {
                "name": "frozen_equilibrium_artifact",
                "version": equilibrium_version,
                "sha256": _equilibrium_sha256,
            },
            _component_entry(
                "approved_opponent_artifacts",
                configs[0].generator_version,
                opponent_artifacts,
            ),
            _component_entry(
                "approved_training_catalog",
                configs[0].generator_version,
                [config.canonical_payload() for config in configs],
            ),
            _component_entry(
                "approved_candidate_grid",
                plan.candidates[0].canonical_payload()["grid_version"],
                plan.manifest["candidates"],
            ),
            _component_entry(
                "baseline_table",
                PRODUCTION_BASELINE_TABLE_VERSION,
                baseline_payload,
            ),
            _component_entry(
                "estimator_config_index",
                PRODUCTION_ESTIMATOR_VERSION,
                estimator_index,
            ),
            _component_entry(
                "safety_mixer",
                PRODUCTION_SAFETY_MIXER_VERSION,
                {
                    "formula": "final=(1-alpha)*base+alpha*exploit",
                    "action_union": "stable",
                    "candidate_alpha": [
                        {
                            "candidate_id": candidate.candidate_id,
                            "safety_alpha": candidate.safety_alpha,
                        }
                        for candidate in plan.candidates
                    ],
                },
            ),
            _component_entry(
                "exact_ev_evaluator",
                EXACT_EV_INPUT_VERSION,
                {
                    "implementation": "phase6.exact_ev.evaluate_exact_ev",
                    "hero_player": 0,
                    "consistency_abs_tolerance": EV_CONSISTENCY_ABS_TOLERANCE_WIRE,
                    "denominator_abs_tolerance": EV_DENOMINATOR_ABS_TOLERANCE_WIRE,
                    "paths": ["production", "independent_leaves"],
                },
            ),
        )
    )
    if len({component["name"] for component in components}) != len(components):
        raise ValueError("component provenance names must be unique")
    return components


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("run timestamps must be timezone-aware UTC")
    return value.isoformat().replace("+00:00", "Z")


def _run_manifest_payload(
    *,
    raw_argv: list[str],
    repository_state: RepositoryState,
    expected_commit: str,
    contract_reference: dict[str, str],
    dependency_reference: dict[str, str],
    sampling_contract: dict[str, object],
    plan: TrainingBatchPlan,
    bundle: TrainingArtifactBundle,
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, object]:
    return {
        "schema_version": PRODUCTION_TRAINING_RUN_SCHEMA_VERSION,
        "artifact_type": "phase6_training_run_manifest",
        "cli_version": PRODUCTION_TRAINING_CLI_VERSION,
        "status": "completed_and_verified",
        "split": "training",
        "git": {
            "expected_commit": expected_commit,
            "actual_commit": repository_state.commit,
            "dirty": repository_state.dirty,
        },
        "invocation": {
            "entrypoint": PRODUCTION_TRAINING_ENTRYPOINT,
            "argv": raw_argv,
        },
        "runtime": _runtime_payload(),
        "timing": {
            "started_at_utc": _iso_utc(started_at),
            "finished_at_utc": _iso_utc(finished_at),
        },
        "inputs": {
            "phase6_contract_manifest": contract_reference,
            "dependency_lock": dependency_reference,
            "sampling_contract": {
                "payload": sampling_contract,
                "sha256": sha256_bytes(canonical_json_bytes(sampling_contract)),
            },
            "training_batch_manifest_sha256": plan.manifest_sha256,
        },
        "approved_plan": {
            "expected_cardinality": _EXPECTED_CARDINALITY,
            "horizons": list(HORIZONS),
            "repetitions": [
                {"master_seed": seed, "repetition_id": repetition_id}
                for repetition_id, seed in REPETITION_SEEDS
            ],
            "performance_based_top_n": None,
        },
        "components": _component_provenance(
            plan,
            contract_manifest_sha256=contract_reference["sha256"],
        ),
        "outputs": bundle.references,
    }


def _write_run_manifest(output_root: Path, payload: dict[str, object]) -> Path:
    path = output_root / PRODUCTION_TRAINING_RUN_MANIFEST
    raw = canonical_json_bytes(payload)
    with path.open("xb") as stream:
        stream.write(raw)
    return path


def _load_canonical_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Training run manifest is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError("Training run manifest bytes are not canonical")
    return payload, raw


def _resolve_manifest_input(repo_root: Path, reference: object, label: str) -> Path:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ValueError(f"{label} reference is not closed-world")
    _validate_sha256(reference["sha256"], f"{label} hash")
    path_value = reference["path"]
    if not isinstance(path_value, str) or not path_value or "\\" in path_value:
        raise ValueError(f"{label} path must be a POSIX repository-relative path")
    return _resolve_repo_input(repo_root, Path(path_value), label)


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _validate_git_commit(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase 40-character git commit")
    return value


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} must be UTC")
    return parsed


def _verify_production_backend_identity(
    root: Path,
    outputs: dict[str, Any],
    components: object,
) -> None:
    expected_identity = {
        "backend_id": PRODUCTION_TRAINING_BACKEND_ID,
        "backend_version": PRODUCTION_TRAINING_BACKEND_VERSION,
    }
    if not isinstance(components, list):
        raise ValueError("Training run component provenance must be a list")
    backend_components = [
        component
        for component in components
        if isinstance(component, dict) and component.get("name") == PRODUCTION_TRAINING_BACKEND_ID
    ]
    if len(backend_components) != 1:
        raise ValueError("Training run requires exactly one production backend component")
    expected_component = _component_entry(
        PRODUCTION_TRAINING_BACKEND_ID,
        PRODUCTION_TRAINING_BACKEND_VERSION,
        {
            "name": PRODUCTION_TRAINING_BACKEND_ID,
            "version": PRODUCTION_TRAINING_BACKEND_VERSION,
        },
    )
    if backend_components[0] != expected_component:
        raise ValueError("Training run backend component is not the production backend")

    for artifact_type in (
        "terminal_candidate_snapshots",
        "hero_policy_snapshots",
        "exact_ev_cells",
        "calibration_cells",
        "aggregate_metrics",
    ):
        reference = outputs[artifact_type]
        artifact_path = (root / reference["path"]).resolve()
        artifact = json.loads(artifact_path.read_bytes())
        records = artifact.get("records") if isinstance(artifact, dict) else None
        if not isinstance(records, list) or not records:
            raise ValueError("production Training output must contain backend-bound records")
        for record in records:
            record_payload = record.get("payload") if isinstance(record, dict) else None
            backend = record_payload.get("backend") if isinstance(record_payload, dict) else None
            if backend != expected_identity:
                raise ValueError(
                    "Training output record backend identity is not the production backend"
                )


def verify_training_run_manifest(
    manifest_path: Path | str,
    *,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Independently rehash inputs/outputs and reconstruct the approved Training plan."""
    path = Path(manifest_path).resolve()
    root = path.parent
    repository_root = Path(repo_root).resolve()
    payload, _raw = _load_canonical_manifest(path)
    expected_fields = {
        "schema_version",
        "artifact_type",
        "cli_version",
        "status",
        "split",
        "git",
        "invocation",
        "runtime",
        "timing",
        "inputs",
        "approved_plan",
        "components",
        "outputs",
    }
    if set(payload) != expected_fields:
        raise ValueError("Training run manifest fields are not closed-world")
    if (
        payload["schema_version"] != PRODUCTION_TRAINING_RUN_SCHEMA_VERSION
        or payload["artifact_type"] != "phase6_training_run_manifest"
        or payload["cli_version"] != PRODUCTION_TRAINING_CLI_VERSION
        or payload["status"] != "completed_and_verified"
        or payload["split"] != "training"
    ):
        raise ValueError("Training run manifest identity is not approved")

    git = payload["git"]
    if not isinstance(git, dict) or set(git) != {"expected_commit", "actual_commit", "dirty"}:
        raise ValueError("Training run git provenance is not closed-world")
    _validate_git_commit(git["expected_commit"], "expected git commit")
    _validate_git_commit(git["actual_commit"], "actual git commit")
    if git["expected_commit"] != git["actual_commit"] or git["dirty"] is not False:
        raise ValueError("Training run git provenance is not clean and commit-pinned")

    invocation = payload["invocation"]
    if (
        not isinstance(invocation, dict)
        or set(invocation) != {"entrypoint", "argv"}
        or invocation["entrypoint"] != PRODUCTION_TRAINING_ENTRYPOINT
        or not isinstance(invocation["argv"], list)
        or any(not isinstance(item, str) for item in invocation["argv"])
    ):
        raise ValueError("Training run invocation provenance is invalid")
    try:
        invocation_args = _parse_args(invocation["argv"])
    except SystemExit as exc:
        raise ValueError("Training run argv does not parse as the approved CLI surface") from exc
    runtime = payload["runtime"]
    if not isinstance(runtime, dict) or set(runtime) != set(_runtime_payload()):
        raise ValueError("Training run runtime/platform provenance is invalid")
    if any(not isinstance(value, str) for value in runtime.values()):
        raise ValueError("Training run runtime/platform values must be strings")
    timing = payload["timing"]
    if not isinstance(timing, dict) or set(timing) != {
        "started_at_utc",
        "finished_at_utc",
    }:
        raise ValueError("Training run timing provenance is invalid")
    started = _parse_utc(timing["started_at_utc"], "started_at_utc")
    finished = _parse_utc(timing["finished_at_utc"], "finished_at_utc")
    if finished < started:
        raise ValueError("Training run finished before it started")

    inputs = payload["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "phase6_contract_manifest",
        "dependency_lock",
        "sampling_contract",
        "training_batch_manifest_sha256",
    }:
        raise ValueError("Training run input provenance is not closed-world")
    contract_path = _resolve_manifest_input(
        repository_root, inputs["phase6_contract_manifest"], "Phase 6 contract manifest"
    )
    dependency_path = _resolve_manifest_input(
        repository_root, inputs["dependency_lock"], "dependency lock"
    )
    contract_reference = inputs["phase6_contract_manifest"]
    dependency_reference = inputs["dependency_lock"]
    if sha256_bytes(contract_path.read_bytes()) != contract_reference["sha256"]:
        raise ValueError("Phase 6 contract manifest hash mismatch")
    if sha256_bytes(dependency_path.read_bytes()) != dependency_reference["sha256"]:
        raise ValueError("dependency lock hash mismatch")
    invocation_output = (
        invocation_args.output_dir
        if invocation_args.output_dir.is_absolute()
        else repository_root / invocation_args.output_dir
    ).resolve()
    if (
        invocation_args.expected_commit != git["expected_commit"]
        or _resolve_repo_input(
            repository_root,
            invocation_args.phase6_contract_manifest,
            "argv Phase 6 contract manifest",
        )
        != contract_path
        or invocation_args.phase6_contract_manifest_sha256 != contract_reference["sha256"]
        or _resolve_repo_input(
            repository_root,
            invocation_args.dependency_lock,
            "argv dependency lock",
        )
        != dependency_path
        or invocation_args.dependency_lock_sha256 != dependency_reference["sha256"]
        or invocation_output != root
    ):
        raise ValueError("Training run argv does not join recorded provenance")
    load_phase6_contract_bundle(
        contract_path,
        expected_sha256=contract_reference["sha256"],
    )

    sampling = inputs["sampling_contract"]
    if not isinstance(sampling, dict) or set(sampling) != {"payload", "sha256"}:
        raise ValueError("sampling contract input is not closed-world")
    _validate_sha256(sampling["sha256"], "sampling contract hash")
    if not isinstance(sampling["payload"], dict):
        raise ValueError("sampling contract payload must be an object")
    approved_sampling = _approved_sampling_contract()
    approved_sampling_sha256 = sha256_bytes(canonical_json_bytes(approved_sampling))
    validate_sampling_contract(approved_sampling, expected_sha256=approved_sampling_sha256)
    if sampling["payload"] != approved_sampling or sampling["sha256"] != approved_sampling_sha256:
        raise ValueError(
            "sampling contract does not match the independently reconstructed approved registry"
        )
    plan = build_training_batch_plan(approved_sampling)
    _validate_approved_plan(plan, approved_sampling)
    _validate_sha256(inputs["training_batch_manifest_sha256"], "training batch manifest hash")
    if inputs["training_batch_manifest_sha256"] != plan.manifest_sha256:
        raise ValueError("training batch manifest does not reconstruct from approved inputs")

    if payload["approved_plan"] != {
        "expected_cardinality": _EXPECTED_CARDINALITY,
        "horizons": list(HORIZONS),
        "repetitions": [
            {"master_seed": seed, "repetition_id": repetition_id}
            for repetition_id, seed in REPETITION_SEEDS
        ],
        "performance_based_top_n": None,
    }:
        raise ValueError("Training run approved plan projection is invalid")
    if payload["components"] != _component_provenance(
        plan,
        contract_manifest_sha256=contract_reference["sha256"],
    ):
        raise ValueError("Training run component provenance is invalid")

    outputs = payload["outputs"]
    if not isinstance(outputs, dict) or set(outputs) != _BUNDLE_OUTPUT_NAMES:
        raise ValueError("Training run output reference set is not closed-world")
    for name, reference in outputs.items():
        if (
            not isinstance(reference, dict)
            or set(reference) != {"name", "path", "sha256"}
            or reference["name"] != name
        ):
            raise ValueError("Training run output reference shape is invalid")
        _validate_sha256(reference["sha256"], "output hash")
        relative = reference["path"]
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise ValueError("Training run output path must remain below the bundle root")
        output_path = (root / relative).resolve()
        if root != output_path and root not in output_path.parents:
            raise ValueError("Training run output path escapes the bundle root")
        if sha256_bytes(output_path.read_bytes()) != reference["sha256"]:
            raise ValueError("Training run output hash mismatch")
    if outputs["training_batch_manifest"]["sha256"] != plan.manifest_sha256:
        raise ValueError("Training output batch manifest hash does not match approved input")
    verify_training_artifact_bundle(TrainingArtifactBundle(root, outputs))
    _verify_production_backend_identity(root, outputs, payload["components"])
    return payload


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = _parse_args(raw_argv)
    repo_root = REPO_ROOT.resolve()
    initial_state = _require_repository_state(repo_root, args.expected_commit)
    output_root = _resolve_fresh_output(repo_root, args.output_dir)
    contract_path = _resolve_repo_input(
        repo_root, args.phase6_contract_manifest, "Phase 6 contract manifest"
    )
    dependency_path = _resolve_repo_input(repo_root, args.dependency_lock, "dependency lock")
    contract_reference = _input_reference(
        repo_root,
        contract_path,
        args.phase6_contract_manifest_sha256,
        "Phase 6 contract manifest",
    )
    dependency_reference = _input_reference(
        repo_root,
        dependency_path,
        args.dependency_lock_sha256,
        "dependency lock",
    )
    contract_bundle = load_phase6_contract_bundle(
        contract_path,
        expected_sha256=args.phase6_contract_manifest_sha256,
    )
    sampling_contract = _approved_sampling_contract()
    plan = build_training_batch_plan(sampling_contract)
    _validate_approved_plan(plan, sampling_contract)
    backend = ProductionTrainingExecutionBackend(
        contract_bundle=contract_bundle,
        sampling_contract=sampling_contract,
    )

    output_root.mkdir()
    try:
        execution_state = _require_repository_state(repo_root, args.expected_commit)
    except Exception:
        output_root.rmdir()
        raise
    if execution_state != initial_state:
        output_root.rmdir()
        raise RuntimeError("repository state changed during production preflight")

    started_at = _utc_now()
    records = run_training_execution_adapter(plan, backend)
    bundle = write_training_artifact_bundle(plan, records, output_root)
    verify_training_artifact_bundle(bundle)
    finished_at = _utc_now()
    manifest_payload = _run_manifest_payload(
        raw_argv=raw_argv,
        repository_state=execution_state,
        expected_commit=args.expected_commit,
        contract_reference=contract_reference,
        dependency_reference=dependency_reference,
        sampling_contract=sampling_contract,
        plan=plan,
        bundle=bundle,
        started_at=started_at,
        finished_at=finished_at,
    )
    manifest_path = _write_run_manifest(output_root, manifest_payload)
    verify_training_run_manifest(manifest_path, repo_root=repo_root)
    print(f"verified 12,960-session Training bundle: {output_root}")
    print(f"run_manifest_sha256={sha256_bytes(manifest_path.read_bytes())}")
    return 0


__all__ = [
    "CANONICALIZER_VERSION",
    "PRODUCTION_TRAINING_CLI_VERSION",
    "PRODUCTION_TRAINING_ENTRYPOINT",
    "PRODUCTION_TRAINING_RUN_MANIFEST",
    "PRODUCTION_TRAINING_RUN_SCHEMA_VERSION",
    "RepositoryState",
    "main",
    "verify_training_run_manifest",
]
