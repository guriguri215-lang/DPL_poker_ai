"""R005-only session orchestration and public-showdown evidence verification."""

from __future__ import annotations

import json
import math
import random
from pathlib import Path

from poker_core.dpl_schema import DPL_SCHEMA_VERSION
from poker_core.run_manifest import ArtifactRef, ConfigRef

from ._r005 import (
    _CONTEXT,
    _HISTORY,
    _MODE,
    _OPPONENT_ID,
    _VERSION,
    _classify_revealed,
    _R005BasePolicy,
    _R005Detector,
    _R005ExploitProvider,
    _scenario,
    _ShowdownStats,
)
from .cfr_policy import CfrRiverPolicyConfig
from .leak import LeakDetectorConfig
from .posterior_bundle import (
    ESTIMATOR_CONFIG_NAME,
    ESTIMATOR_CONFIG_PATH,
    PosteriorBundleParts,
    ValidatedPosteriorBundle,
    canonical_json_bytes,
    resolve_bundle_path,
    sha256_bytes,
)

_BASELINE_NAME = "r005_raise_composition_baseline"
_BASELINE_PATH = "provenance/r005_raise_composition_baseline.json"
_EVIDENCE_NAME = "r005_public_showdowns"
_EVIDENCE_PATH = "provenance/r005_public_showdowns.json"


def _is_r005(manifest, *, logs=None):
    return (
        any(item.opponent_id == _OPPONENT_ID for item in manifest.opponents)
        or manifest.versions.baseline_table_version == _VERSION
        or any(
            ref.name in {_EVIDENCE_NAME, _BASELINE_NAME}
            or ref.path in {_EVIDENCE_PATH, _BASELINE_PATH}
            or ref.path.startswith(f"inline:{_VERSION}:")
            for ref in [*manifest.configs, *manifest.outputs]
        )
        or any(
            log.baseline_table_version == _VERSION
            or log.base_strategy_provenance.source == _R005BasePolicy.source
            or (log.solver_result_id or "").startswith("nodelock_solver:r005:")
            or any(leak.reason_id == "LEAK_R005" for leak in log.detected_leaks)
            for log in logs or ()
        )
    )


def _decision(hand_id, session_id, detector, stats, base, provider, alpha, epsilon):
    from .decision import Observation
    from .session import _assemble_dpl

    scenario = _scenario(hand_id)
    observation = Observation(
        hand_id=hand_id,
        session_id=session_id,
        board=scenario.board_cards(),
        position="OOP",
        pot=scenario.pot,
        facing_bet=scenario.effective_stack,
        effective_stack=scenario.effective_stack,
        hero_combo=scenario.hero_combo_obj(),
        hero_range=scenario.hero_range_obj(),
        opponent_assumed_range=scenario.opponent_range_obj(),
    )
    return _assemble_dpl(
        scenario,
        hand_id,
        session_id,
        observation=observation,
        detected_leaks=detector._detect_public(stats),
        leak_detector=detector,
        safety_alpha=alpha,
        exploration_epsilon=epsilon,
        exploit_provider=provider,
        base_policy_provider=base,
    )


def _estimator_payload(detector, *, seed, horizon, baseline_sha):
    config = detector.config
    return {
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
            "opponent_ids": [_OPPONENT_ID],
            "seeds": [seed],
            "horizon": horizon,
            "situation_keys": [_CONTEXT],
        },
        "baseline_table": {
            "name": _BASELINE_NAME,
            "table_version": _VERSION,
            "sha256": baseline_sha,
        },
    }


def _bundle(detector, *, seed, events, stats, safety_alpha, exploit_enabled):
    base = _R005BasePolicy(detector.solver_config)
    baseline = {
        "version": _VERSION,
        "context": base._identity(),
        "estimand": "P(bluff | RAISE_ALL_IN, fixed public context)",
        "bluff_definition": "strictly loses to every combo in the public Hero support",
        "sampling": "iid conditional raised episodes; CALL independent of current hidden combo",
        "posterior": "Beta(1,1) upper tail of complementary value share",
        "baseline_bluff_rate": detector.baseline_bluff_rate,
    }
    baseline_bytes = canonical_json_bytes(baseline)
    estimator = _estimator_payload(
        detector, seed=seed, horizon=len(events), baseline_sha=sha256_bytes(baseline_bytes)
    )
    evidence = {
        "version": _VERSION,
        "session_id": f"S{seed:08d}",
        "situation_key": _CONTEXT,
        "safety_alpha": safety_alpha,
        "exploit_enabled": exploit_enabled,
        "events": events,
        "terminal": detector._score(stats),
    }
    estimator_bytes = canonical_json_bytes(estimator)
    evidence_bytes = canonical_json_bytes(evidence)
    return PosteriorBundleParts(
        artifacts={
            _BASELINE_PATH: baseline_bytes,
            ESTIMATOR_CONFIG_PATH: estimator_bytes,
            _EVIDENCE_PATH: evidence_bytes,
        },
        estimator_ref=ConfigRef(
            name=ESTIMATOR_CONFIG_NAME,
            role="other",
            path=ESTIMATOR_CONFIG_PATH,
            sha256=sha256_bytes(estimator_bytes),
        ),
        baseline_ref=ConfigRef(
            name=_BASELINE_NAME,
            role="baseline_table",
            path=_BASELINE_PATH,
            sha256=sha256_bytes(baseline_bytes),
        ),
        snapshot_ref=ArtifactRef(
            name=_EVIDENCE_NAME,
            path=_EVIDENCE_PATH,
            sha256=sha256_bytes(evidence_bytes),
        ),
    )


def _run_r005_session(
    seed,
    num_hands,
    *,
    solver_config,
    leak_detector,
    safety_alpha,
    exploration_epsilon,
    exploit_provider,
    git_commit,
    git_dirty,
    package_version,
    entrypoint,
    argv,
    _base_policy_provider=None,
):
    from .opponent import _sample_r005_raised_combo
    from .session import SessionResult, build_manifest

    if isinstance(num_hands, bool) or not isinstance(num_hands, int) or num_hands <= 0:
        raise ValueError("R005 requires a positive number of conditional decision episodes")
    detector = leak_detector or _R005Detector(solver_config)
    if not isinstance(detector, _R005Detector) or detector.solver_config != solver_config:
        raise ValueError("R005 requires its matching public-showdown detector")
    base = _base_policy_provider or _R005BasePolicy(solver_config)
    if not isinstance(base, _R005BasePolicy) or base.config != solver_config:
        raise ValueError("R005 requires its matching fixed-tree base provider")
    if exploit_provider is not None and (
        not isinstance(exploit_provider, _R005ExploitProvider)
        or exploit_provider.confidence_config != detector.config
        or exploit_provider.solver_config != solver_config
    ):
        raise ValueError("R005 requires its matching solver-backed provider")
    # None is a useful identity-exploit control, just as in normal sessions.
    session_id = f"S{seed:08d}"
    rng = random.Random(f"{session_id}:r005-independent-opponent-deal-v1")
    stats = _ShowdownStats()
    logs, events = [], []
    for index in range(num_hands):
        hand_id = f"{session_id}-H{index:05d}"
        private_combo = _sample_r005_raised_combo(rng)
        log = _decision(
            hand_id,
            session_id,
            detector,
            stats,
            base,
            exploit_provider,
            safety_alpha,
            exploration_epsilon,
        )
        # This is the sole environment -> observation boundary for dealt cards.
        revealed = private_combo if log.selected_action == "CALL" else None
        stats = stats.after(selected_action=log.selected_action, revealed_combo=revealed)
        events.append(
            {
                "hand_id": hand_id,
                "history": list(_HISTORY),
                "selected_action": log.selected_action,
                "revealed_combo": revealed,
                "classification": _classify_revealed(revealed)
                if revealed is not None
                else "unknown",
                "available_after": hand_id,
            }
        )
        logs.append(log)
    bundle = _bundle(
        detector,
        seed=seed,
        events=events,
        stats=stats,
        safety_alpha=safety_alpha,
        exploit_enabled=exploit_provider is not None,
    )
    manifest = build_manifest(
        seed,
        num_hands,
        git_commit=git_commit,
        git_dirty=git_dirty,
        package_version=package_version,
        entrypoint=entrypoint,
        argv=argv,
        leak_detector=detector,
        safety_alpha=safety_alpha,
        exploration_epsilon=exploration_epsilon,
        posterior_bundle=bundle,
        solver_config=solver_config,
        session_mode=_MODE,
        _base_policy_provider=base,
    )
    # Capture configs as outputs too so the saved verifier uses the same bytes.
    manifest.outputs.extend(
        ArtifactRef(name=ref.name, path=ref.path, sha256=ref.sha256)
        for ref in (bundle.estimator_ref, bundle.baseline_ref)
    )
    _validate_r005(manifest, bundle.artifacts, logs=logs)
    return SessionResult(session_id, logs, manifest, bundle)


def _config_from_estimator(payload):
    return LeakDetectorConfig(
        method_version=payload["method_version"],
        alpha0=payload["alpha0"],
        beta0=payload["beta0"],
        tail=payload["tail"],
        min_effective_sample_size=payload["min_effective_sample_size"],
        min_deviation=payload["tau"],
        min_confidence=payload["detector_min_confidence"],
        rule_exploit_min_confidence=payload["rule_exploit_min_confidence"],
        nodelock_exploit_min_confidence=payload["nodelock_exploit_min_confidence"],
    )


def _validate_r005(manifest, artifacts, *, logs=None):
    """Reconstruct public evidence, prefix detection, and exact DPL decisions."""
    from .session import _execution_sampler_config_ref

    if (
        manifest.versions.dpl_schema_version != DPL_SCHEMA_VERSION
        or manifest.versions.baseline_table_version != _VERSION
        or len(manifest.opponents) != 1
        or manifest.opponents[0].opponent_id != _OPPONENT_ID
    ):
        raise ValueError("R005 manifest identity mismatch")
    payloads = {}
    for name, path in (
        (_BASELINE_NAME, _BASELINE_PATH),
        (ESTIMATOR_CONFIG_NAME, ESTIMATOR_CONFIG_PATH),
        (_EVIDENCE_NAME, _EVIDENCE_PATH),
    ):
        refs = [ref for ref in manifest.outputs if ref.name == name]
        if len(refs) != 1 or refs[0].path != path or refs[0].sha256 is None:
            raise ValueError("R005 requires one exact public-evidence output reference")
        raw = artifacts[path]
        if sha256_bytes(raw) != refs[0].sha256:
            raise ValueError("R005 public evidence hash mismatch")
        payload = json.loads(raw)
        if canonical_json_bytes(payload) != raw or not isinstance(payload, dict):
            raise ValueError("R005 public evidence must be a canonical object")
        payloads[path] = payload
        if name != _EVIDENCE_NAME:
            configs = [ref for ref in manifest.configs if ref.name == name]
            role = "other" if name == ESTIMATOR_CONFIG_NAME else "baseline_table"
            expected = ConfigRef(name=name, role=role, path=path, sha256=refs[0].sha256)
            if configs != [expected]:
                raise ValueError("R005 config/output evidence join mismatch")
    baseline = payloads[_BASELINE_PATH]
    estimator = payloads[ESTIMATOR_CONFIG_PATH]
    evidence = payloads[_EVIDENCE_PATH]
    solver_config = CfrRiverPolicyConfig.model_validate(baseline["context"]["solver"])
    base = _R005BasePolicy(solver_config)
    detector = _R005Detector(solver_config, _config_from_estimator(estimator))
    solver_refs = [ref for ref in manifest.configs if ref.name == "cfr_river_policy"]
    if solver_refs != [base.config_ref()] or (
        manifest.versions.strategy_table_version != base.strategy_version
    ):
        raise ValueError("R005 solver identity mismatch")
    seed = manifest.seeds["master"]
    if manifest.run_id != f"S{seed:08d}":
        raise ValueError("R005 run identity mismatch")
    events = evidence["events"]
    alpha = evidence["safety_alpha"]
    enabled = evidence["exploit_enabled"]
    if (
        isinstance(alpha, bool)
        or not isinstance(alpha, int | float)
        or not 0 <= alpha <= 1
        or not isinstance(enabled, bool)
    ):
        raise ValueError("R005 execution settings invalid")
    if not isinstance(events, list) or not events:
        raise ValueError("R005 evidence requires completed conditional episodes")
    stats = _ShowdownStats()
    if logs is not None and len(logs) != len(events):
        raise ValueError("R005 evidence/DPL count mismatch")
    sampler_refs = [ref for ref in manifest.configs if ref.name == "execution_sampler"]
    if len(sampler_refs) != 1:
        raise ValueError("R005 execution sampler missing")
    epsilon = float(sampler_refs[0].path.rsplit("=", 1)[1])
    if not 0 <= epsilon <= 1 or sampler_refs != [_execution_sampler_config_ref(epsilon)]:
        raise ValueError("R005 execution sampler mismatch")
    provider = _R005ExploitProvider(solver_config, detector.config) if enabled else None
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {
            "hand_id",
            "history",
            "selected_action",
            "revealed_combo",
            "classification",
            "available_after",
        }:
            raise ValueError("R005 public event shape mismatch")
        hand_id = f"{manifest.run_id}-H{index:05d}"
        if event["hand_id"] != hand_id or event["available_after"] != hand_id:
            raise ValueError("R005 reveal order mismatch")
        if event["history"] != list(_HISTORY):
            raise ValueError("R005 public action history mismatch")
        revealed = event["revealed_combo"]
        label = _classify_revealed(revealed) if revealed is not None else "unknown"
        if label != event["classification"]:
            raise ValueError("R005 reveal classification mismatch")
        if logs is not None:
            log = logs[index]
            # Reconstruct the pinned provider mode with no hidden input.
            expected = _decision(
                hand_id,
                manifest.run_id,
                detector,
                stats,
                base,
                provider,
                alpha,
                epsilon,
            )
            if log.model_dump() != expected.model_dump():
                raise ValueError("R005 DPL does not reconstruct from earlier public reveals")
            if log.selected_action != event["selected_action"]:
                raise ValueError("R005 revealed action does not match DPL")
        stats = stats.after(selected_action=event["selected_action"], revealed_combo=revealed)
    expected_bundle = _bundle(
        detector,
        seed=seed,
        events=events,
        stats=stats,
        safety_alpha=alpha,
        exploit_enabled=enabled,
    )
    if any(artifacts[path] != raw for path, raw in expected_bundle.artifacts.items()):
        raise ValueError("R005 baseline, estimator or terminal posterior does not reconstruct")
    return ValidatedPosteriorBundle(manifest, estimator, baseline, evidence)


def _validate_r005_directory(manifest, root, *, logs=None):
    artifacts = {
        path: resolve_bundle_path(Path(root), path).read_bytes()
        for path in (_BASELINE_PATH, ESTIMATOR_CONFIG_PATH, _EVIDENCE_PATH)
    }
    return _validate_r005(manifest, artifacts, logs=logs)


def _terminal_records(manifest, bundle):
    validated = _validate_r005(manifest, bundle.artifacts)
    record = dict(validated.terminal_snapshots["terminal"])
    record["threshold_bluff_rate"] = record["baseline_bluff_rate"] - validated.estimator["tau"]
    return [record]


def _candidate_metrics(records, answer_key):
    from .opponent import _R005AnswerKey
    from .post_session_evaluation import _CandidateMetrics

    if not isinstance(answer_key, _R005AnswerKey) or len(records) != 1:
        raise ValueError("R005 post-session evaluation requires its conditional answer key")
    record = records[0]
    n = record["revealed"]
    true_positive = answer_key.bluff_rate < record["threshold_bluff_rate"]
    eligible = (
        n > 0
        and record["threshold_bluff_rate"] > 0
        and not math.isclose(
            answer_key.bluff_rate, record["threshold_bluff_rate"], abs_tol=1e-12, rel_tol=0
        )
    )
    predicted = record["detected"]
    error = abs(record["observed_bluff_rate"] - answer_key.bluff_rate) if n else 0.0
    return _CandidateMetrics(
        accuracy=float(predicted == true_positive) if eligible else 0.0,
        average_estimation_error=error,
        false_positive_count=int(eligible and predicted and not true_positive),
        false_negative_count=int(eligible and not predicted and true_positive),
        truth_positive_by_reason_and_situation={("LEAK_R005", _CONTEXT): true_positive},
    )


def _validate_saved_post_session(manifest, artifacts, actual):
    from poker_core.dpl_schema import DecisionProvenanceLog

    from .explanation_artifacts import _generate_and_verify_explanation_set
    from .opponent import _reveal_r005_answer_key
    from .post_session_evaluation import build_post_session_artifact

    dpl_refs = [ref for ref in manifest.outputs if ref.path.endswith(".dpl.jsonl")]
    if len(dpl_refs) != 1:
        raise ValueError("R005 post-session reconstruction requires one DPL artifact")
    logs = [
        DecisionProvenanceLog.model_validate_json(line)
        for line in artifacts[dpl_refs[0].path].splitlines()
        if line.strip()
    ]
    explanations, verification = _generate_and_verify_explanation_set(logs)
    bundle = PosteriorBundleParts(
        artifacts={
            path: artifacts[path]
            for path in (_BASELINE_PATH, ESTIMATOR_CONFIG_PATH, _EVIDENCE_PATH)
        },
        estimator_ref=next(ref for ref in manifest.configs if ref.name == ESTIMATOR_CONFIG_NAME),
        baseline_ref=next(ref for ref in manifest.configs if ref.name == _BASELINE_NAME),
        snapshot_ref=next(ref for ref in manifest.outputs if ref.name == _EVIDENCE_NAME),
    )
    expected = build_post_session_artifact(
        session_id=manifest.run_id,
        logs=logs,
        manifest=manifest,
        posterior_bundle=bundle,
        answer_key=_reveal_r005_answer_key(),
        explanations=explanations,
        checker_results=verification.checker_results,
    )
    if expected.to_payload() != actual.to_payload():
        raise ValueError("R005 post-session evaluation/settings do not reconstruct")
