"""Unit/tmp and independent-arithmetic fixtures for P6-10B."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
from dataclasses import replace
from decimal import ROUND_DOWN, ROUND_HALF_EVEN, Decimal, localcontext
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

import phase6.p6_10b as p6_10b
from phase6 import (
    AtomicGroupMetrics,
    CalibrationCell,
    ConfidenceValueReplacement,
    GtoFprSummary,
    MetricValue,
    MicroMetrics,
    P610BValidationExecutionBackend,
    RateFraction,
    SeriesCalibrationResult,
    canonical_json_bytes,
    equilibrium_counterfactual_action_values,
    legacy_mvp_confidence,
    revalue_series_confidence,
    run_p6_10b_independent_verifier,
    sha256_bytes,
)
from phase6.calibration import _macro_metrics, _metric_set
from phase6.p6_7 import REPETITION_SEEDS, PrimaryCandidate
from phase6.validation_execution import _backend_identity
from phase6.validation_runner import ValidationSessionKey
from poker_solver.game import Decision, Game, Terminal

_PRECISION_50_ESTIMAND_CASES = (
    (
        "0.032986748833684122996726160624556761983269190784751",
        "0.012945942450642294370403267922015549648665191628527",
        "0.020040806383041828626322892702541212334603999156224",
        "0.0200408063830418286263228927",
    ),
    (
        "0.010506055943898203868466823944991007504731784632178",
        "0.012764520537135088343830794336234383216058766400372",
        "-0.002258464593236884475363970391243375711326981768194",
        "-0.002258464593236884475363970391",
    ),
)
_FRESH_RESULT_MARKER = "p6_10b_fresh_test_result.json"


def _fresh_result_marker_path(result_root):
    if (
        result_root.name != p6_10b.P6_10B_RESULT_ROOT
        or result_root.parent.name != p6_10b.P6_10B_PHYSICAL_DIRECTORY
        or result_root.parent.parent.name != p6_10b.P6_10B_ARTIFACT_DIRECTORY
    ):
        raise ValueError("fresh P6-10B test result has a noncanonical path")
    return result_root.parent.parent.parent / _FRESH_RESULT_MARKER


def _require_fresh_test_result(result_root):
    source_root = result_root.resolve()
    repository_root = Path.cwd().resolve()
    protected_roots = (repository_root / "experiments_output",)
    for protected in protected_roots:
        try:
            source_root.relative_to(protected.resolve())
        except ValueError:
            continue
        raise ValueError("fresh P6-10B test result must not be an immutable production tree")
    marker_path = _fresh_result_marker_path(source_root)
    marker = json.loads(marker_path.read_bytes())
    expected = {
        "artifact_type": "p6_10b_fresh_test_result",
        "result_root_sha256": sha256_bytes(source_root.read_bytes()),
    }
    if marker != expected:
        raise ValueError("fresh P6-10B test result marker mismatch")
    return source_root


def _generate_fresh_test_result(tmp_path):
    repository_root = Path.cwd().resolve()
    source_run = (
        repository_root
        / "experiments_output"
        / "p6_10a_comparator_ablation_run_20260719"
        / "phase6_p6_10a_run_manifest.json"
    )
    snapshot = p6_10b.load_p6_10a_snapshot(source_run, repo_root=repository_root)
    batch = p6_10b.build_p6_10b_batch(snapshot)
    artifact_parent = tmp_path / p6_10b.P6_10B_ARTIFACT_DIRECTORY
    artifact_parent.mkdir()
    bundle = p6_10b.execute_p6_10b(
        snapshot,
        batch,
        artifact_parent / p6_10b.P6_10B_PHYSICAL_DIRECTORY,
        repo_root=repository_root,
    )
    marker = {
        "artifact_type": "p6_10b_fresh_test_result",
        "result_root_sha256": bundle.root_manifest_sha256,
    }
    _fresh_result_marker_path(bundle.root_manifest_path).write_bytes(canonical_json_bytes(marker))
    return _require_fresh_test_result(bundle.root_manifest_path)


def test_fresh_result_guard_rejects_immutable_production_tree():
    old_root = (
        Path.cwd()
        / "experiments_output"
        / "p6_10b_confidence_provider_run_20260719"
        / p6_10b.P6_10B_ARTIFACT_DIRECTORY
        / p6_10b.P6_10B_PHYSICAL_DIRECTORY
        / p6_10b.P6_10B_RESULT_ROOT
    )
    with pytest.raises(ValueError, match="must not be an immutable production tree"):
        _require_fresh_test_result(old_root)


@pytest.mark.parametrize(
    ("ablation_value", "primary_value", "expected", "legacy_default_28"),
    _PRECISION_50_ESTIMAND_CASES,
)
def test_decimal_difference_uses_explicit_precision_50(
    ablation_value, primary_value, expected, legacy_default_28
):
    with localcontext() as global_context:
        global_context.prec = 7
        global_context.rounding = ROUND_DOWN
        actual = p6_10b._decimal_difference(ablation_value, primary_value)

    assert actual == expected
    assert actual != legacy_default_28


def test_decimal_difference_preserves_none_contract():
    assert p6_10b._decimal_difference(None, "1") is None
    assert p6_10b._decimal_difference("1", None) is None


def test_embedded_verifier_estimand_delta_uses_independent_precision_50_path():
    tree = ast.parse(p6_10b._INDEPENDENT_VERIFIER_SOURCE)
    helpers = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {"decimal_token", "estimand_delta"}
    ]
    namespace = {
        "Decimal": Decimal,
        "ROUND_HALF_EVEN": ROUND_HALF_EVEN,
        "localcontext": localcontext,
    }
    exec(
        compile(ast.Module(body=helpers, type_ignores=[]), "<precision-fixture>", "exec"), namespace
    )

    with localcontext() as global_context:
        global_context.prec = 9
        global_context.rounding = ROUND_DOWN
        actual = tuple(
            namespace["estimand_delta"](ablation_value, primary_value)
            for ablation_value, primary_value, _expected, _legacy in _PRECISION_50_ESTIMAND_CASES
        )

    assert actual == tuple(case[2] for case in _PRECISION_50_ESTIMAND_CASES)
    assert actual != tuple(case[3] for case in _PRECISION_50_ESTIMAND_CASES)


def test_legacy_mvp_confidence_matches_independent_binary64_arithmetic():
    cases = (
        (0, 0, 0.5, 10, 0.0),
        (5, 10, 0.5, 10, 0.0),
        (9, 10, 0.5, 10, 0.8),
        (10, 10, 0.5, 10, 1.0),
        (5, 5, 0.2, 10, 0.8),
    )
    for k, n, baseline, floor, expected in cases:
        observed_rate = 0.0 if n <= 0 else k / n
        deviation = observed_rate - baseline
        sample_factor = min(1.0, n / floor) if n > 0 else 0.0
        independent = 0.0 if n <= 0 else min(1.0, max(0.0, (deviation * 2.0) * sample_factor))
        actual = legacy_mvp_confidence(k=k, n=n, baseline_rate=baseline, sample_floor=floor)
        assert actual == independent == expected
        assert Decimal.from_float(actual) == Decimal.from_float(float.fromhex(actual.hex()))


def test_counterfactual_action_value_excludes_hero_reach_independent_fixture():
    hero_x = Decision(0, "hero", ("FOLD", "CALL"), (Terminal(0), Terminal(2)))
    hero_y = Decision(0, "hero", ("FOLD", "CALL"), (Terminal(0), Terminal(4)))
    root = Decision(1, "opponent", ("X", "Y"), (hero_x, hero_y))
    game = Game(root, "counterfactual-fixture")
    strategy = {
        "opponent": {"X": 0.25, "Y": 0.75},
        "hero": {"FOLD": 0.99, "CALL": 0.01},
    }

    values = equilibrium_counterfactual_action_values(game, strategy, "hero")

    assert values == {"FOLD": 0.0, "CALL": 3.5}


def test_additive_confidence_revaluation_changes_only_score_metrics():
    keys = (
        ("s", "gto", "LEAK_R008", "river_vs_check", 50, "r001"),
        ("s", "gto", "LEAK_R008", "river_vs_check", 50, "r002"),
    )
    cells = tuple(
        CalibrationCell(
            key=key,
            q=Decimal("0.75"),
            true_rate=Decimal("1") if index == 0 else Decimal("0"),
            reach_weight=Decimal("1"),
            confidence=Decimal("0.9") if index == 0 else Decimal("0.1"),
            structurally_eligible=True,
            predicted_positive=index == 0,
            label=1 if index == 0 else 0,
            exclusion_status="eligible",
            brier_component=Decimal("0.01"),
            bin_index=9 if index == 0 else 1,
        )
        for index, key in enumerate(keys)
    )
    metric = _metric_set(cells)
    source_group = AtomicGroupMetrics("gto", 50, metric, MetricValue(Decimal("0.5"), "defined", 2))
    source = SeriesCalibrationResult(
        "s",
        "1" * 64,
        "2" * 64,
        ("3" * 64, "4" * 64),
        cells,
        (source_group,),
        _macro_metrics((source_group,)),
        MicroMetrics(metric, source_group.mean_cell_efficiency),
        GtoFprSummary(
            "gto_false_positive_rate",
            (),
            MetricValue(None, "undefined_no_defined_groups", 0),
            RateFraction(0, 0, None, "undefined_no_eligible_records"),
        ),
    )
    replacements = tuple(ConfidenceValueReplacement(key, Decimal("0.5"), False) for key in keys)

    result = revalue_series_confidence(source, replacements)

    assert result.macro.brier.value == Decimal("0.25")
    assert result.micro.micro_mean_cell_efficiency == source.micro.micro_mean_cell_efficiency
    assert tuple(cell.label for cell in result.cells) == (1, 0)
    assert all(cell.confidence == Decimal("0.5") for cell in result.cells)


def _batch_fixture(monkeypatch):
    selected = PrimaryCandidate(
        "primary__" + "a" * 64,
        "0.05",
        10,
        "0.9",
        "0.9",
        "0.5",
        "b" * 64,
    )
    opponents = [{"opponent_id": f"opp-{index}", "control_role": "ordinary"} for index in range(9)]
    sessions = tuple(
        ValidationSessionKey(selected.candidate_id, item["opponent_id"], horizon, repetition)
        for item in opponents
        for horizon in (50, 200, 1000)
        for repetition, _seed in REPETITION_SEEDS
    )
    plan = SimpleNamespace(
        sessions=sessions,
        manifest={
            "validation_catalog_index": {
                "schema_version": "fixture",
                "split": "validation",
                "opponents": opponents,
            },
            "sampling_contract": {"payload": {"fixture": True}, "sha256": "b" * 64},
        },
    )
    p69 = SimpleNamespace(selected_candidate=selected, plan=plan)
    snapshot = SimpleNamespace(p69=p69)
    monkeypatch.setattr(p6_10b, "_source_snapshot", lambda _snapshot: {"fixture": "source"})
    monkeypatch.setattr(p6_10b, "_selected_primary_series_id", lambda _snapshot: "c" * 64)
    return snapshot


def test_batch_is_two_distinct_one_intervention_series(monkeypatch):
    snapshot = _batch_fixture(monkeypatch)

    batch = p6_10b.build_p6_10b_batch(snapshot)

    assert len(batch.sessions) == 1620
    assert len(batch.manifest["stream_roots"]) == 3240
    assert batch.manifest["stream_root_reference_count"] == 6480
    assert tuple(item.ablation_id for item in batch.ablations) == (
        "abl_confidence_mvp__v1",
        "abl_provider_rule__v1",
    )
    assert [set(item.config["intervention"]) for item in batch.ablations] == [
        {"leak_confidence_estimator"},
        {"exploit_provider"},
    ]
    assert len({item.config_sha256 for item in batch.ablations}) == 2
    assert len({item.series_id for item in batch.ablations}) == 2


def test_batch_tamper_is_fail_closed(monkeypatch):
    snapshot = _batch_fixture(monkeypatch)
    batch = p6_10b.build_p6_10b_batch(snapshot)
    payload = dict(batch.manifest)
    payload["stream_root_reference_count"] = 6479
    raw = canonical_json_bytes(payload)
    tampered = replace(
        batch, manifest=payload, manifest_bytes=raw, manifest_sha256=sha256_bytes(raw)
    )

    with pytest.raises(ValueError, match="cardinality"):
        p6_10b.verify_p6_10b_batch(tampered, snapshot=snapshot)


def test_batch_metric_contract_tamper_is_fail_closed(monkeypatch):
    snapshot = _batch_fixture(monkeypatch)
    batch = p6_10b.build_p6_10b_batch(snapshot)
    payload = dict(batch.manifest)
    payload["metric_contract"] = {
        **payload["metric_contract"],
        "abl_confidence_mvp__v1": {
            **payload["metric_contract"]["abl_confidence_mvp__v1"],
            "primary": "macro.ece",
        },
    }
    raw = canonical_json_bytes(payload)
    tampered = replace(
        batch, manifest=payload, manifest_bytes=raw, manifest_sha256=sha256_bytes(raw)
    )

    with pytest.raises(ValueError, match="retained source contract"):
        p6_10b.verify_p6_10b_batch(tampered, snapshot=snapshot)


def test_batch_duplicate_session_and_order_tamper_is_fail_closed(monkeypatch):
    snapshot = _batch_fixture(monkeypatch)
    batch = p6_10b.build_p6_10b_batch(snapshot)
    payload = dict(batch.manifest)
    payload["sessions"] = [dict(item) for item in payload["sessions"]]
    payload["sessions"][17] = dict(payload["sessions"][16])
    raw = canonical_json_bytes(payload)
    tampered = replace(
        batch, manifest=payload, manifest_bytes=raw, manifest_sha256=sha256_bytes(raw)
    )

    with pytest.raises(ValueError, match="session product"):
        p6_10b.verify_p6_10b_batch(tampered, snapshot=snapshot)


def test_rule_provider_calibration_invariance_is_cell_level():
    cells = [
        {
            "key": ["provider-series", "opp", "LEAK_R008", "river_vs_check", 50, "r001"],
            "confidence": "0.9",
        }
        for _ in range(810)
    ]
    primary_cells = [{**cell, "key": ["primary-series", *cell["key"][1:]]} for cell in cells]
    metric = {"value": "0", "status": "defined", "record_count": 1}
    macro = {
        "brier": metric,
        "ece": metric,
        "precision": metric,
        "recall": metric,
        "mean_cell_efficiency": metric,
        "undefined_brier_groups": 0,
        "undefined_ece_groups": 0,
        "undefined_precision_groups": 0,
        "undefined_recall_groups": 0,
        "undefined_efficiency_groups": 0,
    }
    aggregate = {
        "macro": macro,
        "micro": {"calibration": {"fixture": True}, "micro_mean_cell_efficiency": metric},
        "gto_fpr": {"fixture": True},
    }

    p6_10b._verify_provider_calibration_invariance(
        aggregate, aggregate, {"cells": cells}, {"cells": primary_cells}
    )
    cells[417] = {**cells[417], "confidence": "0.8"}
    with pytest.raises(ValueError, match="calibration cell"):
        p6_10b._verify_provider_calibration_invariance(
            aggregate, aggregate, {"cells": cells}, {"cells": primary_cells}
        )


def test_additive_policy_verifier_reconstructs_and_rejects_tamper():
    backend = object.__new__(P610BValidationExecutionBackend)
    backend._confidence_candidate_id = "confidence"
    backend._provider_candidate_id = "provider"
    dimension = {"fixture": "frozen"}
    backend._context = SimpleNamespace(dimension=dimension)
    base = {"hero": {"FOLD": 0.75, "CALL": 0.25}}
    final = {"hero": {"FOLD": 0.5, "CALL": 0.5}}
    backend._hero_policies = lambda *_args: (base, final)
    candidate = SimpleNamespace(candidate_id="confidence")
    terminal = {"action_counts": {"CHECK": 5, "BET": 5}, "opportunity_count": 10}
    policy = {
        "base_hero_policy": {
            "hero": {action: probability.hex() for action, probability in base["hero"].items()}
        },
        "final_hero_policy": {
            "hero": {action: probability.hex() for action, probability in final["hero"].items()}
        },
    }

    assert backend.validate_p6_10b_saved_policy(
        candidate, terminal, policy, SimpleNamespace(), dimension
    ) == (base, final)
    policy["final_hero_policy"]["hero"]["CALL"] = (0.25).hex()
    with pytest.raises(ValueError, match="does not reconstruct"):
        backend.validate_p6_10b_saved_policy(
            candidate, terminal, policy, SimpleNamespace(), dimension
        )


def test_p6_10b_backend_identity_is_validation_only():
    backend = object.__new__(P610BValidationExecutionBackend)

    assert _backend_identity(backend) == {
        "backend_id": "phase6-validation-p6-10b-river",
        "backend_version": "p6-10b-confidence-provider-validation-backend-v1",
    }


def test_independent_verifier_rejects_non_result_bytes(tmp_path):
    root = tmp_path / p6_10b.P6_10B_RESULT_ROOT
    raw = canonical_json_bytes({})
    root.write_bytes(raw)

    with pytest.raises(ValueError, match="independent verifier failed"):
        run_p6_10b_independent_verifier(
            root,
            expected_sha256=sha256_bytes(raw),
            repo_root=tmp_path,
        )


def test_independent_verifier_exact_sequence_and_gate_checks_fail_closed():
    tree = ast.parse(p6_10b._INDEPENDENT_VERIFIER_SOURCE)
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "require_exact"
    )
    namespace = {}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), "<fixture>", "exec"), namespace)
    require_exact = namespace["require_exact"]
    labels = {
        call.args[2].value
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "require_exact"
        and len(call.args) == 3
        and isinstance(call.args[2], ast.Constant)
    }

    assert labels >= {
        "legacy eligibility gate",
        "aggregate group key sequence",
        "report ablation identity/order",
        "stream-root exact product",
        "execution event transcript",
        "action draw audit transcript",
        "fixed-source sampling contract",
        "fixed-source opponent catalog",
    }
    with pytest.raises(ValueError, match="aggregate group key sequence"):
        require_exact(
            [("a", 50), ("a", 50)],
            [("a", 50), ("b", 50)],
            "aggregate group key sequence",
        )
    with pytest.raises(ValueError, match="report ablation identity/order"):
        require_exact(
            ["provider", "confidence"], ["confidence", "provider"], "report ablation identity/order"
        )
    with pytest.raises(ValueError, match="legacy eligibility gate"):
        require_exact(
            {"emitted": False},
            {
                "structurally_eligible": True,
                "sample_gate": True,
                "deviation_gate": False,
                "confidence_gate": False,
                "emitted": False,
            },
            "legacy eligibility gate",
        )


def test_independent_verifier_pins_approved_source_and_rejects_escaping_paths(tmp_path):
    tree = ast.parse(p6_10b._INDEPENDENT_VERIFIER_SOURCE)
    source_assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "APPROVED_SOURCE_SNAPSHOT"
            for target in node.targets
        )
    )
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {"require_fields", "safe_source_path"}
    ]
    namespace = {"Path": Path, "PurePosixPath": PurePosixPath}
    exec(
        compile(
            ast.Module(body=[source_assignment, *functions], type_ignores=[]),
            "<source-closure-fixture>",
            "exec",
        ),
        namespace,
    )
    approved = namespace["APPROVED_SOURCE_SNAPSHOT"]
    assert set(approved) == {
        "target_commit",
        "p6_10a_batch_manifest",
        "p6_10a_run_manifest",
        "p6_10a_result_root",
        "comparator_ablation_report",
        "gate_b_readiness_gap_packet",
    }
    assert approved["target_commit"] == p6_10b.P6_10B_BASELINE
    assert {name: approved[name]["sha256"] for name in approved if name != "target_commit"} == {
        "p6_10a_batch_manifest": p6_10b.P6_10A_BATCH_SHA256,
        "p6_10a_run_manifest": p6_10b.P6_10A_RUN_SHA256,
        "p6_10a_result_root": p6_10b.P6_10A_RESULT_ROOT_SHA256,
        "comparator_ablation_report": p6_10b.P6_10A_REPORT_SHA256,
        "gate_b_readiness_gap_packet": p6_10b.P6_10A_GAP_SHA256,
    }

    root = tmp_path / "repo"
    source = root / "approved" / "source.json"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"{}\n")
    reference = {
        "name": "source",
        "path": "approved/source.json",
        "sha256": sha256_bytes(source.read_bytes()),
        "size_bytes": source.stat().st_size,
    }
    safe_source_path = namespace["safe_source_path"]
    assert (
        safe_source_path(
            root,
            root,
            reference,
            {"name", "path", "sha256", "size_bytes"},
            "source",
        )
        == source.resolve()
    )
    for invalid in (
        "../outside.json",
        "/absolute/source.json",
        "C:/absolute/source.json",
        "approved\\source.json",
        "approved//source.json",
    ):
        changed = dict(reference, path=invalid)
        with pytest.raises(ValueError, match="repository-relative|escapes the repository"):
            safe_source_path(
                root,
                root,
                changed,
                {"name", "path", "sha256", "size_bytes"},
                "source",
            )


def test_canonical_child_path_rejects_ads_and_noncanonical_aliases(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    child = root / "artifact.json"
    child.write_bytes(b"{}\n")
    assert p6_10b._safe_child(root, "artifact.json", "artifact") == child.resolve()
    for invalid in (
        "artifact.json:alternate",
        "./artifact.json",
        "nested/../artifact.json",
        "nested//artifact.json",
        "nested\\artifact.json",
    ):
        with pytest.raises(ValueError, match="relative POSIX|escapes"):
            p6_10b._safe_child(root, invalid, "artifact")


def _rehash_valid_result_tamper(source_root, target_root, mode):
    source_root = _require_fresh_test_result(source_root)
    source_dir = source_root.parent
    target_dir = target_root.parent
    target_dir.mkdir(parents=True)
    for source in source_dir.iterdir():
        target = target_dir / source.name
        shutil.copyfile(source, target)

    def copy_for_write(source, target):
        target.unlink()
        shutil.copyfile(source, target)

    root = json.loads(target_root.read_bytes())
    refs = {item["name"]: item for item in root["artifacts"]}
    batch_ref = refs["p6_10b_batch_manifest"]
    report_ref = refs["p6_10b_contract_closure_report"]
    terminal_name = "abl_confidence_mvp__v1__terminal_candidate_snapshots"
    terminal_ref = refs[terminal_name]
    policy_ref = refs["abl_confidence_mvp__v1__hero_policy_snapshots"]
    old_batch_sha = root["p6_10b_batch_manifest_sha256"]

    if mode in {
        "source_snapshot",
        "source_sampling",
        "source_catalog",
        "stream_root",
        "config",
    }:
        batch_path = target_dir / batch_ref["path"]
        copy_for_write(source_dir / batch_ref["path"], batch_path)
        payload = json.loads(batch_path.read_bytes())
        if mode == "source_snapshot":
            root["source_snapshot"]["target_commit"] = "0" * 40
            payload["source_snapshot"] = root["source_snapshot"]
        elif mode == "source_sampling":
            payload["sampling_contract"]["payload"]["unexpected"] = False
            payload["sampling_contract"]["sha256"] = sha256_bytes(
                canonical_json_bytes(payload["sampling_contract"]["payload"])
            )
        elif mode == "source_catalog":
            coverage = payload["opponent_catalog"]["opponents"][0]["coverage"]
            coverage["end_to_end_coverage"] = not coverage["end_to_end_coverage"]
        if mode == "stream_root":
            payload["stream_roots"][0]["digest"] = "f" * 64
        elif mode == "config":
            payload["ablation_configs"][0]["config"]["retained_primary_config"]["sample_floor"] = 11
        batch_raw = canonical_json_bytes(payload)
        batch_path.write_bytes(batch_raw)
        batch_ref["sha256"] = sha256_bytes(batch_raw)
        batch_ref["size_bytes"] = len(batch_raw)
        root["p6_10b_batch_manifest_sha256"] = batch_ref["sha256"]

        old_token = old_batch_sha.encode("ascii")
        new_token = batch_ref["sha256"].encode("ascii")
        for ref in root["artifacts"][1:-1]:
            source = source_dir / ref["path"]
            raw = source.read_bytes()
            assert raw.count(old_token) == 1
            changed = raw.replace(old_token, new_token, 1)
            target = target_dir / ref["path"]
            copy_for_write(source, target)
            target.write_bytes(changed)
            ref["sha256"] = sha256_bytes(changed)
            ref["size_bytes"] = len(changed)

    if mode in {"execution_event", "action_draw_audit", "nested_evidence"}:
        terminal_path = target_dir / terminal_ref["path"]
        copy_for_write(source_dir / terminal_ref["path"], terminal_path)
        target_raw = terminal_path.read_bytes()
        if mode == "execution_event":
            marker = b'"execution_events":[{'
            start = target_raw.index(marker)
            original = b'"decision_index":0'
            index = target_raw.index(original, start)
            target_raw = (
                target_raw[:index] + b'"decision_index":9' + target_raw[index + len(original) :]
            )
        elif mode == "action_draw_audit":
            marker = b'"action_draw_audits":[{'
            start = target_raw.index(marker)
            prefix = b'"final_action":"'
            index = target_raw.index(prefix, start) + len(prefix)
            original = target_raw[index : index + 4]
            replacement = b"FOLD" if original == b"CALL" else b"CALL"
            target_raw = target_raw[:index] + replacement + target_raw[index + 4 :]
        else:
            payload = json.loads(target_raw)
            payload["records"][0]["ablation_evidence"]["unexpected"] = False
            target_raw = canonical_json_bytes(payload)
        terminal_path.write_bytes(target_raw)
        terminal_ref["sha256"] = sha256_bytes(target_raw)
        terminal_ref["size_bytes"] = len(target_raw)
        if mode == "nested_evidence":
            policy_path = target_dir / policy_ref["path"]
            copy_for_write(source_dir / policy_ref["path"], policy_path)
            policy = json.loads(policy_path.read_bytes())
            policy["records"][0]["ablation_evidence"]["unexpected"] = False
            policy_raw = canonical_json_bytes(policy)
            policy_path.write_bytes(policy_raw)
            policy_ref["sha256"] = sha256_bytes(policy_raw)
            policy_ref["size_bytes"] = len(policy_raw)

    if mode == "artifact_ads":
        source = source_dir / batch_ref["path"]
        ads_path = target_dir / f"{batch_ref['path']}:alternate"
        ads_path.write_bytes(source.read_bytes())
        batch_ref["path"] = ads_path.name

    report_path = target_dir / report_ref["path"]
    copy_for_write(source_dir / report_ref["path"], report_path)
    report = json.loads(report_path.read_bytes())
    if mode == "source_snapshot":
        report["source_snapshot"] = root["source_snapshot"]
    report["artifact_references"] = root["artifacts"][1:-1]
    report_raw = canonical_json_bytes(report)
    report_path.write_bytes(report_raw)
    report_ref["sha256"] = sha256_bytes(report_raw)
    report_ref["size_bytes"] = len(report_raw)

    root_raw = canonical_json_bytes(root)
    target_root.write_bytes(root_raw)
    return sha256_bytes(root_raw)


def _rewrite_primary_estimand_deltas(result_root, replacements):
    root = json.loads(result_root.read_bytes())
    report_ref = next(
        ref for ref in root["artifacts"] if ref["name"] == "p6_10b_contract_closure_report"
    )
    report_path = result_root.parent / report_ref["path"]
    report = json.loads(report_path.read_bytes())
    for row in report["ablations"]:
        if row["ablation_id"] in replacements:
            row["primary_estimand"]["delta"] = replacements[row["ablation_id"]]
    report_raw = canonical_json_bytes(report)
    report_path.write_bytes(report_raw)
    report_ref["sha256"] = sha256_bytes(report_raw)
    report_ref["size_bytes"] = len(report_raw)
    root_raw = canonical_json_bytes(root)
    result_root.write_bytes(root_raw)
    return sha256_bytes(root_raw)


def test_independent_verifier_rejects_rehashed_default_precision_delta(tmp_path):
    if os.environ.get("P6_10B_RUN_FRESH_FULL_CHAIN") != "1":
        pytest.skip("set P6_10B_RUN_FRESH_FULL_CHAIN=1 for the generated full-chain fixture")
    target_root = _generate_fresh_test_result(tmp_path)
    corrected = {
        "abl_confidence_mvp__v1": _PRECISION_50_ESTIMAND_CASES[0][2],
        "abl_provider_rule__v1": _PRECISION_50_ESTIMAND_CASES[1][2],
    }
    report = json.loads((target_root.parent / p6_10b.P6_10B_REPORT).read_bytes())
    assert {
        row["ablation_id"]: row["primary_estimand"]["delta"] for row in report["ablations"]
    } == corrected
    valid_sha256 = sha256_bytes(target_root.read_bytes())

    verified = run_p6_10b_independent_verifier(
        target_root,
        expected_sha256=valid_sha256,
        repo_root=Path.cwd(),
    )
    assert verified["status"] == "verified"

    tampered_sha256 = _rewrite_primary_estimand_deltas(
        target_root,
        {"abl_confidence_mvp__v1": _PRECISION_50_ESTIMAND_CASES[0][3]},
    )
    assert tampered_sha256 != valid_sha256
    with pytest.raises(ValueError, match="report row reconstruction mismatch"):
        run_p6_10b_independent_verifier(
            target_root,
            expected_sha256=tampered_sha256,
            repo_root=Path.cwd(),
        )


@pytest.mark.parametrize(
    "mode",
    [
        "source_snapshot",
        "source_sampling",
        "source_catalog",
        "stream_root",
        "config",
        "execution_event",
        "action_draw_audit",
        "nested_evidence",
        pytest.param("artifact_ads", marks=pytest.mark.skipif(os.name != "nt", reason="NTFS ADS")),
    ],
)
def test_independent_verifier_rejects_rehashed_valid_result_tamper(tmp_path, mode):
    source_value = os.environ.get("P6_10B_FRESH_TEST_RESULT_ROOT")
    if source_value is None:
        pytest.skip("set P6_10B_FRESH_TEST_RESULT_ROOT to a generated fresh tmp fixture")
    source_root = _require_fresh_test_result(Path(source_value))
    target_root = (
        tmp_path
        / p6_10b.P6_10B_ARTIFACT_DIRECTORY
        / p6_10b.P6_10B_PHYSICAL_DIRECTORY
        / p6_10b.P6_10B_RESULT_ROOT
    )
    expected_sha256 = _rehash_valid_result_tamper(source_root, target_root, mode)

    expected_failure = {
        "source_snapshot": "approved source snapshot mismatch",
        "source_sampling": "fixed-source sampling contract mismatch",
        "source_catalog": "fixed-source opponent catalog mismatch",
        "stream_root": "stream-root exact product mismatch",
        "config": "retained ablation config mismatch",
        "execution_event": "execution event transcript mismatch",
        "action_draw_audit": "action draw audit transcript mismatch",
        "nested_evidence": "confidence ablation evidence is not closed-world",
        "artifact_ads": "artifact name/path mapping mismatch",
    }[mode]
    with pytest.raises(ValueError, match=expected_failure):
        run_p6_10b_independent_verifier(
            target_root,
            expected_sha256=expected_sha256,
            repo_root=Path.cwd(),
        )


@pytest.mark.parametrize(
    ("mode", "expected_failure"),
    [
        ("solver_iterations", "frozen equilibrium content hash mismatch"),
        ("unknown_field", "frozen equilibrium is not closed-world"),
    ],
)
def test_independent_verifier_rejects_fixed_equilibrium_tamper(tmp_path, mode, expected_failure):
    tree = ast.parse(p6_10b._INDEPENDENT_VERIFIER_SOURCE)
    function_names = {
        "canonical_no_lf",
        "digest",
        "load_source",
        "require_fields",
        "load_fixed_equilibrium",
    }
    helpers = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in function_names
    ]
    namespace = {
        "hashlib": hashlib,
        "json": json,
        "Path": Path,
        "PurePosixPath": PurePosixPath,
    }
    exec(
        compile(ast.Module(body=helpers, type_ignores=[]), "<equilibrium-fixture>", "exec"),
        namespace,
    )

    content = {
        "schema_version": "1.0.0",
        "artifact_type": "frozen-equilibrium",
        "equilibrium_version": "river-large-bet-equilibrium-v1",
        "game": {
            "builder": "poker_solver.river_tree.build_river_game",
            "builder_version": "river-single-bet-v1",
            "pot": "10",
            "bet_fraction": "0.5",
            "board": "fixture-board",
            "oop_range": {"OOP": "1"},
            "ip_range": {"IP": "1"},
        },
        "strategy": {"OOP:OOP:start": {"CHECK": "1", "BET": "0"}},
        "solver": {
            "algorithm": "fixture-solver",
            "implementation": "fixture-implementation",
            "iterations": 1,
            "average_delay": 0,
        },
    }
    declared = hashlib.sha256(
        json.dumps(
            content,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    equilibrium = {**content, "artifact_sha256": declared}
    equilibrium_path = (
        tmp_path
        / "configs"
        / "opponents"
        / "equilibria"
        / "river-large-bet-equilibrium-v1.equilibrium.json"
    )
    equilibrium_path.parent.mkdir(parents=True)
    if mode == "solver_iterations":
        equilibrium["solver"]["iterations"] += 1
    else:
        equilibrium["unexpected"] = False
    equilibrium_path.write_bytes(canonical_json_bytes(equilibrium))
    fixed_catalog = {"opponents": [{"equilibrium_artifact_sha256": declared}]}

    with pytest.raises(ValueError, match=expected_failure):
        namespace["load_fixed_equilibrium"](tmp_path, fixed_catalog)


def test_result_root_rejects_nested_extra_child_before_replay(tmp_path, monkeypatch):
    artifact_parent = tmp_path / p6_10b.P6_10B_ARTIFACT_DIRECTORY
    result_dir = artifact_parent / p6_10b.P6_10B_PHYSICAL_DIRECTORY
    result_dir.mkdir(parents=True)
    expected_names = [
        "p6_10b_batch_manifest",
        *[
            f"{ablation_id}__{suffix}"
            for ablation_id in (
                "abl_confidence_mvp__v1",
                "abl_provider_rule__v1",
            )
            for suffix in p6_10b._TYPE_SUFFIXES
        ],
        "p6_10b_contract_closure_report",
    ]
    file_names = {
        p6_10b.P6_10B_BATCH_MANIFEST,
        p6_10b.P6_10B_REPORT,
        *[f"{name}.json" for name in expected_names[1:-1]],
    }
    raw_artifact = canonical_json_bytes({})
    for name in file_names:
        (result_dir / name).write_bytes(raw_artifact)
    refs = []
    for index, name in enumerate(expected_names):
        filename = (
            p6_10b.P6_10B_BATCH_MANIFEST
            if index == 0
            else p6_10b.P6_10B_REPORT
            if index == len(expected_names) - 1
            else f"{name}.json"
        )
        refs.append(
            {
                "name": name,
                "path": filename,
                "sha256": sha256_bytes(raw_artifact),
                "size_bytes": len(raw_artifact),
            }
        )
    source = {"fixture": "source"}
    root_payload = {
        "schema_version": p6_10b.P6_10B_RESULT_ROOT_SCHEMA_VERSION,
        "artifact_type": "p6_10b_result_root",
        "scope": "p6_10b_confidence_provider_ablation",
        "physical_directory": p6_10b.P6_10B_PHYSICAL_DIRECTORY,
        "source_snapshot": source,
        "p6_10b_batch_manifest_sha256": "1" * 64,
        "expected_cardinality": p6_10b._EXPECTED_CARDINALITY,
        "manual_override": False,
        "series_pooling": False,
        "primary_selection_recomputed": False,
        "p6_9_artifacts_modified": False,
        "p6_10a_artifacts_modified": False,
        "p6_10_complete": False,
        "gate_b_ready": False,
        "human_approval_required": True,
        "artifacts": refs,
    }
    root_raw = canonical_json_bytes(root_payload)
    root_path = result_dir / p6_10b.P6_10B_RESULT_ROOT
    root_path.write_bytes(root_raw)
    (result_dir / "unexpected-nested-child").mkdir()
    monkeypatch.setattr(p6_10b, "_source_snapshot", lambda _snapshot: source)

    with pytest.raises(ValueError, match="directory is not closed-world"):
        p6_10b.verify_p6_10b_result_root(
            root_path,
            expected_sha256=sha256_bytes(root_raw),
            repo_root=tmp_path,
            snapshot=SimpleNamespace(),
        )


def test_failed_attempt_retains_marker_and_failure_record(tmp_path, monkeypatch):
    import phase6.p6_10b_freeze as p6_10b_freeze

    repo_root = tmp_path / "repo"
    output_root = repo_root / "experiments_output" / p6_10b_freeze.P6_10B_OUTPUT_ROOT_NAME
    output_root.parent.mkdir(parents=True)
    source = repo_root / "source.json"
    source.write_bytes(canonical_json_bytes({"fixture": True}))
    frozen = {
        "paths": {"output_root": str(output_root)},
        "git": {"expected_target_commit": "1" * 40},
        "manifest_sha256": "2" * 64,
        "p6_10b_batch_manifest": {"sha256": "3" * 64},
        "source_snapshot": {"p6_10a_run_manifest": {"path": "source.json"}},
    }
    monkeypatch.setattr(
        p6_10b_freeze,
        "verify_p6_10b_freeze_manifest",
        lambda *_args, **_kwargs: frozen,
    )
    monkeypatch.setattr(
        p6_10b,
        "load_p6_10a_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("fixture failure")),
    )

    with pytest.raises(RuntimeError, match="fixture failure"):
        p6_10b.run_p6_10b_from_freeze(
            tmp_path / "freeze.json",
            tmp_path / "freeze.sha256.json",
            repo_root=repo_root,
        )
    assert (output_root / p6_10b.P6_10B_ATTEMPT_MARKER).is_file()
    failure = p6_10b._strict_object(
        (output_root / p6_10b.P6_10B_FAILURE_RECORD).read_bytes(), "fixture failure"
    )
    assert failure["status"] == "failed_verification"
    assert failure["partial_retention"] == "preserve_without_cleanup"
    assert not (output_root / p6_10b.P6_10B_RUN_MANIFEST).exists()


def test_run_manifest_binds_frozen_namespace_and_immutable_marker(tmp_path, monkeypatch):
    import phase6.p6_10b_freeze as p6_10b_freeze

    output_root = tmp_path / "canonical-output"
    result_path = (
        output_root
        / p6_10b.P6_10B_ARTIFACT_DIRECTORY
        / p6_10b.P6_10B_PHYSICAL_DIRECTORY
        / p6_10b.P6_10B_RESULT_ROOT
    )
    result_path.parent.mkdir(parents=True)
    result_path.write_bytes(canonical_json_bytes({"fixture": "result"}))
    freeze_path = tmp_path / "freeze.json"
    sidecar_path = tmp_path / "freeze.sha256.json"
    freeze_path.write_bytes(canonical_json_bytes({"fixture": "freeze"}))
    sidecar_path.write_bytes(canonical_json_bytes({"fixture": "sidecar"}))
    frozen = {
        "paths": {"output_root": str(output_root)},
        "git": {"expected_target_commit": "1" * 40},
        "runtime": {"python": "fixture"},
        "dependency_lock": {"sha256": "2" * 64},
        "p6_10b_batch_manifest": {"sha256": "3" * 64},
        "source_snapshot": {"fixture": "source"},
        "manifest_sha256": "4" * 64,
    }
    marker = {
        "schema_version": p6_10b.P6_10B_ATTEMPT_SCHEMA_VERSION,
        "artifact_type": "p6_10b_attempt_marker",
        "attempt_id": p6_10b.P6_10B_ATTEMPT_ID,
        "attempt_number": 1,
        "retry_count": 0,
        "status": "reserved_in_progress",
        "target_commit": frozen["git"]["expected_target_commit"],
        "freeze_manifest_sha256": frozen["manifest_sha256"],
        "p6_10b_batch_manifest_sha256": frozen["p6_10b_batch_manifest"]["sha256"],
        "partial_retention": "preserve_without_cleanup",
    }
    marker_path = output_root / p6_10b.P6_10B_ATTEMPT_MARKER
    marker_path.write_bytes(canonical_json_bytes(marker))
    payload = {
        "schema_version": p6_10b.P6_10B_RUN_SCHEMA_VERSION,
        "artifact_type": "phase6_p6_10b_run_manifest",
        "cli_version": p6_10b.P6_10B_CLI_VERSION,
        "status": "completed_and_verified",
        "scope": "p6_10b_confidence_provider_ablation",
        "git": frozen["git"],
        "runtime": frozen["runtime"],
        "timing": {
            "started_at_utc": "2026-07-19T00:00:00+00:00",
            "finished_at_utc": "2026-07-19T00:00:01+00:00",
        },
        "inputs": {
            "freeze_manifest": p6_10b._absolute_reference(freeze_path),
            "freeze_hash_sidecar": p6_10b._absolute_reference(sidecar_path),
            "dependency_lock": frozen["dependency_lock"],
            "p6_10b_batch_manifest": frozen["p6_10b_batch_manifest"],
            "source_snapshot": frozen["source_snapshot"],
        },
        "attempt": {
            "attempt_id": p6_10b.P6_10B_ATTEMPT_ID,
            "attempt_number": 1,
            "retry_count": 0,
            "marker": p6_10b._relative_reference(output_root, marker_path),
        },
        "outputs": {"p6_10b_result_root": p6_10b._relative_reference(output_root, result_path)},
        "p6_10_complete": False,
        "gate_b_ready": False,
        "human_approval_required": True,
    }
    run_path = output_root / p6_10b.P6_10B_RUN_MANIFEST
    run_path.write_bytes(canonical_json_bytes(payload))
    monkeypatch.setattr(
        p6_10b_freeze, "verify_p6_10b_freeze_manifest", lambda *_args, **_kwargs: frozen
    )
    monkeypatch.setattr(
        p6_10b,
        "verify_p6_10b_result_root",
        lambda *_args, **_kwargs: {
            "p6_10b_batch_manifest_sha256": frozen["p6_10b_batch_manifest"]["sha256"]
        },
    )

    assert p6_10b.verify_p6_10b_run_manifest(run_path, repo_root=tmp_path) == payload

    marker_path.write_bytes(canonical_json_bytes({**marker, "status": "completed"}))
    payload["attempt"]["marker"] = p6_10b._relative_reference(output_root, marker_path)
    run_path.write_bytes(canonical_json_bytes(payload))
    with pytest.raises(ValueError, match="marker was mutated"):
        p6_10b.verify_p6_10b_run_manifest(run_path, repo_root=tmp_path)

    alternate_root = tmp_path / "alternate-output"
    alternate_root.mkdir()
    alternate_run = alternate_root / p6_10b.P6_10B_RUN_MANIFEST
    alternate_run.write_bytes(canonical_json_bytes(payload))
    with pytest.raises(ValueError, match="outside the frozen canonical output root"):
        p6_10b.verify_p6_10b_run_manifest(alternate_run, repo_root=tmp_path)
