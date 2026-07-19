"""Unit/tmp fixtures for the closed-world P6-10A report boundary."""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import phase6.p6_10 as p6_10
from phase6 import (
    ABL_EPSILON_ZERO_ID,
    HORIZONS,
    P69Snapshot,
    PrimaryCandidate,
    ValidationArtifactRecord,
    ValidationBatchPlan,
    ValidationSessionKey,
    build_p6_10a_batch,
    canonical_json_bytes,
    sha256_bytes,
    verify_p6_10a_batch,
)


def _snapshot(tmp_path: Path) -> P69Snapshot:
    repo_root = tmp_path / "repo"
    run_path = repo_root / "source" / "phase6_validation_run_manifest.json"
    result_path = repo_root / "source" / "validation_result_root.json"
    artifact_root = result_path.parent
    artifact_root.mkdir(parents=True)
    selected = PrimaryCandidate(
        "primary_bb_v2__" + p6_10.P6_9_SELECTED_CONFIG_SHA256,
        "0.05",
        10,
        "0.9",
        "0.9",
        "0.5",
        "a" * 64,
    )
    other_candidates = tuple(
        PrimaryCandidate(
            f"primary_bb_v2__{index:064x}", "0.1", 25, "0.95", "0.95", "0.25", "a" * 64
        )
        for index in range(15)
    )
    opponents = tuple(f"opponent-{index:02d}" for index in range(9))
    sessions = tuple(
        ValidationSessionKey(selected.candidate_id, opponent_id, horizon, f"r{rep:03d}")
        for opponent_id in opponents
        for horizon in HORIZONS
        for rep in range(1, 31)
    )
    plan = ValidationBatchPlan(
        {"sampling_contract": {"payload": {"fixture": True}, "sha256": "a" * 64}},
        b"fixture\n",
        p6_10.P6_9_VALIDATION_BATCH_SHA256,
        tuple(sorted((selected, *other_candidates), key=lambda item: item.candidate_id)),
        sessions,
    )
    lock = {
        "selected_candidate_id": selected.candidate_id,
        "selected_config": selected.canonical_payload(),
    }
    aggregate = {
        "records": [
            {
                "candidate_id": selected.candidate_id,
                "payload": {"result": {"series_id": "b" * 64}},
            }
        ]
    }
    return P69Snapshot(
        repo_root,
        run_path,
        {},
        result_path,
        {},
        artifact_root,
        {"validation_aggregate_metrics": aggregate, "validation_exact_ev_cells": {}},
        {},
        plan,
        selected,
        lock,
        {},
    )


def test_epsilon_zero_batch_changes_only_epsilon_and_never_pools(tmp_path):
    snapshot = _snapshot(tmp_path)
    batch = build_p6_10a_batch(snapshot)

    assert batch.candidate.candidate_id.startswith(f"{ABL_EPSILON_ZERO_ID}__")
    assert batch.candidate.epsilon == "0"
    assert batch.candidate.sample_floor == snapshot.selected_candidate.sample_floor
    assert batch.candidate.detector_confidence == "0.9"
    assert batch.candidate.provider_confidence == "0.9"
    assert batch.candidate.safety_alpha == "0.5"
    assert len(batch.sessions) == 810
    assert len(batch.manifest["stream_roots"]) == 3240
    assert batch.manifest["series_non_pooling"] == {
        "pool_with_selected_series": False,
        "candidate_id_distinct": True,
        "config_sha256_distinct": True,
    }
    assert batch.manifest["manual_override"] is False
    assert batch.manifest["primary_selection_recomputed"] is False

    forged = copy.deepcopy(batch.manifest)
    forged["epsilon_zero_candidate"]["config"]["sample_floor"] = 25
    raw = canonical_json_bytes(forged)
    with pytest.raises(ValueError, match="exact one-field replacement"):
        verify_p6_10a_batch(
            replace(batch, manifest=forged, manifest_bytes=raw, manifest_sha256=sha256_bytes(raw)),
            snapshot=snapshot,
        )


def _exact_ev_records(candidate_id: str) -> list[dict[str, object]]:
    records = []
    for opponent_index in range(9):
        for horizon in HORIZONS:
            for repetition in range(1, 31):
                records.append(
                    {
                        "candidate_id": candidate_id,
                        "opponent_id": f"opponent-{opponent_index:02d}",
                        "horizon": horizon,
                        "repetition_id": f"r{repetition:03d}",
                        "payload": {
                            "result": {
                                "cell": {
                                    "base_ev": {
                                        "production_binary64_hex": (0.25).hex(),
                                        "independent_leaves_binary64_hex": (0.25).hex(),
                                    },
                                    "oracle_br_ev": {
                                        "production_binary64_hex": (0.5).hex(),
                                        "independent_leaves_binary64_hex": (0.5).hex(),
                                    },
                                }
                            }
                        },
                    }
                )
    return records


def test_comparators_use_saved_exact_ev_and_alpha_is_exact_zero_delta(tmp_path):
    snapshot = _snapshot(tmp_path)
    records = _exact_ev_records(snapshot.selected_candidate.candidate_id)
    snapshot.artifact_payloads["validation_exact_ev_cells"] = {"records": records}
    batch = build_p6_10a_batch(snapshot)
    aggregate_record = ValidationArtifactRecord(
        batch.candidate.candidate_id,
        "c" * 64,
        {"result": {"series_id": "d" * 64}},
    )
    epsilon_records = {
        "validation_aggregate_metrics": (aggregate_record,),
    }
    references = {
        name: {"name": name, "path": f"{name}.json", "sha256": "e" * 64, "size_bytes": 1}
        for name in p6_10._EPSILON_ARTIFACT_NAMES
    }

    report = p6_10._comparator_ablation_report(
        snapshot,
        batch,
        references,
        epsilon_records,
    )

    base, oracle, alpha = report["comparators"]
    assert base["source_value"] == "EV(pi_base)"
    assert base["aggregation"]["macro_mean_ev"] == "0.25"
    assert base["aggregation"]["micro_mean_ev"] == "0.25"
    assert len(base["aggregation"]["cells"]) == 810
    assert oracle["source_value"] == "EV(oracle_br)"
    assert oracle["aggregation"]["micro_mean_ev"] == "0.5"
    assert len(oracle["aggregation"]["cells"]) == 810
    assert alpha["comparator_status"] == "degenerate_equal_to_primary"
    assert alpha["closed_world_deltas"]["macro_ev_delta"] == "0"
    assert alpha["closed_world_deltas"]["micro_ev_delta"] == "0"
    assert len(alpha["closed_world_deltas"]["cells"]) == 810
    assert {item["ev_delta"] for item in alpha["closed_world_deltas"]["cells"]} == {"0"}
    assert {item["ev_delta"] for item in alpha["closed_world_deltas"]["atomic_groups"]} == {"0"}
    assert report["p6_10_complete"] is False
    assert report["gate_b_ready"] is False


def test_gate_b_packet_keeps_unresolved_ablations_and_human_gate(tmp_path):
    snapshot = _snapshot(tmp_path)
    batch = build_p6_10a_batch(snapshot)

    packet = p6_10._gate_b_gap_packet(snapshot, batch)

    assert packet["p6_10a_report_complete"] is True
    assert packet["p6_10_complete"] is False
    assert packet["gate_b_ready"] is False
    assert packet["human_approval_required"] is True
    assert [item["id"] for item in packet["unresolved_gaps"]] == [
        "abl_confidence_mvp__v1",
        "abl_provider_rule__v1",
    ]
    assert all(
        item["missing_contract_fields"]
        == [
            "estimand",
            "retained_and_replaced_boundaries",
            "cardinality",
            "schema",
            "production_discipline",
        ]
        for item in packet["unresolved_gaps"]
    )


def test_ev_summary_rejects_cross_path_disagreement(tmp_path):
    snapshot = _snapshot(tmp_path)
    records = _exact_ev_records(snapshot.selected_candidate.candidate_id)
    records[0]["payload"]["result"]["cell"]["base_ev"]["independent_leaves_binary64_hex"] = (
        0.5
    ).hex()

    with pytest.raises(ValueError, match="paths disagree"):
        p6_10._ev_summary(records, "base_ev")


def test_pinned_verifier_adapter_requires_clean_pushed_direct_child(tmp_path, monkeypatch):
    import phase6.validation_cli as validation_cli
    import phase6.validation_freeze as validation_freeze

    target = "1" * 40
    state = SimpleNamespace(
        branch="main",
        head_commit=target,
        local_main_commit=target,
        cached_origin_main_commit=target,
        dirty=False,
    )
    observed = []
    monkeypatch.setattr(validation_freeze, "_read_repository_state", lambda _root: state)
    monkeypatch.setattr(
        p6_10,
        "_git_stdout",
        lambda _root, *args: (
            f"{target} {p6_10.P6_9_BASELINE}"
            if args[0] == "rev-list"
            else "src/phase6/p6_10.py\ntests/phase6/test_p6_10.py"
        ),
    )

    def verifier(_path, *, repo_root):
        del repo_root
        observed.append(validation_cli._read_repository_state(tmp_path))
        observed.append(validation_freeze._read_repository_state(tmp_path))
        return {"status": "completed_and_verified"}

    monkeypatch.setattr(p6_10, "verify_validation_run_manifest", verifier)
    verified, mode, commit = p6_10._run_pinned_p6_9_verifier(
        tmp_path / "run.json",
        repo_root=tmp_path,
    )

    assert verified == {"status": "completed_and_verified"}
    assert mode == "unchanged_p6_9_verifier_with_direct_child_git_adapter"
    assert commit == target
    assert {item.head_commit for item in observed} == {p6_10.P6_9_BASELINE}
    assert validation_freeze._read_repository_state(tmp_path) is state
