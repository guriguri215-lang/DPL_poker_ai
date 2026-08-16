"""E2E tests for the P5-4 leaky-fixture explanation artifacts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from explanation import ExplanationDocument, verify_explanation
from poker_core.dpl_schema import DecisionProvenanceLog
from poker_core.run_manifest import RunManifest


def test_p5_4_artifact_cli_writes_verified_leaky_fixture_outputs(tmp_path, capsys):
    cli = _load_artifact_cli()
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    # This is the smallest fixed prefix that crosses the canonical confidence
    # gate and reaches an eligible OOP node-lock topology on its second hand.
    for output_root in (first_root, second_root):
        assert (
            cli.main(
                [
                    "--seed",
                    "32",
                    "--hands",
                    "2",
                    "--out-dir",
                    str(output_root),
                ]
            )
            == 0
        )

    out = capsys.readouterr().out
    assert out.count("2/2 explanations verified") == 2
    assert out.count("pass_rate=1.000") == 2

    dpl_path = first_root / "S00000032.dpl.jsonl"
    explanations_path = first_root / "S00000032.explanations.jsonl"
    summary_path = first_root / "S00000032.verifier_summary.json"
    manifest_path = first_root / "S00000032.manifest.json"
    assert dpl_path.exists()
    assert explanations_path.exists()
    assert summary_path.exists()
    assert manifest_path.exists()

    dpls = [
        DecisionProvenanceLog.model_validate(json.loads(line))
        for line in dpl_path.read_text(encoding="utf-8").splitlines()
    ]
    explanations = [
        ExplanationDocument.model_validate(json.loads(line))
        for line in explanations_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(dpls) == len(explanations) == 2
    assert all(log.detected_leaks for log in dpls)
    assert any(log.mix_reasons for log in dpls)

    solver_pairs = [
        (dpl, explanation)
        for dpl, explanation in zip(dpls, explanations, strict=True)
        if dpl.exploit_source == "nodelock_solver"
    ]
    assert solver_pairs
    for dpl, explanation in solver_pairs:
        assert dpl.ev_estimate.exploit_ev > dpl.ev_estimate.base_ev
        assert dpl.solver_result_id
        assert dpl.solver_result_id in explanation.rendered_text

    for dpl, explanation in zip(dpls, explanations, strict=True):
        result = verify_explanation(explanation, dpl)
        assert result.passed, result.issues

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["metadata"]["artifact_id"] == "p5_4_e2e_explanation_artifacts"
    assert summary["verification"]["total"] == 2
    assert summary["verification"]["passed"] == 2
    assert summary["verification"]["failed"] == 0
    assert summary["verification"]["pass_rate"] == 1.0
    assert summary["verification"]["failures"] == []
    assert summary["session"]["detected_leaks"] == 2

    manifest = RunManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert manifest.run_id == "S00000032"
    assert manifest.code.entrypoint == "cli/p5_4_e2e_explanation_artifacts.py"
    assert manifest.versions.baseline_table_version == "fixture-action-baseline"
    assert {output.name for output in manifest.outputs} == {
        "S00000032.dpl.jsonl",
        "S00000032.explanations.jsonl",
        "S00000032.verifier_summary.json",
        "action_stats_terminal_snapshots",
    }
    assert all(output.sha256 for output in manifest.outputs)

    second_dpl_path = second_root / dpl_path.name
    second_explanations_path = second_root / explanations_path.name
    second_summary_path = second_root / summary_path.name
    assert dpl_path.read_bytes() == second_dpl_path.read_bytes()
    assert explanations_path.read_bytes() == second_explanations_path.read_bytes()

    second_summary = json.loads(second_summary_path.read_text(encoding="utf-8"))
    summary["metadata"].pop("generated_at_utc")
    second_summary["metadata"].pop("generated_at_utc")
    assert summary == second_summary


def _load_artifact_cli():
    path = Path(__file__).resolve().parents[2] / "cli" / "p5_4_e2e_explanation_artifacts.py"
    spec = importlib.util.spec_from_file_location("p5_4_e2e_explanation_artifacts_cli", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
