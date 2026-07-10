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

    rc = cli.main(
        [
            "--seed",
            "20260704",
            "--hands",
            "3",
            "--out-dir",
            str(tmp_path),
        ]
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "3/3 explanations verified" in out
    assert "pass_rate=1.000" in out

    dpl_path = tmp_path / "S20260704.dpl.jsonl"
    explanations_path = tmp_path / "S20260704.explanations.jsonl"
    summary_path = tmp_path / "S20260704.verifier_summary.json"
    manifest_path = tmp_path / "S20260704.manifest.json"
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
    assert len(dpls) == len(explanations) == 3
    assert all(log.detected_leaks for log in dpls)
    assert any(log.mix_reasons for log in dpls)

    for dpl, explanation in zip(dpls, explanations, strict=True):
        result = verify_explanation(explanation, dpl)
        assert result.passed, result.issues

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["metadata"]["artifact_id"] == "p5_4_e2e_explanation_artifacts"
    assert summary["verification"]["total"] == 3
    assert summary["verification"]["passed"] == 3
    assert summary["verification"]["failed"] == 0
    assert summary["verification"]["pass_rate"] == 1.0
    assert summary["verification"]["failures"] == []
    assert summary["session"]["detected_leaks"] == 3

    manifest = RunManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert manifest.run_id == "S20260704"
    assert manifest.code.entrypoint == "cli/p5_4_e2e_explanation_artifacts.py"
    assert manifest.versions.baseline_table_version == "fixture-action-baseline"
    assert {output.name for output in manifest.outputs} == {
        "S20260704.dpl.jsonl",
        "S20260704.explanations.jsonl",
        "S20260704.verifier_summary.json",
        "action_stats_terminal_snapshots",
    }
    assert all(output.sha256 for output in manifest.outputs)


def _load_artifact_cli():
    path = Path(__file__).resolve().parents[2] / "cli" / "p5_4_e2e_explanation_artifacts.py"
    spec = importlib.util.spec_from_file_location("p5_4_e2e_explanation_artifacts_cli", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
