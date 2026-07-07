"""Write Phase 4 gate node-lock sensitivity evidence as JSON.

Usage::

    python cli/phase4_gate_nodelock_sensitivity.py

The output is intentionally written under ``experiments_output/``. That tree is
gitignored, but it is kept in the workspace as the primary Phase 4 gate evidence
artifact for the opponent-overfold allocation comparison.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from poker_ai.scenario import Scenario
from poker_solver.nodelock import (
    COMBO_ALLOCATIONS,
    ComboAllocation,
    NodeLockRule,
    analyze_nodelock_sensitivity,
)

DEFAULT_BET_FRACTION = 0.5
DEFAULT_ITERATIONS = 20
DEFAULT_TARGET_FREQUENCIES = (0.5, 0.65, 0.75)
DEFAULT_OUTPUT_DIR = Path("experiments_output/phase4_gate_nodelock_sensitivity")
DEFAULT_OUTPUT_NAME = "phase4_gate_nodelock_sensitivity.json"


def _phase4_gate_scenario() -> Scenario:
    return Scenario(
        scenario_id="NL-OVERFOLD",
        board=("8c", "Qc", "3s", "Jc", "Jd"),
        position="OOP",
        pot=8.0,
        effective_stack=10.0,
        hero_combo="Qs7d",
        hero_range={"Qs7d": 1.0, "Jh5c": 1.0, "Ah6h": 1.0},
        opponent_range={"Js7c": 1.0, "Kh5d": 1.0, "3h2s": 1.0},
    )


def _current_git_commit(repo_root: Path) -> str:
    try:
        out = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={repo_root.as_posix()}",
                "rev-parse",
                "HEAD",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"
    commit = out.stdout.strip()
    return commit if commit else "unknown"


def _report_payload(
    *,
    repo_root: Path,
    iterations: int,
    target_frequencies: tuple[float, ...],
    combo_allocations: tuple[ComboAllocation, ...],
) -> dict[str, Any]:
    scenario = _phase4_gate_scenario()
    rule = NodeLockRule(
        actor="IP",
        phase="vs_bet",
        action="FOLD",
        target_frequency=0.0,
        rule_id="phase4_gate_opponent_overfold",
    )
    report = analyze_nodelock_sensitivity(
        scenario,
        bet_fraction=DEFAULT_BET_FRACTION,
        iterations=iterations,
        rule=rule,
        target_frequencies=target_frequencies,
        combo_allocations=combo_allocations,
        unlocked_policy_mode="resolve",
    )
    return {
        "metadata": {
            "artifact_id": "phase4_gate_nodelock_sensitivity",
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "git_commit": _current_git_commit(repo_root),
            "scenario_id": scenario.scenario_id,
            "bet_fraction": DEFAULT_BET_FRACTION,
            "iterations": iterations,
            "target_frequencies": list(target_frequencies),
            "combo_allocations": list(combo_allocations),
            "lock_mode": "HARD",
            "unlocked_policy_mode": "resolve",
            "columns": {
                "target": "target_frequency",
                "allocation": "combo_allocation",
            },
        },
        "scenario": scenario.model_dump(mode="json"),
        "rule": {
            "rule_id": rule.rule_id,
            "actor": rule.actor,
            "phase": rule.phase,
            "infoset": rule.infoset,
            "action": rule.action,
            "target_frequency_source": "sweep",
            "target_frequencies": list(target_frequencies),
            "combo_allocations": list(combo_allocations),
        },
        "report": {
            "scenario_id": report.scenario_id,
            "action": report.action,
            "actor": report.actor,
            "phase": report.phase,
            "infoset": report.infoset,
            "lock_mode": report.lock_mode,
            "unlocked_policy_mode": report.unlocked_policy_mode,
            "base_game_value": report.base_game_value,
            "points": [asdict(point) for point in report.points],
            "allocation_comparisons": [
                asdict(comparison) for comparison in report.allocation_comparisons
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"CFR+ iterations for base and resolve solves (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--target",
        dest="targets",
        type=float,
        action="append",
        help="target FOLD frequency; repeat to override the default sweep",
    )
    parser.add_argument(
        "--combo-allocation",
        dest="combo_allocations",
        choices=COMBO_ALLOCATIONS,
        action="append",
        help="combo allocation rule; repeat to override the default allocations",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=repo_root / DEFAULT_OUTPUT_DIR,
        help=f"output directory (default: {DEFAULT_OUTPUT_DIR.as_posix()})",
    )
    parser.add_argument(
        "--output-name",
        default=DEFAULT_OUTPUT_NAME,
        help=f"output JSON filename (default: {DEFAULT_OUTPUT_NAME})",
    )
    args = parser.parse_args(argv)

    target_frequencies = tuple(args.targets or DEFAULT_TARGET_FREQUENCIES)
    combo_allocations = tuple(args.combo_allocations or COMBO_ALLOCATIONS)
    payload = _report_payload(
        repo_root=repo_root,
        iterations=args.iterations,
        target_frequencies=target_frequencies,
        combo_allocations=combo_allocations,
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    output_path = args.out_dir / args.output_name
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
