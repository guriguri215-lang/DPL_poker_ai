"""Shared fixtures: valid example payloads for the frozen contracts.

Each fixture returns a freshly built ``dict`` so a test can copy-and-mutate it to
construct invalid variants without affecting other tests.
"""

from __future__ import annotations

import copy

import pytest


def _valid_dpl() -> dict:
    """A valid DPL dict.

    Uses the Poker AI Spec 6.11 example situation, remapped to ADR-0001 reason
    ids, with policies chosen so ``final`` is exactly the alpha-mix of base and
    exploit (base BET_75 0.4 -> final 0.6 at alpha 0.5).
    """
    return {
        "hand_id": "H000421",
        "session_id": "S0001",
        "schema_version": "2.0.0",
        "state_cluster": "river_flush_complete",
        "cluster_def_version": "1.0.0",
        "hand_bucket": "strong_value",
        "hero_combo": "AhKh",
        "base_policy": {"CHECK": 0.6, "BET_75": 0.4},
        "detected_leaks": [
            {
                "reason_id": "LEAK_R001",
                "leak_type": "river_large_bet_overfold",
                "situation_key": "river_flush_complete:facing_BET_75",
                "observed_rate": 0.64,
                "baseline_rate": 0.48,
                "effective_sample_size": 37,
                "confidence": 0.74,
                "direction": "increase_large_bet_frequency",
            }
        ],
        "trigger_reasons": ["TRG_R001", "TRG_R002", "TRG_R003"],
        "mix_reasons": ["MIX_R001"],
        "exploit_policy": {"CHECK": 0.2, "BET_75": 0.8},
        "exploit_source": "rule_based",
        "solver_result_id": None,
        "safety_alpha": 0.5,
        "final_policy": {"CHECK": 0.4, "BET_75": 0.6},
        "selected_action": "BET_75",
        "sampling_seed": 123456,
        "ev_estimate": {
            "base_ev": 4.12,
            "exploit_ev": 4.46,
            "final_ev": 4.27,
            "worst_case_penalty": -0.08,
            "ev_source": "solver_exact",
            "ev_unit": "bb",
            "ev_definition": "incremental_ev_from_current_node",
        },
        "allowed_reason_ids": [
            "LEAK_R001",
            "TRG_R001",
            "TRG_R002",
            "TRG_R003",
            "MIX_R001",
        ],
        "baseline_table_version": "1.0.0",
    }


def _valid_manifest() -> dict:
    return {
        "run_id": "R0001",
        "description": "smoke run",
        "code": {
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "git_dirty": False,
            "package_version": "0.0.0",
            "python_version": "3.12.0",
            "entrypoint": "cli/run_session.py",
            "argv": ["--manifest", "demo.json"],
        },
        "versions": {
            "reason_ontology_version": "1.1.0",
            "cluster_def_version": "1.0.0",
            "strategy_table_version": "1.0.0",
            "baseline_table_version": "1.0.0",
        },
        "seeds": {"master": 42, "sampling": 123456},
        "configs": [
            {
                "name": "scenario",
                "role": "scenario",
                "path": "configs/scenario.yaml",
                "sha256": "a" * 64,
            }
        ],
        "opponents": [
            {
                "opponent_id": "overfold_0.16",
                "opponent_version": "1.0.0",
                "split": "training",
            }
        ],
    }


def _valid_strategy_table() -> dict:
    return {
        "table_version": "1.0.0",
        "situation_key": "river_flush_complete:IP:facing_none",
        "cluster_def_version": "1.0.0",
        "source": "cfr_base_solve",
        "entries": [
            {"combo": "AhKh", "policy": {"CHECK": 0.2, "BET_75": 0.8}, "reach_prob": 0.6},
            {"combo": "QsQd", "policy": {"CHECK": 0.7, "BET_75": 0.3}, "reach_prob": 0.4},
        ],
    }


@pytest.fixture
def valid_dpl() -> dict:
    return copy.deepcopy(_valid_dpl())


@pytest.fixture
def valid_manifest() -> dict:
    return copy.deepcopy(_valid_manifest())


@pytest.fixture
def valid_strategy_table() -> dict:
    return copy.deepcopy(_valid_strategy_table())
