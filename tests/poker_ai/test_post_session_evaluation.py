from __future__ import annotations

from copy import deepcopy

import pytest

from explanation import generate_template_explanation, verify_explanation
from poker_ai.base_policy import StubBasePolicyProvider
from poker_ai.leak import LeakDetectorConfig
from poker_ai.opponent import OpponentAnswerKey
from poker_ai.post_session_evaluation import evaluate_post_session
from poker_ai.session import run_session
from poker_core.dpl_schema import DecisionProvenanceLog


@pytest.fixture(scope="module")
def base_log() -> DecisionProvenanceLog:
    result = run_session(
        19,
        1,
        _base_policy_provider=StubBasePolicyProvider(),
    )
    return result.logs[0]


def _record(*, detected: bool, k: int, n: int) -> dict[str, object]:
    return {
        "opponent_id": "fixture-opponent",
        "rule_id": "LEAK_R008",
        "situation_key": "fixture-situation",
        "action_group": ["BET_ALL_IN"],
        "n": n,
        "k": k,
        "q": 0.25,
        "candidate_eligibility": {
            "structurally_eligible": True,
            "detected": detected,
        },
    }


def _neutral_log(
    base_log: DecisionProvenanceLog,
    *,
    safety_alpha: float = 0.5,
    cited_false_positive: bool = False,
) -> DecisionProvenanceLog:
    payload = deepcopy(base_log.model_dump(mode="json"))
    payload["safety_alpha"] = safety_alpha
    if cited_false_positive:
        payload["detected_leaks"] = [
            {
                "reason_id": "LEAK_R008",
                "leak_type": "bet_too_often_when_checked_to",
                "situation_key": "fixture-situation",
                "observed_rate": 1.0,
                "baseline_rate": 0.0,
                "effective_sample_size": 1,
                "confidence": 0.75,
                "direction": "decrease_bet_frequency_when_checked_to",
            }
        ]
        payload["allowed_reason_ids"] = ["LEAK_R008"]
    return DecisionProvenanceLog.model_validate(payload)


def _adjusted_log(
    base_log: DecisionProvenanceLog,
    *,
    base_ev: float,
    exploit_ev: float,
    final_ev: float,
) -> DecisionProvenanceLog:
    payload = deepcopy(base_log.model_dump(mode="json"))
    payload.update(
        {
            "base_policy": {"FOLD": 1.0, "CALL": 0.0},
            "exploit_policy": {"FOLD": 0.0, "CALL": 1.0},
            "final_policy": {"FOLD": 0.5, "CALL": 0.5},
            "selected_action": "FOLD",
            "safety_alpha": 0.5,
            "mix_reasons": ["MIX_R001"],
            "allowed_reason_ids": ["MIX_R001"],
            "ev_estimate": {
                "base_ev": base_ev,
                "exploit_ev": exploit_ev,
                "final_ev": final_ev,
                "worst_case_penalty": None,
                "ev_source": "solver_exact",
                "ev_unit": base_log.ev_estimate.ev_unit,
                "ev_definition": base_log.ev_estimate.ev_definition,
            },
        }
    )
    return DecisionProvenanceLog.model_validate(payload)


def _evaluate(
    log: DecisionProvenanceLog,
    *,
    record: dict[str, object],
    answer_key: OpponentAnswerKey,
    detector_config: LeakDetectorConfig,
):
    explanation = generate_template_explanation(log)
    checker = verify_explanation(explanation, log)
    assert checker.passed, checker.issues
    return evaluate_post_session(
        session_id=log.session_id,
        opponent_model_id="fixture-opponent",
        logs=[log],
        snapshot_records=[record],
        answer_key=answer_key,
        explanations=[explanation],
        checker_results=[checker],
        detector_config=detector_config,
        safety_alpha=log.safety_alpha,
        epsilon=0.2,
    )


def test_false_positive_is_truth_invalid_and_conservative(base_log):
    config = LeakDetectorConfig(
        min_effective_sample_size=1,
        min_confidence=0.5,
    )
    log = _neutral_log(base_log, cited_false_positive=True)
    answer_key = OpponentAnswerKey(
        "fixture-opponent",
        (("BET_ALL_IN", 0.2), ("CHECK", 0.8)),
    )

    artifact = _evaluate(
        log,
        record=_record(detected=True, k=1, n=1),
        answer_key=answer_key,
        detector_config=config,
    )

    assert artifact.evaluation.leak_detection_accuracy == 0.0
    assert artifact.evaluation.average_estimation_error == pytest.approx(0.8)
    assert artifact.evaluation.explanation_validity_score == 0.0
    assert "outcome:false_positive_count=1" in artifact.evaluation.notes
    assert artifact.next_session_settings.leak_detector_config.min_confidence == 1.0
    assert artifact.next_session_settings.leak_detector_config.rule_exploit_min_confidence == 1.0
    assert artifact.next_session_settings.safety_alpha == 0.0
    assert artifact.next_session_settings.epsilon == 0.0


def test_false_negative_holds_settings_and_never_auto_increases_aggression(base_log):
    config = LeakDetectorConfig(min_effective_sample_size=10)
    log = _neutral_log(base_log)
    answer_key = OpponentAnswerKey("fixture-opponent", (("BET_ALL_IN", 1.0),))

    first = _evaluate(
        log,
        record=_record(detected=False, k=1, n=1),
        answer_key=answer_key,
        detector_config=config,
    )
    second = _evaluate(
        log,
        record=_record(detected=False, k=1, n=1),
        answer_key=answer_key,
        detector_config=config,
    )

    assert first.evaluation.leak_detection_accuracy == 0.0
    assert first.evaluation.average_estimation_error == 0.0
    assert first.evaluation.explanation_validity_score == 1.0
    assert "outcome:false_negative_count=1" in first.evaluation.notes
    assert first.next_session_settings.leak_detector_config == config
    assert first.next_session_settings.safety_alpha == 0.5
    assert first.next_session_settings.epsilon == 0.2
    assert first == second
    assert first.canonical_bytes() == second.canonical_bytes()


@pytest.mark.parametrize(
    ("base_ev", "exploit_ev", "final_ev", "over", "under", "conservative"),
    [
        (0.0, -2.0, -1.0, 1, 0, True),
        (0.0, 2.0, 1.0, 0, 1, False),
    ],
)
def test_over_and_under_adjustment_use_exact_dpl_ev_and_only_over_conservatizes(
    base_log,
    base_ev,
    exploit_ev,
    final_ev,
    over,
    under,
    conservative,
):
    config = LeakDetectorConfig()
    log = _adjusted_log(
        base_log,
        base_ev=base_ev,
        exploit_ev=exploit_ev,
        final_ev=final_ev,
    )
    artifact = _evaluate(
        log,
        record=_record(detected=False, k=0, n=1),
        answer_key=OpponentAnswerKey("fixture-opponent", (("CHECK", 1.0),)),
        detector_config=config,
    )

    assert artifact.evaluation.exploit_ev_gain_vs_base == final_ev - base_ev
    assert artifact.evaluation.over_adjustment_count == over
    assert artifact.evaluation.under_adjustment_count == under
    assert artifact.next_session_settings.safety_alpha == (0.0 if conservative else 0.5)
    assert artifact.next_session_settings.epsilon == (0.0 if conservative else 0.2)
    if conservative:
        assert artifact.next_session_settings.leak_detector_config.min_confidence == 1.0
    else:
        assert artifact.next_session_settings.leak_detector_config == config
