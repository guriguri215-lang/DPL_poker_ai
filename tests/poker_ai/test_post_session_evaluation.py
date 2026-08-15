from __future__ import annotations

from copy import deepcopy

import pytest

from explanation import (
    VerificationIssue,
    VerificationResult,
    generate_template_explanation,
    verify_explanation,
)
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


def _record(
    *,
    detected: bool,
    k: int,
    n: int,
    action_group: tuple[str, ...] = ("BET_ALL_IN",),
    q: float = 0.25,
    situation_key: str = "fixture-situation",
    structurally_eligible: bool = True,
) -> dict[str, object]:
    return {
        "opponent_id": "fixture-opponent",
        "rule_id": "LEAK_R008",
        "situation_key": situation_key,
        "action_group": list(action_group),
        "n": n,
        "k": k,
        "q": q,
        "candidate_eligibility": {
            "structurally_eligible": structurally_eligible,
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
    hand_id: str | None = None,
) -> DecisionProvenanceLog:
    payload = deepcopy(base_log.model_dump(mode="json"))
    if hand_id is not None:
        payload["hand_id"] = hand_id
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


def _checked_explanations(logs: list[DecisionProvenanceLog]):
    explanations = [generate_template_explanation(log) for log in logs]
    checkers = [
        verify_explanation(explanation, log)
        for log, explanation in zip(logs, explanations, strict=True)
    ]
    assert all(checker.passed for checker in checkers)
    return explanations, checkers


def _evaluate_many(
    logs: list[DecisionProvenanceLog],
    *,
    records: list[dict[str, object]],
    answer_key: OpponentAnswerKey,
    detector_config: LeakDetectorConfig,
):
    explanations, checkers = _checked_explanations(logs)
    return evaluate_post_session(
        session_id=logs[0].session_id,
        opponent_model_id="fixture-opponent",
        logs=logs,
        snapshot_records=records,
        answer_key=answer_key,
        explanations=explanations,
        checker_results=checkers,
        detector_config=detector_config,
        safety_alpha=logs[0].safety_alpha,
        epsilon=0.2,
    )


def _evaluate(
    log: DecisionProvenanceLog,
    *,
    record: dict[str, object],
    answer_key: OpponentAnswerKey,
    detector_config: LeakDetectorConfig,
):
    return _evaluate_many(
        [log],
        records=[record],
        answer_key=answer_key,
        detector_config=detector_config,
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


def test_explanation_validity_binds_same_reason_to_each_situation_truth(base_log):
    positive_situation = "validity-truth-positive"
    negative_situation = "validity-truth-negative"
    logs = []
    for hand_id, situation_key in (
        ("validity-positive-hand", positive_situation),
        ("validity-negative-hand", negative_situation),
    ):
        payload = deepcopy(base_log.model_dump(mode="json"))
        payload["hand_id"] = hand_id
        payload["detected_leaks"] = [
            {
                "reason_id": "LEAK_R008",
                "leak_type": "bet_too_often_when_checked_to",
                "situation_key": situation_key,
                "observed_rate": 1.0,
                "baseline_rate": 0.0,
                "effective_sample_size": 1,
                "confidence": 0.75,
                "direction": "decrease_bet_frequency_when_checked_to",
            }
        ]
        payload["allowed_reason_ids"] = ["LEAK_R008"]
        logs.append(DecisionProvenanceLog.model_validate(payload))

    assert len({log.hand_id for log in logs}) == 2
    assert [log.detected_leaks[0].reason_id for log in logs] == ["LEAK_R008", "LEAK_R008"]
    assert {log.detected_leaks[0].situation_key for log in logs} == {
        positive_situation,
        negative_situation,
    }

    explanations = [generate_template_explanation(log) for log in logs]
    checker_results = [
        verify_explanation(explanation, log)
        for log, explanation in zip(logs, explanations, strict=True)
    ]
    assert [checker.passed for checker in checker_results] == [True, True]

    answer_key = OpponentAnswerKey(
        "fixture-opponent",
        (("BET_ALL_IN", 0.75), ("CHECK", 0.25)),
    )
    # p_true(BET_ALL_IN) is 0.75: q=0.5 is truth-positive and q=0.9 is truth-negative.
    snapshot_records = [
        {
            "opponent_id": "fixture-opponent",
            "rule_id": "LEAK_R008",
            "situation_key": positive_situation,
            "action_group": ["BET_ALL_IN"],
            "n": 4,
            "k": 3,
            "q": 0.5,
            "candidate_eligibility": {
                "structurally_eligible": True,
                "detected": True,
            },
        },
        {
            "opponent_id": "fixture-opponent",
            "rule_id": "LEAK_R008",
            "situation_key": negative_situation,
            "action_group": ["BET_ALL_IN"],
            "n": 4,
            "k": 3,
            "q": 0.9,
            "candidate_eligibility": {
                "structurally_eligible": True,
                "detected": True,
            },
        },
    ]
    artifact = evaluate_post_session(
        session_id=logs[0].session_id,
        opponent_model_id="fixture-opponent",
        logs=logs,
        snapshot_records=snapshot_records,
        answer_key=answer_key,
        explanations=explanations,
        checker_results=checker_results,
        detector_config=LeakDetectorConfig(),
        safety_alpha=logs[0].safety_alpha,
        epsilon=0.2,
    )

    # Both checkers passed, so validity is the mean of the two cited situation truths.
    manual_oracle = (1 + 0) / 2
    assert manual_oracle == 0.5
    assert artifact.evaluation.explanation_validity_score == manual_oracle


def test_mixed_records_use_distinct_metric_populations_and_are_order_invariant(base_log):
    records = [
        _record(
            detected=True,
            k=3,
            n=4,
            q=0.5,
            situation_key="tp",
        ),
        _record(
            detected=False,
            k=1,
            n=2,
            q=0.5,
            situation_key="fn",
        ),
        _record(
            detected=True,
            k=1,
            n=2,
            action_group=("CHECK",),
            q=0.5,
            situation_key="fp",
        ),
        _record(
            detected=False,
            k=1,
            n=4,
            action_group=("CHECK",),
            q=0.5,
            situation_key="tn",
        ),
        _record(
            detected=True,
            k=0,
            n=1,
            q=0.75,
            situation_key="truth-boundary",
        ),
        _record(
            detected=True,
            k=1,
            n=1,
            action_group=("CHECK",),
            q=0.0,
            situation_key="structurally-ineligible",
            structurally_eligible=False,
        ),
        _record(
            detected=True,
            k=0,
            n=0,
            q=0.5,
            situation_key="unreached",
        ),
    ]
    answer_key = OpponentAnswerKey(
        "fixture-opponent",
        (("BET_ALL_IN", 0.75), ("CHECK", 0.25)),
    )
    config = LeakDetectorConfig(
        min_confidence=0.6,
        rule_exploit_min_confidence=0.7,
        nodelock_exploit_min_confidence=0.8,
    )
    log = _neutral_log(base_log)

    first = _evaluate_many(
        [log],
        records=records,
        answer_key=answer_key,
        detector_config=config,
    )
    reordered = _evaluate_many(
        [log],
        records=list(reversed(records)),
        answer_key=answer_key,
        detector_config=config,
    )

    # Accuracy sees the four TP/TN/FP/FN records: (1 + 1) / 4 = 1 / 2.
    assert first.evaluation.leak_detection_accuracy == 0.5
    # Error sees all six reached records: (0 + 1/4 + 1/4 + 0 + 3/4 + 3/4) / 6.
    assert first.evaluation.average_estimation_error == pytest.approx(1 / 3)
    assert first.evaluation.notes.count("outcome:false_positive_count=1") == 1
    assert first.evaluation.notes.count("outcome:false_negative_count=1") == 1
    assert first.evaluation.notes.count("outcome:next_settings=conservative") == 1
    assert len(first.evaluation.notes) == 9
    assert first.next_session_settings.leak_detector_config.min_confidence == 1.0
    assert first.next_session_settings.leak_detector_config.rule_exploit_min_confidence == 1.0
    assert first.next_session_settings.leak_detector_config.nodelock_exploit_min_confidence == 1.0
    assert first.next_session_settings.safety_alpha == 0.0
    assert first.next_session_settings.epsilon == 0.0
    assert first == reordered
    assert first.canonical_bytes() == reordered.canonical_bytes()


def test_multiple_dpls_aggregate_exact_ev_and_bind_explanations_by_order(base_log):
    logs = [
        _adjusted_log(
            base_log,
            hand_id="multi-1",
            base_ev=0.0,
            exploit_ev=4.0,
            final_ev=2.0,
        ),
        _adjusted_log(
            base_log,
            hand_id="multi-2",
            base_ev=1.0,
            exploit_ev=-1.0,
            final_ev=0.0,
        ),
        _adjusted_log(
            base_log,
            hand_id="multi-3",
            base_ev=-2.0,
            exploit_ev=-2.0,
            final_ev=-2.0,
        ),
    ]
    record = _record(detected=False, k=0, n=1)
    answer_key = OpponentAnswerKey("fixture-opponent", (("CHECK", 1.0),))
    config = LeakDetectorConfig()

    explanations, checkers = _checked_explanations(logs)
    checkers[1] = VerificationResult(
        issues=(
            VerificationIssue(
                code="synthetic-checker-failure",
                location="fixture",
                message="synthetic failed explanation checker",
            ),
        )
    )
    artifact = evaluate_post_session(
        session_id=logs[0].session_id,
        opponent_model_id="fixture-opponent",
        logs=logs,
        snapshot_records=[record],
        answer_key=answer_key,
        explanations=explanations,
        checker_results=checkers,
        detector_config=config,
        safety_alpha=logs[0].safety_alpha,
        epsilon=0.2,
    )

    # Exact gains are +2, -1, and 0; the first is under-adjusted and the second over-adjusted.
    assert artifact.evaluation.exploit_ev_gain_vs_base == pytest.approx(1 / 3)
    assert artifact.evaluation.over_adjustment_count == 1
    assert artifact.evaluation.under_adjustment_count == 1
    assert artifact.evaluation.explanation_validity_score == pytest.approx(2 / 3)

    with pytest.raises(ValueError, match="explanation order or DPL identity does not match"):
        evaluate_post_session(
            session_id=logs[0].session_id,
            opponent_model_id="fixture-opponent",
            logs=logs,
            snapshot_records=[record],
            answer_key=answer_key,
            explanations=[explanations[1], explanations[0], explanations[2]],
            checker_results=checkers,
            detector_config=config,
            safety_alpha=logs[0].safety_alpha,
            epsilon=0.2,
        )


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
