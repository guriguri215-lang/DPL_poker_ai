"""Tests for hand evaluation (Solver spec test 19.1).

This is the highest-blast-radius module: a kicker or split-detection bug would
silently poison every downstream EV number, so the category ordering, kicker
comparison and tie detection are all covered.
"""

from __future__ import annotations

import pytest

from poker_core.card import Card, parse_cards
from poker_core.combo import Combo
from poker_core.hand_evaluator import (
    HandCategory,
    category_of,
    evaluate_best,
    evaluate_five,
    hand_strength,
)


def strength(hand: str) -> int:
    return evaluate_five(parse_cards(hand))


# One representative hand per category, strongest to weakest.
_CATEGORY_EXAMPLES = [
    ("As Ks Qs Js Ts", HandCategory.STRAIGHT_FLUSH),
    ("Ah Ad Ac As Kh", HandCategory.FOUR_OF_A_KIND),
    ("Ah Ad Ac Kh Kd", HandCategory.FULL_HOUSE),
    ("As Ks Qs Js 9s", HandCategory.FLUSH),
    ("As Kd Qh Jc Ts", HandCategory.STRAIGHT),
    ("Ah Ad Ac Kh Qd", HandCategory.THREE_OF_A_KIND),
    ("Ah Ad Kh Kd Qc", HandCategory.TWO_PAIR),
    ("Ah Ad Kh Qd Jc", HandCategory.PAIR),
    ("Ah Kd Qh Jc 9s", HandCategory.HIGH_CARD),
]


@pytest.mark.parametrize("hand,category", _CATEGORY_EXAMPLES)
def test_category_detection(hand, category):
    assert category_of(strength(hand)) == category


def test_categories_strictly_ordered():
    strengths = [strength(hand) for hand, _ in _CATEGORY_EXAMPLES]
    assert all(strengths[i] > strengths[i + 1] for i in range(len(strengths) - 1))


def test_royal_flush_beats_lower_straight_flush():
    assert strength("As Ks Qs Js Ts") > strength("9s 8s 7s 6s 5s")


def test_full_house_beats_flush():
    # 19.1.2
    assert strength("Ah Ad Ac Kh Kd") > strength("As Ks Qs Js 9s")


def test_straight_beats_three_of_a_kind():
    assert strength("As Kd Qh Jc Ts") > strength("Ah Ad Ac Kh Qd")


def test_wheel_is_five_high_straight():
    wheel = strength("Ah 2d 3c 4s 5h")
    six_high = strength("6h 5d 4c 3s 2h")
    assert category_of(wheel) == HandCategory.STRAIGHT
    assert wheel < six_high  # ace plays low in the wheel


def test_same_category_kicker_comparison():
    # 19.1.3: identical pair, higher kicker wins.
    assert strength("Ah Ad Kh Qd Jc") > strength("As Ac Kh Qd Tc")
    # two pair: same pairs, kicker decides.
    assert strength("Ah Ad Kh Kd Qc") > strength("As Ac Ks Kc Jd")
    # trips: same trips, kicker decides.
    assert strength("9h 9d 9c Ah 2d") > strength("9s 9h 9d Kh 2c")


def test_tie_detection_split_pot():
    # 19.1.4: hands of equal rank tie regardless of suits.
    assert strength("Ah Kd Qh Jc 9s") == strength("As Kh Qs Jd 9h")


def test_evaluate_best_picks_best_five_of_seven():
    # Seven cards containing a flush; the best five must be the flush.
    seven = parse_cards("As Ks Qs Js 9s 2d 3c")
    assert category_of(evaluate_best(seven)) == HandCategory.FLUSH


def test_hand_strength_uses_board_and_hole():
    board = parse_cards("Qs 7d 2c Jc 9h")
    trips = hand_strength(Combo.from_str("QhQd"), board)  # trip queens
    pair = hand_strength(Combo.from_str("AhAd"), board)  # overpair aces
    assert category_of(trips) == HandCategory.THREE_OF_A_KIND
    assert category_of(pair) == HandCategory.PAIR
    assert trips > pair


def test_evaluate_five_requires_five_cards():
    with pytest.raises(ValueError, match="exactly 5"):
        evaluate_five(parse_cards("As Ks Qs Js"))


def test_evaluate_best_requires_five_to_seven_cards():
    with pytest.raises(ValueError, match="5 to 7"):
        evaluate_best(parse_cards("As Ks Qs Js"))  # 4 cards
    with pytest.raises(ValueError, match="5 to 7"):
        evaluate_best(parse_cards("As Ks Qs Js Ts 9s 8s 7s"))  # 8 cards


def test_evaluate_five_rejects_duplicate_cards():
    # Cards built directly can repeat; a duplicate is an impossible hand.
    hand = [Card("A", "s"), Card("A", "s"), Card("K", "h"), Card("Q", "d"), Card("J", "c")]
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_five(hand)


def test_evaluate_best_rejects_duplicate_cards():
    hand = [
        Card("A", "s"),
        Card("A", "s"),
        Card("K", "h"),
        Card("Q", "d"),
        Card("J", "c"),
        Card("9", "h"),
        Card("2", "d"),
    ]
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_best(hand)
