"""River betting tree: structure, EV cross-check and symmetry (P3-1 item 2)."""

from __future__ import annotations

import pytest

from poker_core.card import parse_cards
from poker_core.range_model import Range
from poker_core.showdown_ev import showdown_ev
from poker_solver.evaluate import expected_value
from poker_solver.reach import total_reach
from poker_solver.river_tree import RiverBettingConfig, build_river_game
from poker_solver.strategy import uniform_profile, validate_profile

BOARD = parse_cards("As Ks Qs 2d 7h")
OOP = Range({"AhAd": 1.0, "JhJd": 1.0, "5h5c": 1.0})
IP = Range({"TcTd": 1.0, "9h9c": 1.0, "6h6c": 1.0})


def _all_check_profile(game):
    """A profile where both players check to showdown (bet lines unreached)."""
    profile = uniform_profile(game)
    for infoset in game.infosets:
        if infoset.endswith(":start") or infoset.endswith(":vs_check"):
            profile[infoset] = {"CHECK": 1.0, "BET": 0.0}
    return profile


def test_config_bet_size():
    config = RiverBettingConfig(pot=4.0, bet_fraction=0.75)
    assert config.bet == pytest.approx(3.0)


def test_config_rejects_bad_values():
    with pytest.raises(ValueError, match="pot must be positive"):
        RiverBettingConfig(pot=0.0, bet_fraction=0.5)
    with pytest.raises(ValueError, match="bet_fraction must be positive"):
        RiverBettingConfig(pot=4.0, bet_fraction=0.0)


def test_structure_has_the_declared_betting_rounds():
    game = build_river_game(RiverBettingConfig(4.0, 0.5), OOP, IP, BOARD)
    validate_profile(game, uniform_profile(game))
    # Each declared round appears for at least one combo, with the right actions.
    for actor, phase, actions in [
        ("OOP", "start", ("CHECK", "BET")),
        ("IP", "vs_bet", ("CALL", "FOLD")),
        ("IP", "vs_check", ("CHECK", "BET")),
        ("OOP", "vs_bet", ("CALL", "FOLD")),
    ]:
        matches = [i for i in game.infosets if i.startswith(f"{actor}:") and i.endswith(phase)]
        assert matches, f"no infoset for {actor}:{phase}"
        assert game.actions_of(matches[0]) == actions
        assert game.player_of(matches[0]) == (0 if actor == "OOP" else 1)


def test_check_check_ev_matches_poker_core_showdown_ev():
    # Independent cross-check (REV sec.6 L4): the tree's both-check value must equal
    # poker_core's range-vs-range showdown EV with the same pot and ranges.
    config = RiverBettingConfig(pot=4.0, bet_fraction=0.5)
    game = build_river_game(config, OOP, IP, BOARD)
    tree_ev = expected_value(game, _all_check_profile(game))
    reference = showdown_ev(OOP, IP, BOARD, pot=config.pot).hero_ev
    assert tree_ev == pytest.approx(reference)


def test_identical_ranges_are_ev_antisymmetric():
    # Symmetric spot (same range both seats), both check -> zero EV (REV sec.6 L2).
    config = RiverBettingConfig(pot=4.0, bet_fraction=0.5)
    game = build_river_game(config, OOP, OOP, BOARD)
    assert expected_value(game, _all_check_profile(game)) == pytest.approx(0.0, abs=1e-12)


def test_river_reach_and_determinism():
    game = build_river_game(RiverBettingConfig(4.0, 0.5), OOP, IP, BOARD)
    profile = uniform_profile(game)
    assert total_reach(game, profile) == pytest.approx(1.0)
    assert expected_value(game, profile) == expected_value(game, profile)


def test_board_accepts_string():
    game = build_river_game(RiverBettingConfig(4.0, 0.5), OOP, IP, "As Ks Qs 2d 7h")
    assert expected_value(game, uniform_profile(game)) == expected_value(
        build_river_game(RiverBettingConfig(4.0, 0.5), OOP, IP, BOARD),
        uniform_profile(game),
    )


def test_rejects_non_river_board():
    with pytest.raises(ValueError, match="5 cards"):
        build_river_game(RiverBettingConfig(4.0, 0.5), OOP, IP, parse_cards("As Ks Qs 2d"))
