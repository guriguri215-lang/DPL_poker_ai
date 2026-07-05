"""Game-tree construction and information-set indexing (P3-1)."""

from __future__ import annotations

import pytest

from poker_solver.game import Chance, Decision, Game, Terminal


def test_terminal_rejects_non_numeric_payoff():
    with pytest.raises(TypeError):
        Terminal("nope")  # type: ignore[arg-type]


def test_chance_requires_probabilities_summing_to_one():
    with pytest.raises(ValueError, match="sum to 1"):
        Chance(((0.5, Terminal(1.0), "a"), (0.4, Terminal(-1.0), "b")))


def test_chance_rejects_non_positive_probability():
    with pytest.raises(ValueError, match="probability must be > 0"):
        Chance(((1.0, Terminal(1.0), "a"), (0.0, Terminal(-1.0), "b")))


def test_decision_action_child_arity_must_match():
    with pytest.raises(ValueError, match="actions but"):
        Decision(player=0, infoset="x", actions=("A", "B"), children=(Terminal(1.0),))


def test_decision_rejects_duplicate_actions():
    with pytest.raises(ValueError, match="duplicate actions"):
        Decision(player=0, infoset="x", actions=("A", "A"), children=(Terminal(1.0), Terminal(0.0)))


def test_decision_rejects_bad_player():
    with pytest.raises(ValueError, match="player must be 0 or 1"):
        Decision(player=2, infoset="x", actions=("A",), children=(Terminal(1.0),))


def test_child_of_resolves_and_raises_on_unknown():
    node = Decision(
        player=0, infoset="x", actions=("A", "B"), children=(Terminal(1.0), Terminal(2.0))
    )
    assert node.child_of("B").payoff == 2.0
    with pytest.raises(KeyError):
        node.child_of("C")


def test_game_indexes_infoset_player_and_actions():
    leaf = Terminal(1.0)
    d1 = Decision(player=1, infoset="I", actions=("X", "Y"), children=(leaf, Terminal(-1.0)))
    d0 = Decision(player=0, infoset="root", actions=("A", "B"), children=(d1, Terminal(0.0)))
    game = Game(d0)
    assert game.player_of("root") == 0
    assert game.player_of("I") == 1
    assert game.actions_of("I") == ("X", "Y")
    assert set(game.infosets_of(0)) == {"root"}
    assert set(game.infosets_of(1)) == {"I"}


def test_game_rejects_infoset_owned_by_two_players():
    shared_a = Decision(player=0, infoset="S", actions=("A",), children=(Terminal(1.0),))
    shared_b = Decision(player=1, infoset="S", actions=("A",), children=(Terminal(1.0),))
    root = Decision(player=0, infoset="root", actions=("L", "R"), children=(shared_a, shared_b))
    with pytest.raises(ValueError, match="both player"):
        Game(root)


def test_game_rejects_infoset_with_inconsistent_actions():
    a = Decision(player=1, infoset="S", actions=("A", "B"), children=(Terminal(1.0), Terminal(0.0)))
    b = Decision(player=1, infoset="S", actions=("A", "C"), children=(Terminal(1.0), Terminal(0.0)))
    root = Decision(player=0, infoset="root", actions=("L", "R"), children=(a, b))
    with pytest.raises(ValueError, match="inconsistent actions"):
        Game(root)


def test_iter_decisions_and_terminals_cover_tree():
    leaf1, leaf2, leaf3 = Terminal(1.0), Terminal(-1.0), Terminal(0.0)
    d1 = Decision(player=1, infoset="I", actions=("X", "Y"), children=(leaf1, leaf2))
    root = Decision(player=0, infoset="root", actions=("A", "B"), children=(d1, leaf3))
    game = Game(root)
    assert len(list(game.iter_decisions())) == 2
    assert len(list(game.iter_terminals())) == 3
