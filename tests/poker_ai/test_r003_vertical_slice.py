"""Regression coverage for the bounded LEAK_R003 Hero CLI slice."""

from __future__ import annotations

import pytest

from opponents.model import leak_action_mapping
from poker_ai import run_session_cli
from poker_core.reason_ontology import get_ontology


def test_r003_is_in_the_ontology_but_rejected_by_current_runtime_paths(
    tmp_path,
    capsys,
):
    assert get_ontology().get("LEAK_R003").label == "river_small_bet_overfold"

    with pytest.raises(ValueError, match="unsupported synthetic leak reason 'LEAK_R003'"):
        leak_action_mapping("LEAK_R003")

    output_root = tmp_path / "must-not-exist"
    with pytest.raises(SystemExit) as stopped:
        run_session_cli.main(
            [
                "--leaky-fixture",
                "--leaky-fixture-reason",
                "LEAK_R003",
                "--out-dir",
                str(output_root),
            ]
        )

    captured = capsys.readouterr()
    assert stopped.value.code == 2
    assert "invalid choice: 'LEAK_R003'" in captured.err
    assert not output_root.exists()
