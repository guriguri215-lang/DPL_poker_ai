"""Numerical tolerances for the solver's analytic checks (ADR-0017 sec.5).

Collected in one place so tests and fixtures reference the same ADR-mandated
values. Tightening these is an implementation decision; loosening any by more
than 10x, or changing a definition, requires a new ADR (ADR-0017 sec.9).
"""

from __future__ import annotations

#: Game-value match against a closed-form solution: ``|delta| <= GAME_VALUE_ABS_TOL`` (bb).
GAME_VALUE_ABS_TOL = 1e-6

#: Strategy match on provably-unique components: ``L_inf <= STRATEGY_LINF_TOL``.
STRATEGY_LINF_TOL = 1e-3

#: Value + exploitability bound for non-unique-equilibrium games, e.g. Kuhn (bb).
NON_UNIQUE_ABS_TOL = 1e-4

#: Exploitability treated as "numerically zero" for an exact-equilibrium fixture (bb).
EXPLOITABILITY_ZERO_TOL = 1e-9
