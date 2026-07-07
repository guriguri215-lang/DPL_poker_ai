# poker_solver

The game-theoretic solver and its independent verifier.

**P3-1 (implemented): the verification layer.** Built *before* the CFR core so
that reach-probability and turn-sign mistakes cannot hide inside "it looks
converged" (ADR-0017, REV-20260705-phase2-gate2-fable5 sec.5/sec.6):

- `game.py` - extensive-form game tree (`Terminal` / `Chance` / `Decision`,
  `Game`) with information-set indexing and validation.
- `strategy.py` - strategy profiles, validation, uniform fallback (ADR-0017 sec.7).
- `reach.py` - reach-probability decomposition (chance / player0 / player1 kept
  separate, ADR-0017 sec.4).
- `evaluate.py` - exact profile EV, two independent paths (tree walk vs
  reach-weighted leaves).
- `best_response.py` - best response and `exploitability = NashConv / 2`
  (ADR-0017 sec.3), independent of any CFR internals (ADR-0017 sec.4).
- `river_tree.py` - a single-bet river betting tree over combo-granular ranges,
  reusing `poker_core` card/combo/range/hand-evaluation (no re-implementation).
- `games/` - analytic fixtures: AKQ half-street (unique closed-form equilibrium),
  Kuhn poker (non-unique family, checked by value + exploitability only), and
  hand-computed toy trees.

Units are big blinds (ADR-0017 sec.1). Player 0 is the hero; the game is
two-player zero-sum (`u0 + u1 = 0` at every leaf).

**P3-2/P3-3/P3-4 (implemented): solving and artifacts.** The package now includes
the vanilla CFR core, CFR+, independent convergence metrics, frozen river scenario
solves, and StrategyTable baseline artifact generation from solved hero phases.

**Phase 4 node-lock solver (implemented).** `nodelock.py` validates HARD/SOFT/
DISABLE lock configs, projects aggregate river action targets into per-combo
policies with `baseline_scaled` as the default allocation, records EV deltas, and
can keep unlocked infosets fixed to the baseline or re-run CFR+ with hard-locked
infosets fixed. Resolve runs also record exact opponent best-response worst-case
metrics for the fixed hero policy. Sensitivity reports sweep target frequencies
and compare `uniform` against `baseline_scaled` EV deltas as required by
ADR-0002. SOFT rules are defined for provenance but are rejected until their
semantics are implemented in a later task.
