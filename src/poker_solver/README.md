# poker_solver

The game-theoretic solver and its independent verifier.

**P3-1 (implemented): the verification layer.** Built *before* the CFR core so
that reach-probability and turn-sign mistakes cannot hide inside "it looks
converged" (ADR-0017, REV-20260705-phase2-gate2-fable5 §5/§6):

- `game.py` — extensive-form game tree (`Terminal` / `Chance` / `Decision`,
  `Game`) with information-set indexing and validation.
- `strategy.py` — strategy profiles, validation, uniform fallback (ADR-0017 §7).
- `reach.py` — reach-probability decomposition (chance / player0 / player1 kept
  separate, ADR-0017 §4).
- `evaluate.py` — exact profile EV, two independent paths (tree walk vs
  reach-weighted leaves).
- `best_response.py` — best response and `exploitability = NashConv / 2`
  (ADR-0017 §3), independent of any CFR internals (ADR-0017 §4).
- `river_tree.py` — a single-bet river betting tree over combo-granular ranges,
  reusing `poker_core` card/combo/range/hand-evaluation (no re-implementation).
- `games/` — analytic fixtures: AKQ half-street (unique closed-form equilibrium),
  Kuhn poker (non-unique family, checked by value + exploitability only), and
  hand-computed toy trees.

Units are big blinds (ADR-0017 §1). Player 0 is the hero; the game is
two-player zero-sum (`u0 + u1 = 0` at every leaf).

**Later:** CFR core (P3-2), CFR+ (P3-3), BaselineTable generation (P3-4).
