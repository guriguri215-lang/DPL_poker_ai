# configs/opponents/validation

Validation contains exactly nine physically isolated opponent configs:

- one GTO negative control (`control_role="gto_negative_control"` in the
  Phase 6 catalog index);
- `LEAK_R001` at deltas `0.12` and `0.24`;
- `LEAK_R007` at deltas `0.12`, `0.24`, `0.28`, and `0.36`;
- `LEAK_R008` at deltas `0.28` and `0.36`.

The `0.28` and `0.36` R007/R008 configs provide the approved above-`tau`
positive coverage. Their deltas differ from Training so deterministic strategy
profiles are not duplicated across splits. Every config uses the same
closed-world generation schema and pins the same content-addressed frozen
equilibrium used by Training.

Normal loaders keep Validation separate from Training and reject Test access.
The catalog does not define a GTO false-positive threshold or a worst-case
penalty for primary selection.

P6-8B adds a separate Validation freeze boundary. Its CLI accepts all QV5
commit, runtime, dependency, path, command, attempt, and free-space values from
a canonical external manifest; none are catalog defaults. Read-only preflight
reconstructs the verified P6-8A plan and the completed production Training
source before any freeze write is permitted.

The approved attempt contract fixes exactly one planned attempt, a fresh output
directory, atomic directory reservation, and an in-progress marker. Partial
attempts are preserved, the same path is never retried, stale markers are never
released automatically, and every retry requires separate human approval. The
freeze command does not run a Validation backend, session, league, or writer,
and it leaves the future output attempt path unreserved.
