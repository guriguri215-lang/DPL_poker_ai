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
