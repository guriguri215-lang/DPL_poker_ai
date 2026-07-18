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

P6-9A adds a separate repo-only execution boundary. It accepts only a verified
P6-8A plan, requires Validation-only backend ID and version tokens, and
reconstructs the complete 16-by-9-by-3-by-30 product before accepting results.
The five inner results have distinct closed-world Validation schemas for
terminal snapshots, Hero policies, exact-EV cells, calibration cells, and
aggregate metrics. Training, Test, unknown, and missing inner schemas are
rejected. The physical artifact root is the explicit
`validation-artifacts/validation` join; Training/Test namespace ancestors are
rejected.

The immutable writer saves all session and candidate records, then reconstructs
the base, exploit, and final Hero policies from terminal action counts, the
canonical candidate, the frozen Validation game/opponent, and the approved R008
Detector, node-lock ExploitProvider, and SafetyMixer rules. A backend-supplied
final policy is never a trusted P6-5 input and must exactly match the independent
reconstruction. P6-5 then rebuilds the two-path EVs and efficiency from the
reconstructed policy. The writer rebuilds the P6-6 series,
terminal/ground-truth join, cells, atomic groups, macro/micro metrics, GTO
groups, and aggregate from saved session provenance. Candidate selection
metrics and expected GTO eligible keys/counts are derived only from that
independent reconstruction, not accepted from the backend. The writer records all 16 ranks in
`primary_selection_report` and exactly one canonical `selected_config_lock`.
The root verifier independently rehashes every file, reconstructs every record
and join from the saved batch manifest, and reruns the unchanged P6-7 ranker.
P6-9A has no production run CLI, QV5 values, freeze, attempt reservation,
marker, or production execution path.

P6-9B adds the versioned production run boundary without selecting any QV5 or
experiment values. Its CLI accepts only the absolute frozen input directory,
the absolute fresh output directory, and the exactly-one attempt ID already
recorded by QV5. The full Python executable, entrypoint, and canonical argv must
exactly match the frozen planned command before the attempt can be reserved.

The concrete Validation backend implements the unchanged P6-9A Protocol and
uses only the frozen Validation catalog and approved digest sampling streams.
The CLI preserves the P6-8B in-progress marker, writes the P6-9A immutable root
under `validation-artifacts/validation`, and then saves a canonical run manifest
binding the clean commit, runtime, dependency lock, frozen inputs, attempt,
component provenance, production backend identity, and output root. The saved
run verifier permits the approved output path to exist, but independently
rehashes the frozen input bundle, reconstructs the plan, revalidates the marker
and P6-9A root, and rejects Training/Test or non-production backend identities.
This repo-only implementation does not choose QV5 values, freeze production
inputs, reserve a production attempt, or execute production Validation.
