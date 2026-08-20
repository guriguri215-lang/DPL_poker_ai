# Architecture

[Back to the documentation index](README.md).

`DPL_poker_ai` is the repository name; the Python distribution and CLI use
`poker-xai`. This is an early-alpha simulation and evaluation framework, not a
real-time poker bot. The repository has no screen reader, poker-site API,
real-time input adapter, or live-play automation.

The central research claim is a faithfulness-evaluation framework for
explanations of bounded, safety-mixed exploitation experiments—not a proof of
safety, GTO status, solver convergence, or EV superiority.

## Component boundaries

- [`poker_core`](../src/poker_core/README.md) owns shared cards, ranges, strategy
  tables, the Reason Ontology, the versioned Decision Provenance Log (DPL), and
  the RunManifest contract.
- [`poker_solver`](../src/poker_solver/README.md) owns the game tree, exact
  fixed-profile EV and best-response evaluation, finite-iteration CFR/CFR+,
  node-lock, and frozen river-scenario experiment code.
- [`poker_ai`](../src/poker_ai/README.md) connects public observations to a Hero
  base policy, leak detection, optional exploitation, SafetyMixer, action
  selection, DPL validation, and session output. Its small explanation-artifact
  orchestration layer connects completed sessions to the existing generator and
  verifier without moving either implementation across component boundaries.
- [`opponents`](../src/opponents/README.md) owns versioned synthetic opponent
  models used by the research and evaluation paths.
- [`explanation`](../src/explanation/README.md) renders and verifies explanations
  from validated records. It does not change the policy or solver result.
- [`phase6`](../src/phase6) contains the separate evaluation and Gate B contracts;
  the normal Hero session does not redefine them.
- [`experiments`](../src/experiments) is reserved and empty; implemented Phase 6
  code lives under [`src/phase6`](../src/phase6).

Gate B v2 is an implemented, Windows-only, one-shot validation route for approved
local artifacts. “Production” is an internal route label, not a
production-readiness or independent-security-certification claim.

## Normal Hero session flow

The normal session implemented by
[`poker_ai.session`](../src/poker_ai/session.py) follows this sequence:

When `poker-xai-run-session` receives an explicit
`--previous-session-manifest`, its CLI first verifies that complete saved
explanation bundle and its single versioned post-session evaluation. It restores
only `LeakDetectorConfig`, safety alpha, and epsilon as defaults; operator flags
override alpha or epsilon. Any load or semantic-validation failure stops before
this sequence begins and before a new run output directory is created. Without
the option, the sequence uses its historical defaults unchanged. Bare
`--leaky-fixture` also keeps the historical R008 facing-all-in fixture. The
explicit `--leaky-fixture-reason LEAK_R007` selector chooses a bounded alternate
branch within the same session entry point.

1. A seed deterministically produces simulated river scenarios.
2. On the default/R008 path, the environment lets the jam-all stub act, then
   gives Hero only the public observation and assumed range. On the R007 path,
   Hero is OOP with no bet facing. Hero is never given either opponent's hidden
   strategy.
3. The CFR+ river adapter produces Hero's finite-iteration combo-specific
   `vs_bet` policy for the default path or the existing tree's OOP `start`
   `CHECK`/`BET_33` policy for R007.
4. Public opponent actions update the action-only observation tracker. For R007,
   the environment records a check-back only after Hero actually checks and
   after that hand's DPL decision, so the response can affect only later hands.
   A known but unreached situation is retained with zero observations. The leak
   detector may produce hypotheses, and an optional exploit provider may propose
   a policy through the same HARD node-lock and fallback boundary.
5. SafetyMixer forms `final_policy` as
   `(1-alpha)*base + alpha*exploit`; this convex mixing contract is not a
   strategy-safety proof. The optional epsilon sampler affects only execution
   and is recorded separately.
6. Each decision is validated as a current DPL v3 record. The session also builds
   a RunManifest containing invocation, version, seed, and hashed configuration
   references.
7. Without explanation opt-in, the existing writer validates the posterior
   provenance bundle, then writes DPL JSONL, the RunManifest sidecar, and the
   supporting `provenance/` JSON files exactly as before.
8. With `--explanations`, one deterministic `ExplanationDocument` is generated
   for each validated DPL in input order. A separate in-repository verifier
   checks all pairs, including their session/hand reference, DPL and ontology
   paths, source references, numeric claims, and rendered template, before the
   output directory is changed. This check does not certify solver convergence,
   strategy safety or optimality, GTO status, external validation, or independent
   third-party reproducibility. Only a fully verified set is written using the
   existing explanations JSONL and verifier-summary formats. The unchanged
   RunManifest schema uses its existing hashed `ArtifactRef` outputs for DPL,
   explanations, summary, and the terminal posterior-provenance snapshot.
9. After every decision and every explanation check has completed, the
   environment reveals the fixed stub answer key to the post-session evaluator.
   It compares all terminal posterior candidates with ground truth, aggregates
   existing exact DPL EV and verifier results, and writes one canonical evaluation
   plus conservative next-session settings. The answer key is never passed to
   Hero. A later normal session can consume the settings only through the
   explicit manifest-first handoff above. The resulting DPL, posterior estimator
   artifact, and execution-sampler `ConfigRef` record the settings actually used.

The [DPL and RunManifest page](dpl_and_run_manifest.md) describes the two public
contracts. The [session tutorial](hero_session.md) shows the supported command.

## Current boundary

The default river adapter supports only a Hero decision while facing an all-in,
so its legal actions are `FOLD` and `CALL`. The explicit R007 fixture adds only
the existing OOP no-facing `CHECK` and fixed 0.33-pot `BET_33` branches. It does
not add `BET_75`, a raise, another size, or a general no-facing session loop. The
default CFR+ budget is 40 iterations with average delay 0 and no checkpoints.
Forty iterations is an alpha default, not a convergence guarantee; the resulting
policy has no exact-equilibrium or GTO certificate.

One explicit, verified handoff from a named previous RunManifest into one later
normal Hero session is implemented. The handoff carries settings only: it does
not carry the prior baseline, opponent/session mode, posterior/action history,
or answer key. The caller must explicitly select R007 again for an R007
successor. Implicit manifest discovery, latest-file search, a session registry,
and an automatic multi-session loop remain outside this slice.
