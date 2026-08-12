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

1. A seed deterministically produces simulated river scenarios.
2. The environment lets the stub opponent act, then gives Hero only the public
   observation and assumed public range. Hero is not given the opponent's hidden
   strategy.
3. The CFR+ river adapter produces Hero's finite-iteration combo- and
   position-specific `vs_bet` base policy for the observed all-in size.
4. Public opponent actions update the action-only observation tracker. The leak
   detector may produce recorded leak hypotheses, and an optional exploit
   provider may propose a policy.
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

The [DPL and RunManifest page](dpl_and_run_manifest.md) describes the two public
contracts. The [session tutorial](hero_session.md) shows the supported command.

## Current boundary

The normal river adapter supports only a Hero decision while facing an all-in,
so the legal actions are `FOLD` and `CALL`. It does not expand the other action
branches. The default CFR+ budget is 40 iterations with average delay 0 and no
checkpoints. Forty iterations is an alpha default, not a convergence guarantee;
the resulting policy has no exact-equilibrium or GTO certificate.
