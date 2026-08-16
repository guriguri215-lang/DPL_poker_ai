# Normal Hero session tutorial

[Back to the documentation index](README.md).

This command runs a deterministic, simulated Hero river session. It uses no
network input and writes a validated local bundle.

## Identify the command

Show the version without starting a session or creating files:

```text
poker-xai-run-session --version
```

For a source checkout, the historical wrapper goes through the same
`poker_ai.run_session_cli` module:

```text
python cli/run_session.py --version
```

The output identifies the invoked entry point and the authoritative
project/distribution version. If that version cannot be resolved under the
[no-guessing provenance contract](dpl_and_run_manifest.md#version-and-git-provenance),
the version is `unknown`. It is never inferred from the current directory or an
unrelated installation.

Inspect all current options without running a session:

```text
poker-xai-run-session --help
```

## Run a minimal offline session

Use one hand and one CFR+ iteration for a quick smoke run:

```text
poker-xai-run-session --seed 7 --hands 1 --solver-iterations 1 --out-dir experiments_output/tutorial
```

The compatibility command accepts the same arguments:

```text
python cli/run_session.py --seed 7 --hands 1 --solver-iterations 1 --out-dir experiments_output/tutorial
```

The bundle contains:

- `S00000007.dpl.jsonl`, with one validated DPL v3 object per line;
- `S00000007.manifest.json`, the RunManifest sidecar;
- `provenance/leak_confidence_estimator.json`;
- `provenance/action_baseline_table.json`;
- `provenance/action_stats_terminal_snapshots.json`.

The writer validates the provenance files before writing the DPL and manifest.
The manifest records the actual entry point, the full argument vector, the
resolved-or-`unknown` package/Git provenance, the master seed, and hashed solver
and configuration references.

## Opt in to in-repository-checked explanations

Add one flag to the same command; no separate top-level command is introduced:

```text
poker-xai-run-session --seed 7 --hands 1 --solver-iterations 1 --explanations --out-dir experiments_output/tutorial
```

The flag adds these existing-format files:

- `S00000007.explanations.jsonl`, with one `ExplanationDocument` per DPL line;
- `S00000007.verifier_summary.json`, with all-item verification counts and any
  failures (a successful published bundle has none);
- `S00000007.post_session_evaluation.json`, a canonical versioned Phase 8
  evaluation plus the proposed next-session settings.

The DPL and explanations preserve count and order, and every explanation's
`dpl_ref` is `session_id:hand_id` for the corresponding DPL. Generation uses the
deterministic template generator with no LLM, network input, or additional
dependency. The separate in-repository verifier checks every explanation against
its DPL, ontology paths, source references, numeric claims, and rendered template
before the writer creates or changes the run bundle; if any item fails, no
artifact from that attempted run is written. These checks do not certify solver
convergence, strategy safety or optimality, GTO status, external validation, or
independent third-party reproducibility. On success, the existing RunManifest
schema references the DPL, explanations, summary, terminal provenance snapshot,
and post-session evaluation with relative paths and SHA-256 hashes.

The answer key remains environment-only throughout every decision and is
revealed only after `run_session` has returned all validated DPLs. The initial
MVP makes the following deterministic assumptions because the specification
does not prescribe formulas or numeric update steps:

- detection accuracy is `(TP + TN) / (TP + FP + FN + TN)` over reached,
  structurally eligible, non-boundary terminal candidates;
- estimation error is the unweighted mean absolute observed-rate error over
  reached terminal candidates;
- EV gain is the per-decision mean of exact `final_ev - base_ev`;
- over-adjustment means exact `final_ev < base_ev`, while under-adjustment means
  exact `exploit_ev > final_ev`;
- explanation validity requires both the existing explanation verifier and
  truth-positive cited LEAK reasons.

A false positive, negative mean EV gain, or over-adjustment keeps the existing
detector estimator but sets its three existing confidence gates to `1.0`, safety
alpha to `0.0`, and epsilon to `0.0`. Otherwise every current value is retained.
In particular, false negatives and under-adjustment do not lower a threshold or
raise alpha/epsilon in this slice.

## Hand settings to the next session explicitly

Name the completed source RunManifest; the command never searches for one:

```text
poker-xai-run-session --seed 8 --hands 1 --solver-iterations 1 --previous-session-manifest experiments_output/tutorial/S00000007.manifest.json --out-dir experiments_output/tutorial-next
```

The source must be the complete `--explanations` bundle above, because that is
the existing opt-in that writes the post-session evaluation.

Before the first Hero decision, the loader reuses the saved explanation-bundle
verifier, validates every relative `ArtifactRef` path and SHA-256, and requires
one canonical post-session artifact with the supported schema/type and matching
source-session/opponent identities. It strictly reconstructs the existing
`LeakDetectorConfig`, safety alpha, and epsilon and rejects invalid ranges. A
failure creates no output for the attempted successor.

The restored values are defaults. Explicit `--safety-alpha` and
`--exploration-epsilon` flags take precedence, including an explicit `0.0`.
When `--leaky-fixture` is also present, the existing fixture baseline remains
the only baseline while the restored detector config is passed to both the
detector and real solver-backed node-lock provider. Its node-lock confidence
gate and retained rule-based fallback use the restored thresholds. The source's
posterior/action history, baseline, and answer key are not transferred. There
is no implicit latest-file search, session registry, or automatic loop; repeat
the explicit handoff for each intended successor.

Omitting `--explanations` retains the five-file bundle above and does not change
the session inputs, action, solver behavior, or invocation provenance.

To recheck a saved explanation bundle without rerunning the session, use the
manifest-first, read-only command described in [Saved Hero explanation bundle
verification](explanation_bundle_verification.md).

## Important options and limits

- `--seed` defaults to `20260704`; `--hands` defaults to `200`.
- `--solver-iterations` defaults to `40`; `--solver-average-delay` defaults to
  `0`.
- `--previous-session-manifest PATH` makes that verified session's detector,
  alpha, and epsilon the defaults for this run. If omitted, normal alpha and
  epsilon remain `0.0`.
- Explicit `--safety-alpha` and `--exploration-epsilon` values override restored
  defaults.
- `--leaky-fixture` is a public positive-path smoke fixture that connects the
  detected leak to the solver-backed node-lock exploit provider. The existing
  solver iteration and average-delay values configure both the base-policy and
  node-lock solves. A mapping that does not apply to the fixed river tree, or a
  baseline-scaled lock with no reachable target, uses the retained rule-based
  fallback. Every candidate changes policy only when it strictly improves the
  existing exact action EV; otherwise the base policy remains in use. This is
  not a production opponent model.
- `--explanations` is an artifact-output opt-in; it does not affect policy or
  action selection.

The adapter remains limited to facing an all-in and therefore chooses only
between `FOLD` and `CALL`. The 40-iteration default is not a convergence
guarantee. See [Responsible use](responsible_use.md) before using or sharing
results.
