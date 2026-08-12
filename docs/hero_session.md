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
  failures (a successful published bundle has none).

The DPL and explanations preserve count and order, and every explanation's
`dpl_ref` is `session_id:hand_id` for the corresponding DPL. Generation uses the
deterministic template generator with no LLM, network input, or additional
dependency. The separate in-repository verifier checks every explanation against
its DPL, ontology paths, source references, numeric claims, and rendered template
before the writer creates or changes the run bundle; if any item fails, no
artifact from that attempted run is written. These checks do not certify solver
convergence, strategy safety or optimality, GTO status, external validation, or
independent third-party reproducibility. On success, the existing RunManifest
schema references the DPL, explanations, summary, and terminal provenance
snapshot with their SHA-256 hashes.

Omitting `--explanations` retains the five-file bundle above and does not change
the session inputs, action, solver behavior, or invocation provenance.

## Important options and limits

- `--seed` defaults to `20260704`; `--hands` defaults to `200`.
- `--solver-iterations` defaults to `40`; `--solver-average-delay` defaults to
  `0`.
- `--safety-alpha` and `--exploration-epsilon` default to `0.0` for a normal
  session.
- `--leaky-fixture` is a public positive-path smoke fixture, not a production
  opponent model.
- `--explanations` is an artifact-output opt-in; it does not affect policy or
  action selection.

The adapter remains limited to facing an all-in and therefore chooses only
between `FOLD` and `CALL`. The 40-iteration default is not a convergence
guarantee. See [Responsible use](responsible_use.md) before using or sharing
results.
