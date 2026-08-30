# poker-xai

An early-alpha, simulation-only research framework for explainable decision
provenance and safety-mixed opponent-exploitation experiments in poker. It is not
a real-time playing bot. It studies whether an AI's decision to deviate from a
baseline strategy in order to exploit an opponent can be disclosed *faithfully*
— and how to measure that faithfulness against ground truth.

`DPL_poker_ai` is the repository name; the Python distribution and CLI use
`poker-xai`.

The framework deliberately contains **no** real-time input, screen scraping,
site APIs or automation. That capability is absent by design, not disabled.

## What this is

Poker is a rare setting where the opponent's true strategy can be revealed after
the fact, which gives explanation faithfulness a ground truth. Around this we
build:

- A **Decision Provenance Log (DPL)**: a structured, auditable record of *why*
  the policy was adjusted on each decision (observed leak → trigger → exploit →
  safety mixing → realised action), with an explicit reason ontology and EV
  provenance.
- A **node-lock opponent synthesis** so leaks are constructively known.
- An **answer-key protocol** and faithfulness metrics (Reason Validity,
  numerical consistency, counterfactual consistency, calibration).

The central research claim is a faithfulness-evaluation framework for
explanations of bounded, safety-mixed exploitation experiments—not a proof of
safety, GTO status, solver convergence, or EV superiority.

## Can / cannot do

- **Implemented**: DPL v3, the Reason Ontology, RunManifest verification,
  frozen-model terminal/action EV, bounded CFR/CFR+ river experiments, synthetic
  HARD node locks, deterministic template explanations, source-DPL checks, and
  post-session answer-key evaluation with a conservative next-setting artifact.
- **Experimental and bounded**: heads-up river facing-all-in sessions, plus
  explicit offline R007/R003/R004 `CHECK`/`BET_33` and R001/R002 `CHECK`/`BET_75`
  fixtures, with finite-iteration combo- and position-specific policies. They
  have no convergence, exact-equilibrium, or GTO certificate.
- **Unavailable**: live input, screen scraping, poker-site APIs, and real-money
  automation.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
python cli/export_schemas.py --out-dir docs/schemas
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and verification.
Use [GitHub Issues](https://github.com/guriguri215-lang/DPL_poker_ai/issues) to
report or discuss work, and submit changes through
[Pull requests](https://github.com/guriguri215-lang/DPL_poker_ai/pulls).
Please keep pull requests small and focused so they are easy to review and verify.

## Documentation

See the public [documentation index](docs/README.md) for the current
[architecture](docs/architecture.md), [DPL and RunManifest
contracts](docs/dpl_and_run_manifest.md), [normal Hero session
tutorial](docs/hero_session.md), [responsible-use guidance](docs/responsible_use.md),
and [GitHub Release verification](docs/release_verification.md).

Saved normal Hero explanation bundles can be checked again without rerunning a
session. See [offline explanation bundle verification](docs/explanation_bundle_verification.md)
for the manifest-first, read-only API and `poker-xai-verify-explanation-bundle`
command.

## Normal Hero session CLI

The distributed command runs the normal simulated Hero session and writes DPL
v3 JSONL plus its RunManifest sidecar:

```bash
poker-xai-run-session --seed 20260704 --hands 5 --out-dir experiments_output/quickstart
```

The historical source-checkout command is a compatibility wrapper around the
same packaged module:

```bash
python cli/run_session.py --seed 20260704 --hands 5 --out-dir experiments_output/quickstart
```

Add the single `--explanations` opt-in when the same run should also produce
deterministic template explanations and a separate in-repository verifier
summary:

```bash
poker-xai-run-session --seed 20260704 --hands 5 --explanations --out-dir experiments_output/quickstart
```

Without the flag, the session's inputs, actions, solver behavior, and output file
set are unchanged. With it, each validated DPL produces one explanation in the
same order. Every explanation is independently verified before any run artifact
is written. Here, “verified” means that a separate in-repository verifier checks
each deterministic template against its DPL, ontology paths, source references,
and numeric claims. It does not certify solver convergence, strategy safety or
optimality, GTO status, external validation, or independent third-party
reproducibility. A verification failure leaves no partial bundle from that run.
The expanded bundle reuses the existing explanations JSONL and verifier-summary
JSON formats, and its RunManifest records hashed references to the DPL,
explanations, summary, existing terminal provenance output, and one versioned
`*.post_session_evaluation.json` artifact. Only after every Hero decision has
completed does the environment reveal the fixed stub answer key to this
evaluation. The artifact deterministically records the Phase 8 metrics and a
next-session setting composed only from the existing `LeakDetectorConfig`
thresholds, safety alpha, and epsilon. False positives, negative mean exact EV
gain, or over-adjustment make those settings maximally conservative; false
negatives and under-adjustment do not automatically increase aggression.
Generation is LLM-free, network-free, and adds no dependency or DPL/RunManifest
schema change.

The same entry point has explicit R007, R001, R002, R003, and R004 fixtures that
reach the existing river tree's OOP no-facing node. R007 uses the fixed 0.33-pot branch:

```bash
poker-xai-run-session --seed 20260704 --hands 5 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R007 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r007
```

This bounded R007 path offers only `CHECK` and the existing `BET_33` label. An
opponent `CHECK` is observed only after Hero actually checks, so it can affect a
later hand but never the decision that caused it. The explicit epsilon setting
makes the fixed five-hand smoke exercise those causal opportunities.

R003 reuses that same fixed 0.33-pot branch for a small-bet overfold experiment:

```bash
poker-xai-run-session --seed 20260004 --hands 20 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R003 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r003
```

Hero can select only `CHECK` or `BET_33`. The content-hashed, noncatalog fixture
derives its IP `vs_bet` FOLD baseline from one pinned 40-iteration CFR+ profile
and sets the environment's FOLD rate 0.16 above that baseline. The profile,
reference scenario, solver inputs, baseline and locked-profile hashes, and
response sampler are pinned in the opponent's inline `ConfigRef`; this is a
finite-iteration reference profile, not an equilibrium or GTO claim. The
environment samples and records `FOLD` or `CALL` only after Hero actually
selects `BET_33`, so the response can affect later hands but not the decision
that caused it. An eligible exploit reuses the existing opponent/IP/`vs_bet`/
`FOLD` HARD `fix_to_baseline` node lock and the existing exact `BET_33` adapter.
On the normal Hero CLI, R003 is selected only through the explicit fixture pair
above; omitting `--leaky-fixture` is rejected, and the general
synthetic-opponent catalog/config surface remains unchanged.

R004 uses the same pinned 0.33-pot reference profile for the complementary
small-bet overcall experiment:

```bash
poker-xai-run-session --seed 20260004 --hands 160 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R004 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r004
```

Hero still has only `CHECK` and `BET_33`. The reach-weighted IP `vs_bet` CALL
baseline is `0.7328227049493046`; the existing `0.16` fixture delta produces a
CALL target of `0.8928227049493046`. The environment samples `CALL` or `FOLD`
only after an actual `BET_33`, after that hand's Hero decision has been recorded.
The response can therefore affect only later hands. Eligible solver candidates
use opponent/IP/`vs_bet`/`CALL`, `baseline_scaled`, `HARD`, and
`fix_to_baseline`, and must improve exact current-node EV by more than the
existing `1e-12 bb` tolerance. The inline noncatalog `ConfigRef` content-hashes
the reason, action, solver settings, and baseline and locked profile digests.
Both fixture flags are required. Generic synthetic-opponent configuration and
the Phase 6 catalogs continue to reject R004.

R001 uses the frozen `river-large-bet-equilibrium-v1` size and the pinned
versioned training fixture `nl-train-r001-d016-s102`:

```bash
poker-xai-run-session --seed 20260000 --hands 20 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R001 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r001
```

Hero can select only `CHECK` or fixed 0.75-pot `BET_75`. Choose R001 when you
want an opponent whose IP `FOLD` rate is 0.16 above the equilibrium baseline.
The environment records the synthesized opponent's `FOLD`/`CALL` response only
after a realised `BET_75`; a response can affect later hands but not the
decision that produced it. An eligible exploit reuses the existing
opponent/IP/`vs_bet`/`FOLD` HARD `fix_to_baseline` node lock.

Choose R002 for the complementary overcall experiment at the same node. It uses
an in-memory, content-hashed noncatalog fixture whose IP `CALL` rate is 0.16
above the same equilibrium's CALL baseline:

```bash
poker-xai-run-session --seed 20260000 --hands 40 --solver-iterations 5 --leaky-fixture --leaky-fixture-reason LEAK_R002 --exploration-epsilon 1.0 --explanations --out-dir experiments_output/r002
```

R002 changes neither the Phase 6 catalog nor the available Hero actions. Its
response is sampled only after Hero actually chooses `BET_75`, and its eligible
solver candidate locks opponent/IP/`vs_bet`/`CALL` with `baseline_scaled`,
`HARD`, and `fix_to_baseline`. The provider accepts that candidate only when its
locked exact action EV improves on the base by more than the existing `1e-12 bb`
exact-EV numerical tolerance. `min_decision_ev_delta` remains a configurable
policy threshold, not a separate provider numerical-tolerance contract.

Here, exact EV means exact terminal traversal of the fixed finite river model
for the current combo and current `CHECK`/fixed-bet node; later actions follow the
supplied finite-iteration strategy profile. It does not mean that the profile is
an exact equilibrium, that CFR+ converged, or that the result is GTO. With
`--explanations`, the directory contains DPL v3 JSONL, its RunManifest, template
explanations, verifier summary, post-session evaluation, and the existing
`provenance/` artifacts. Bare `--leaky-fixture` still selects R008, and all normal,
R007, R001, R002, R003, R008, alpha, epsilon, and solver defaults are unchanged.
These fixtures add no arbitrary bet-size option, multi-size tree, raise, schema,
dependency, entry point, registry, or automatic session loop.

Pass that completed session's RunManifest explicitly to make the verified
settings the defaults for one later normal Hero session:

```bash
poker-xai-run-session --seed 20260705 --hands 5 --previous-session-manifest experiments_output/quickstart/S20260704.manifest.json --out-dir experiments_output/quickstart-next
```

Before Hero starts, the command reuses the saved explanation-bundle verifier,
relative-path containment, every `ArtifactRef` SHA-256, and canonical JSON
handling. It requires exactly one supported post-session evaluation whose
session and opponent match the supplied manifest, then restores only the
existing `LeakDetectorConfig`, safety alpha, and epsilon. Explicit
`--safety-alpha` and `--exploration-epsilon` values, including `0.0`, override
the restored defaults. Omitting `--previous-session-manifest` preserves the
earlier normal and `--leaky-fixture` defaults. There is no implicit manifest
discovery, latest-file search, session registry, or automatic session loop.
The saved settings never carry a fixture reason: a successor must explicitly
repeat both R004 fixture flags to run R004 again.

The saved bundle can later be rechecked offline from its manifest:

```bash
poker-xai-verify-explanation-bundle --manifest experiments_output/quickstart/S20260704.manifest.json
```

This read-only command verifies manifest artifact paths and hashes, one-to-one
DPL/explanation identity and order, every explanation with the existing checker,
and the saved checker summary. It neither reruns the session nor writes output.
Add `--show-evaluation` when you also want the six stored post-session metrics
and every stored next-session setting in deterministic `key=value` form:

```bash
poker-xai-verify-explanation-bundle --manifest experiments_output/quickstart/S20260704.manifest.json --show-evaluation
```

The extra lines appear only after the manifest, every artifact and hash, the
DPL/explanation pairs, checker summary, post-session schema and binding, and
next-session settings have all passed on one captured snapshot. The command
does not display hashes, local paths, answer-key data, diagnostic notes, or
session/opponent identities. Without `--show-evaluation`, output and support for
older bundles without a post-session artifact remain unchanged; requesting the
extra display for such a bundle fails without partial success output. The
display confirms the integrity and supported shape of already saved values. It
does not rerun the evaluator, independently recompute the metrics, or provide a
solver-convergence, GTO, strategy-safety, profitability, or real-play guarantee.

Identify either command without starting a session or creating output files:

```bash
poker-xai-run-session --version
python cli/run_session.py --version
```

Both forms reuse the same project/distribution version resolver as the
RunManifest. If authoritative metadata for the executing module is unavailable,
the displayed version is `unknown`.

RunManifest provenance follows an explicit no-guessing contract. When the
executing module is the exact `src/poker_ai` tree, the package version comes
from that project's `pyproject.toml`; its Git commit and dirty state are read
only when Git confirms the same project root. An installed or unpacked wheel
uses only distribution metadata that locates the executing module. An unpacked
sdist likewise uses its own `pyproject.toml`. If version metadata is unavailable,
`package_version` is `unknown`; outside a confirmed Git source checkout,
`git_commit` is `unknown` and `git_dirty` is `null`. The current working
directory and unrelated installations are never used as substitutes.

The manifest records `poker-xai-run-session` or `cli/run_session.py` as the
actual entrypoint and preserves the complete argument vector after the
entrypoint, before argument parsing. The default river path remains limited to
facing an all-in. The explicit R007, R001, R002, R003, and R004 fixtures add only their
bounded OOP `CHECK`/fixed-bet branches above. CFR+ defaults to 40 iterations,
which is not a convergence guarantee.

## Gate B v2 one-shot CLI

Gate B v2 is an implemented, Windows-only, one-shot validation route for approved
local artifacts. “Production” is an internal route label, not a
production-readiness or independent-security-certification claim. The repository
launcher accepts one pinned bootstrap manifest on a fixed local volume and stops
after the initial attempt is durably `SEALED`:

```powershell
$python = (Resolve-Path .\.venv\Scripts\python.exe).Path
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONNOUSERSITE = '1'
$env:PYTHONSAFEPATH = '1'
$env:PYTHONPYCACHEPREFIX = $python
$env:PYTHONPATH = (Resolve-Path .\src).Path
& $python -S -B -P -s -X "pycache_prefix=$python" -m gate_b_v2_launcher execute-once-v2 `
  --spec-parent 'D:\gate-b\approved' `
  --spec-parent-identity-scheme windows-volume-file-id-v1 `
  --spec-parent-serialization-profile windows-volume8-file16-lowerhex-v1 `
  --spec-parent-volume-id-hex 00000001 `
  --spec-parent-file-id-hex 0000000000000001 `
  --spec-name gate-b-v2-bootstrap.json `
  --expected-spec-sha256 <64-lowercase-hex-sha256> `
  --expected-spec-size-bytes <positive-size>
```

The five interpreter variables and the exact `-S -B -P -s -X pycache_prefix=<exact-python.exe>`
flags above are part of the v2 authorization
boundary. Run the command from the approved checkout root with a copied virtual
environment: `PYTHONPATH` must
contain exactly that checkout's resolved `src` directory and no other entry.
`-S` prevents `site`, every venv `.pth` file, `sitecustomize`, and
`usercustomize` from running during process startup. The stdlib-only launcher
checks that closed startup before it appends exactly the running venv's resolved
`site-packages` path; it never calls `site` to process startup hooks.
`PYTHONPYCACHEPREFIX` must resolve to the exact running `python.exe`, which is a
regular copied file rather than a cache directory. Together with disabled
bytecode writes, safe-path mode, and disabled user-site discovery, this makes
every repository `__pycache__` (including an ignored timestamp-valid cache)
unaddressable from process startup. A process started without this source-only
boundary is rejected before the first v2 artifact read or reservation; it is
never re-executed implicitly.

UNC paths, device paths, alternate data streams, nested volume mounts, and
non-fixed target volumes are rejected before artifact open. Storage checks use
the mount that actually contains each target, not only its drive-letter root.
The parent volume/file identity, exact bootstrap bytes, two approved Git
commits, and the complete runtime source inventory must all match.

The `poker-xai-gate-b-v2` console metadata may be packaged in a wheel, but a
console script cannot retroactively prevent Python startup hooks and is not a
production invocation. It fails preflight unless its process already has the
exact closed startup above. Production preflight is deliberately
repository-source-only: every executed Gate B module (including
the executor's calibration, exact-EV, sampling, and production-input helpers)
must originate from the approved checkout and match its declared Git commit.
A wheel or `site-packages` module origin therefore fails closed. Use an
editable/repository-source installation when invoking the packaged command.

A prepared route is single-consume; replay and either public reserve entry
point without its one-shot authorization fail closed. Replace the placeholders
only with independently approved evidence, and do not use this example against
production data.

## Status

Early alpha, simulation-only development. The frozen core contracts now use DPL
v3 with read-only DPL v1/v2 loading compatibility, alongside the Reason Ontology
and RunManifest. Normal Hero sessions use CFR+ to produce finite-iteration combo-
and position-specific policies. The default facing-all-in path remains `vs_bet`;
R007 check-back, R003 small-bet overfold, and R004 small-bet overcall explicitly
select OOP `CHECK`/`BET_33`, while R001 overfold and R002 overcall explicitly share OOP
`CHECK`/the frozen 0.75-pot `BET_75` branch. The
default is 40 iterations,
average delay 0, and no checkpoints. These policies
have no convergence, exact-equilibrium, or GTO certificate. Leak detection, the
SafetyMixer convex mixing contract, synthetic HARD node-lock opponent synthesis,
deterministic template explanations, source-DPL checks, Phase 6 evaluation, and
Gate B v2 contracts are implemented. Convex mixing is not a strategy-safety
proof. Arbitrary or additional no-facing sizes, non-all-in facing bets, and
raises remain outside the adapter. Forty iterations is not a convergence guarantee.

## Responsible use

This is a simulation-only research artefact. Do not use it to gain an unfair
advantage in real-money play or in violation of any poker platform's terms. See
[Responsible use](docs/responsible_use.md).

## Distribution

Release artifacts are distributed only through GitHub Releases. This project
does not publish to PyPI or other package indexes. Starting with `0.1.0a4`, each
release attaches only the wheel, sdist, `artifact-manifest.json`, and
`SHA256SUMS` taken unchanged from the same verified release-workflow bundle.
Before using a release, follow the [GitHub Release verification
guide](docs/release_verification.md) to confirm the exact four uploaded assets,
their checksums, and the recorded offline smoke results without installing them.
Maintainers should use the complete [GitHub prerelease checklist](docs/releasing.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
