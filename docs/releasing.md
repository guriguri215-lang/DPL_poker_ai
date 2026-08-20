# Publish a GitHub prerelease

[Back to the documentation index](README.md).

This maintainer checklist covers the complete GitHub-only publication path for
`0.1.0a12`. It does not publish to PyPI or any other package index. Stop the
publication process whenever an identity, CI, review, asset, checksum, manifest,
or safety check does not match this checklist.

## 1. Update and review the version

- Start a focused `agent/...` branch from the latest `main`.
- Set the current project version in `pyproject.toml` to `0.1.0a12`.
- Update only current-version workflow defaults, public examples, tests, and
  artifact names. Preserve historical descriptions of earlier alpha releases.
- Run the release documentation contract test so the project version, workflow
  defaults, examples, and exact asset names cannot drift independently.
- Confirm post-session validation parity: saved-bundle revalidation and explicit
  next-session settings loading reject the same malformed captured evidence
  before a Hero session starts or output exists.
- Confirm that post-session evaluation covers multiple records, binds cited
  reasons to their situations, and restores only the documented detector,
  alpha, and epsilon settings from an explicitly named prior manifest.
- Confirm that normal Hero `--leaky-fixture` sessions use the node-lock provider
  with the existing rule fallback, and that P5-4 records the resulting
  solver-backed explanation evidence. The default non-leaky Hero baseline stays
  unchanged.
- Dependencies, public action labels, CFR defaults, frozen Scenario, DPL,
  RunManifest and Explanation schemas, solver public API, Phase 6, Gate B, entry
  points, workflow topology, and the exact four-asset release contract stay
  unchanged. One existing runtime CLI gains only the R007 fixture selector; the
  selected fixture has its own opponent identity and baseline provenance.

## 2. Merge through a reviewed pull request

- Push the branch and open a pull request against `main` with the intended
  release notes and validation results.
- Wait for every required check to pass. Confirm that all review conversations
  are resolved and that the pull request is mergeable.
- Merge to `main` only after those conditions hold. Do not bypass a required
  check or unresolved conversation.
- After the merge, wait for the CI run on the resulting `main` commit to finish
  successfully. Use that exact commit for the tag; stop if `main` moves before
  the tag and re-establish the identity checks.

## 3. Create the existing-format tag

The repository uses a lightweight tag whose name is the version without a `v`
prefix. From the verified `main` commit:

```text
git tag 0.1.0a12
git push origin 0.1.0a12
```

Confirm that `0.1.0a12`, the project version, and the tagged commit agree. Never
move, replace, or delete an existing branch, tag, or release.

## 4. Manually approve and run the release workflow

- In GitHub Actions, select the existing **Release artifacts** workflow and
  explicitly choose **Run workflow** from `main`.
- Review the manual inputs before approving the dispatch: both `tag` and
  `expected_version` must be exactly `0.1.0a12`.
- Wait for the Ubuntu build and Windows verification jobs to succeed. The
  workflow must report that the tag points at the requested source, both clean
  builds are reproducible, archive smoke checks are offline, and the final
  four-file internal bundle passes verification.
- Download the one workflow artifact from that run. Do not combine files from
  different runs or builds.

Verify the downloaded internal bundle with the checkout's existing Python. This
reads files only; it performs no network access, installation, `pip` invocation,
archive extraction, or archive-contained code execution:

```text
python scripts/verify_release_bundle.py \
  --bundle <workflow-bundle-directory> \
  --expected-version 0.1.0a12
```

## 5. Check the exact publication set

The prerelease may receive only these four files from that one unchanged
workflow bundle:

- `poker_xai-0.1.0a12-py3-none-any.whl` from `dist/`
- `poker_xai-0.1.0a12.tar.gz` from `dist/`
- `artifact-manifest.json` from `evidence/`
- `SHA256SUMS` from `evidence/`

Do not regenerate, edit, rename, or re-checksum an asset after workflow
verification. `SHA256SUMS` must name exactly the wheel, sdist, and
`artifact-manifest.json`; it must not name itself. GitHub's automatic source
archive links are not uploaded assets and are outside this four-asset contract.

Immediately before publishing, inspect only the tracked pull-request diff, pull
request body, release notes, and these four planned assets. If a non-public
value, personal information, credential material, authentication value, or
local absolute path is detected, stop before push, merge, tag, or release as
applicable. Report only the issue category and affected filename; do not display
or save the matched value. Do not investigate or rewrite repository history.
Any remediation that requires history changes needs explicit human approval.

The release notes must explain these user-facing changes since the preceding
release:

- Post-session validation parity means saved explanation-bundle revalidation and
  explicit next-session settings loading apply the same captured-snapshot,
  schema/type, complete-shape, identity, and configuration-range checks.
  Malformed prior evidence is rejected before a Hero session starts or output
  exists, with no mutation of the source bundle.
- Multiple-record evaluation uses every DPL record, distinguishes eligible and
  reached populations, aggregates exact decision EV and over-/under-adjustment
  counts, and pairs explanations by count, order, session, and hand. Metrics and
  recommended next settings do not depend on record order.
- Reason/situation binding evaluates a cited leak against the truth for that
  specific situation, so an identical reason ID in a different situation does
  not inherit the first situation's result.
- Explicit `--previous-session-manifest` restoration consumes only a named,
  verified bundle and restores detector configuration, safety alpha, and
  exploration epsilon. Operator alpha/epsilon flags, including `0.0`, override
  restored values. There is no implicit manifest discovery, registry, automatic
  session loop, or inheritance of baseline, history, or answer-key evidence.
- Normal Hero `--leaky-fixture` sessions use the real node-lock provider with the
  existing rule fallback. A solver policy is applied only when it strictly
  improves exact decision EV; the default non-leaky baseline continues to
  produce no detected leaks.
- P5-4 uses the same node-lock provider and fallback and now preserves
  solver-backed explanation evidence: an improved DPL records
  `exploit_source="nodelock_solver"` and a non-empty `solver_result_id`, the same
  ID appears in its explanation, and every explanation passes the existing
  verifier.
- `--leaky-fixture-reason LEAK_R007` makes the existing Hero session entry point
  reach a bounded OOP no-facing `CHECK`/`BET_33` decision. Bare
  `--leaky-fixture` still selects R008. R007 reuses the existing river tree,
  CFR+, HARD/fix-to-baseline node lock, DPL, RunManifest, and Explanation schemas.
  A check-back is recorded only after Hero actually checks, cannot inform the
  same decision, and a zero-opportunity terminal scope is preserved without a
  fabricated action. The fixed seed-20260704, five-hand, five-iteration smoke
  passes `--exploration-epsilon 1.0` explicitly and requires strict exact
  decision-EV improvement, `exploit_source="nodelock_solver"`, a non-empty
  `solver_result_id`, the same ID in its `ExplanationDocument`, verification of
  every explanation, and successful saved explanation-bundle revalidation.

The notes must also record that release smoke preserves two consecutive Hero
sessions on source checkout, unpacked wheel, and unpacked sdist, with session two
explicitly consuming session one's manifest via `--previous-session-manifest`.
On every surface, a separate seed-32, two-hand leaky-fixture run verifies the
solver-backed provenance above and the saved explanation bundle.
On every surface, the separate fixed R007 command above verifies the no-facing
solver-backed provenance and its saved explanation bundle while retaining the
R008 smoke.

Keep the simulation-only boundary and identify the published-release four-asset
verification workflow, continued required manual verification, release
documentation contract test, and exact four-asset contract. State that there is
no new dependency, entry point, schema, solver public API, workflow topology, or
release mechanism; the existing runtime CLI gains only the selector above.
Preserve the default facing-all-in limitation, bound R007 to OOP
`CHECK`/`BET_33` with no `BET_75` or raise branch, and state that 40 CFR+
iterations are a fixed alpha computation budget, not a convergence guarantee.

Create a GitHub prerelease for tag `0.1.0a12` and attach only the four verified
files above.

## 6. Re-download and verify the published assets

Download the four uploaded assets from the new GitHub Release into a new, empty
directory. Confirm that the directory contains no additional file or
subdirectory, then run the same verifier in flat-layout mode from the matching
tag source checkout:

```text
python scripts/verify_release_bundle.py \
  --bundle <fresh-release-download-directory> \
  --layout flat \
  --expected-version 0.1.0a12
```

The flat mode enforces the same filenames, exact checksum targets and digests,
manifest version and artifact list, reproducibility result, offline smoke
result, smoke mode, surfaces, and checks as the internal workflow-bundle mode.
It is read-only and does not install or execute either archive.

If the published download differs, stop. Do not replace assets, move the tag,
or delete and recreate the release. Record only the failure category and
affected filename, and obtain explicit maintainer direction before any further
publication action.

This manual re-download is required even though the automated check below runs
after publication. Post-publication automation cannot undo a publication, so a
successful workflow does not replace or permit skipping any manual check in
this checklist.

## 7. Confirm the published-release verification workflow

The **Verify published release assets** workflow runs for the GitHub Release
`published` event. A maintainer may rerun it manually from `main` with the
`workflow_dispatch` inputs `tag` and `expected_version`, both set to
`0.1.0a12`.

The workflow has only `contents: read` permission and does not edit the Release,
tag, assets, Issues, or pull requests. It fails unless the target is a published
prerelease and its Release tag, expected version, and tagged
`pyproject.toml` version agree. The Release API uploaded-asset list must contain
exactly the versioned wheel, versioned sdist, `artifact-manifest.json`, and
`SHA256SUMS`; GitHub's generated source archives are not uploaded assets and are
not counted.

Networked metadata and asset retrieval are separate from local verification.
The workflow downloads all uploaded assets into a new, empty directory and then
uses `scripts/verify_release_bundle.py` from the tag source with `--layout flat`.
That verifier remains network-free, read-only, no-install, and does not extract
or execute archive-contained code.

Wait for this workflow to succeed. On failure, stop without changing or deleting
the tag, Release, or any asset. The workflow reports only a failure category and
target filename and never attempts an automatic repair. If a manual rerun also
fails, preserve the published state and obtain explicit maintainer direction.
