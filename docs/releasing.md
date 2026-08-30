# Publish a GitHub prerelease

[Back to the documentation index](README.md).

This maintainer checklist covers the complete GitHub-only publication path for
`0.1.0a19`. It does not publish to PyPI or any other package index. Stop the
publication process whenever an identity, CI, review, asset, checksum, manifest,
or safety check does not match this checklist.

## 1. Update and review the version

- Start a focused `agent/...` branch from the latest `main`.
- Set the current project version in `pyproject.toml` to `0.1.0a19`.
- Update only current-version workflow defaults, public examples, tests, and
  artifact names. Preserve historical descriptions of earlier alpha releases.
- Run the release documentation contract test so the project version, workflow
  defaults, examples, and exact asset names cannot drift independently.
- Confirm that the public runtime CLI, `poker-xai-run-session`, selects R004 only
  with the explicit pair `--leaky-fixture --leaky-fixture-reason LEAK_R004`.
  The reason without the fixture flag and an R005 selector must be rejected;
  generic synthetic opponent config and Phase 6 catalogs must continue to
  reject R004 before a session starts or output is created. Omitting the
  selector must preserve the existing facing-all-in fixture.
- Confirm that R004 gives Hero only OOP `CHECK` and fixed 0.33-pot `BET_33`.
  The environment may generate and record an opponent `FOLD` or `CALL` only
  after Hero actually selects `BET_33`; that observation may affect later hands
  but must not enter the same hand's decision.
- Confirm that the reach-weighted CALL baseline, baseline-plus-0.16 target,
  locked response, and provenance come from R003's pinned 40-iteration finite-CFR
  0.33-pot profile and R004's content-hashed inline noncatalog reference. The
  reference must identify R004, CALL, solver settings, and both profile digests.
  The release must preserve the linked
  `DetectedLeak`, existing provider, `SafetyMixer`, exact current-node action EV,
  DPL, `RunManifest`, template explanation, post-session evaluation, and
  explicit previous-session settings handoff.
- Confirm that omitted flags and the existing normal and leaky defaults remain
  unchanged; verified saved settings are still restored; explicit values still
  override them, including `0.0`; and the public Python API retains its existing
  validation and defaults.
- Confirm the same R004 success and rejection boundaries on the source checkout,
  unpacked wheel, and unpacked sdist. Keep all existing ordinary, R007/R008,
  R001/R002/R003, probability-validation, explanation, and explicit two-session
  handoff release smoke checks in place.
- Dependencies, the public action vocabulary, CFR defaults, frozen Scenario,
  DPL, RunManifest and Explanation schemas, solver public API, Phase 6, Gate B,
  entry points, defaults, workflow topology, release mechanism, and the exact
  four-asset release contract stay unchanged. Do not add arbitrary bet sizing,
  raises, an automatic session loop, a registry, or another release asset.

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
git tag 0.1.0a19
git push origin 0.1.0a19
```

Confirm that `0.1.0a19`, the project version, and the tagged commit agree. Never
move, replace, or delete an existing branch, tag, or release.

## 4. Manually approve and run the release workflow

- In GitHub Actions, select the existing **Release artifacts** workflow and
  explicitly choose **Run workflow** from `main`.
- Review the manual inputs before approving the dispatch: both `tag` and
  `expected_version` must be exactly `0.1.0a19`.
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
  --expected-version 0.1.0a19
```

## 5. Check the exact publication set

The prerelease may receive only these four files from that one unchanged
workflow bundle:

- `poker_xai-0.1.0a19-py3-none-any.whl` from `dist/`
- `poker_xai-0.1.0a19.tar.gz` from `dist/`
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

The release notes must explain the user-facing addition since the preceding
release:

- The normal Hero CLI reproduces LEAK_R004 only through
  `--leaky-fixture --leaky-fixture-reason LEAK_R004`. Missing the fixture flag,
  requesting R005, and generic synthetic-opponent or catalog selection remain
  rejected; an omitted selector preserves the existing default route.
- R004 reuses the existing OOP `CHECK`/fixed 0.33-pot `BET_33` branch. The
  opponent's `FOLD`/`CALL` is generated and recorded only after an actual
  `BET_33`, so it can influence later hands but never the current decision.
- Its reach-weighted CALL baseline and baseline-plus-0.16 locked response come
  from R003's pinned 40-iteration finite-CFR profile. The exact reason, action,
  seed, scenario, solver configuration, baseline and locked profile digests,
  lock, and sampler identity are carried by a content-hashed inline noncatalog
  provenance reference; this is a fixed alpha computation, not a GTO claim.
- The resulting `DetectedLeak`, existing opponent-tendency provider,
  `SafetyMixer`, exact current-node action EV, DPL, `RunManifest`, template
  explanation, post-session evaluation, and explicit previous-session settings
  handoff remain connected across the source checkout, unpacked wheel, and
  unpacked sdist.
- Existing release smoke preserves the ordinary default, R007/R008, R001/R002/R003,
  flag omission, explicit override, probability-validation, explanation, and
  public Python API behavior. The release remains GitHub-only and uses the
  existing exact four-asset contract.

Identify the published-release four-asset verification workflow, continued
required manual verification, release documentation contract test, and exact
four-asset contract. State that there is no new dependency, entry point, schema,
artifact, registry, file discovery, default, solver public API, workflow
topology, release mechanism, automatic handoff, session loop, arbitrary
bet-size parameter, raise, or Phase 6 catalog content. Phase 6 and Gate B are
unchanged. Preserve the default facing-all-in limitation and state that 40 CFR+
iterations are a fixed alpha computation budget, not a convergence guarantee.
Keep the simulation-only offline boundary and make no convergence, GTO,
strategy-safety, profitability, or real-world performance claim.

Create a GitHub prerelease for tag `0.1.0a19` and attach only the four verified
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
  --expected-version 0.1.0a19
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
`0.1.0a19`.

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
