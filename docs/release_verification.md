# Verify a GitHub Release

[Back to the documentation index](README.md).

`poker-xai` releases are GitHub-only prereleases. Perform these checks in a new,
empty directory before extracting or using either distribution artifact. Do not
continue if any check fails.

## Obtain the four uploaded assets

Open the [`poker-xai` GitHub Releases page](https://github.com/guriguri215-lang/DPL_poker_ai/releases),
select release `0.1.0a7`, and download exactly these four uploaded assets:

- `poker_xai-0.1.0a7-py3-none-any.whl`
- `poker_xai-0.1.0a7.tar.gz`
- `artifact-manifest.json`
- `SHA256SUMS`

GitHub may also display automatically generated source-code archive links. They
are not uploaded release assets and are not part of this four-asset contract. If
the release has any other uploaded asset, is missing one of the four names, or
uses a different name, stop and do not use the release.

If you have the matching source checkout, its read-only verifier applies the
same complete contract to the flat download directory using only the existing
Python. It does not use the network, run `pip`, install anything, extract an
archive, or execute archive-contained code:

```text
python scripts/verify_release_bundle.py \
  --bundle <fresh-release-download-directory> \
  --layout flat \
  --expected-version 0.1.0a7
```

## Automated maintainer re-verification

The read-only **Verify published release assets** workflow runs on the GitHub
Release `published` event and can also be rerun manually from `main` with its
`workflow_dispatch` `tag` and `expected_version` inputs set to `0.1.0a7`. It has
only `contents: read` permission and never modifies a Release, tag, asset,
Issue, or pull request.

The workflow requires a published prerelease whose tag, expected version, and
tagged `pyproject.toml` version all match. It checks the Release API's uploaded
asset list for the exact four assets above. Automatically generated source
archives are not uploaded assets and are not counted. A networked retrieval
stage downloads the assets into a new, empty directory; a separate local stage
uses the tag source's `scripts/verify_release_bundle.py --layout flat` verifier.
The latter remains network-free, read-only, no-install, and does not extract or
execute archive-contained code.

This workflow supplements the manual verification in this guide; it cannot undo
a publication and therefore does not replace or permit skipping the manual
checks. A failure reports only its category and target filename. It does not
repair, replace, or delete the Release, tag, or assets.

## Verify the checksums

`SHA256SUMS` covers exactly the wheel, sdist, and `artifact-manifest.json`.
`SHA256SUMS` does not and cannot include its own digest. Its three entries bind
the two distributions and the workflow's verification report together.

On a POSIX shell, run the following from the fresh download directory. This uses
no `pip` command and performs no installation:

```sh
set -- ./*
[ "$#" -eq 4 ] || { echo "unexpected asset count" >&2; exit 1; }
for name in \
  poker_xai-0.1.0a7-py3-none-any.whl \
  poker_xai-0.1.0a7.tar.gz \
  artifact-manifest.json \
  SHA256SUMS
do
  [ -f "$name" ] || { echo "missing asset: $name" >&2; exit 1; }
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --check SHA256SUMS
else
  shasum -a 256 --check SHA256SUMS
fi

python3 -I - <<'PY'
import json
import hashlib
from pathlib import Path

manifest = json.loads(Path("artifact-manifest.json").read_text(encoding="utf-8"))
assert manifest["version"] == "0.1.0a7"
artifact_names = {
    "poker_xai-0.1.0a7-py3-none-any.whl",
    "poker_xai-0.1.0a7.tar.gz",
}
assert set(manifest["artifacts"]) == artifact_names
for name in artifact_names:
    assert manifest["artifacts"][name] == hashlib.sha256(Path(name).read_bytes()).hexdigest()
assert manifest["reproducible"] is True
assert manifest["offline_smoke"] is True
print("release manifest: passed")
PY
```

On PowerShell, the equivalent check is:

```powershell
$expected = @(
  'SHA256SUMS',
  'artifact-manifest.json',
  'poker_xai-0.1.0a7-py3-none-any.whl',
  'poker_xai-0.1.0a7.tar.gz'
) | Sort-Object
$actual = @(Get-ChildItem -Force | ForEach-Object Name | Sort-Object)
if (@(Compare-Object $expected $actual).Count -ne 0) {
  throw 'release directory does not contain the exact four assets'
}

$checksumTargets = @(
  'artifact-manifest.json',
  'poker_xai-0.1.0a7-py3-none-any.whl',
  'poker_xai-0.1.0a7.tar.gz'
)
$seen = @{}
$verifiedHashes = @{}
foreach ($line in Get-Content -LiteralPath .\SHA256SUMS) {
  if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.+-]+)$') {
    throw 'invalid SHA256SUMS format'
  }
  $expectedHash = $Matches[1]
  $name = $Matches[2]
  if ($name -notin $checksumTargets -or $seen.ContainsKey($name)) {
    throw 'invalid SHA256SUMS target set'
  }
  $seen[$name] = $true
  $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant()
  if ($actualHash -cne $expectedHash) { throw "checksum mismatch: $name" }
  $verifiedHashes[$name] = $actualHash
}
if (@(Compare-Object ($checksumTargets | Sort-Object) ($seen.Keys | Sort-Object)).Count -ne 0) {
  throw 'SHA256SUMS does not cover the exact three targets'
}

$manifest = Get-Content -Raw -LiteralPath .\artifact-manifest.json | ConvertFrom-Json
if ($manifest.version -cne '0.1.0a7') { throw 'manifest version mismatch' }
$manifestArtifacts = @($manifest.artifacts.PSObject.Properties.Name | Sort-Object)
$expectedArtifacts = @(
  'poker_xai-0.1.0a7-py3-none-any.whl',
  'poker_xai-0.1.0a7.tar.gz'
) | Sort-Object
if (@(Compare-Object $expectedArtifacts $manifestArtifacts).Count -ne 0) {
  throw 'manifest artifact set mismatch'
}
foreach ($name in $expectedArtifacts) {
  $manifestHash = ($manifest.artifacts.PSObject.Properties |
    Where-Object { $_.Name -ceq $name }).Value
  if ($manifestHash -cne $verifiedHashes[$name]) { throw "manifest hash mismatch: $name" }
}
if ($manifest.reproducible -ne $true -or $manifest.offline_smoke -ne $true) {
  throw 'manifest verification result is not successful'
}
'release manifest: passed'
```

## Read the artifact manifest

After the checksum succeeds, inspect `artifact-manifest.json` as data rather
than relying only on its filename:

- `version` must be `0.1.0a7`.
- `artifacts` must contain only the wheel and sdist names, with the same SHA-256
  digests already checked through `SHA256SUMS`.
- `reproducible: true` means two independent clean-checkout builds produced the
  same wheel and sdist bytes.
- `offline_smoke: true` records that the workflow used its existing Python to
  exercise the source checkout, unpacked wheel, and unpacked sdist without
  installing the artifacts or accessing a package index.
- `smoke_checks` records version/help commands, entry-point metadata, a minimal
  session, RunManifest round-trip validation, and documentation relative links.

These results verify the release bundle and basic offline execution; they are
not a solver convergence guarantee. The normal river adapter remains limited to
facing an all-in, and its 40 CFR+ iterations remain a fixed alpha computation
budget, not a convergence guarantee.

## Proceed after verification

You may inspect either archive without installing it. For example,
`python3 -I -m zipfile --list poker_xai-0.1.0a7-py3-none-any.whl` lists the
wheel, while `tar -tzf poker_xai-0.1.0a7.tar.gz` lists the sdist. Extracting the
sdist gives a self-contained `README.md`, `CONTRIBUTING.md`, and public Markdown
documentation tree whose relative links were checked by the release workflow.
Read those files before choosing how to use the simulation-only research code.

Stop if the uploaded asset set, any checksum, any manifest value, or any offline
smoke result differs from this contract. The checks detect corruption and
inconsistency among the four GitHub-hosted files, but the current release format
does not provide an independent signature or an external trust anchor.
