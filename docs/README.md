# poker-xai documentation

This is the public documentation index for the simulation-only `poker-xai`
research framework. Start with the repository [README](../README.md) for project
scope and development status.

- [Architecture](architecture.md) describes the current component boundaries and
  the normal Hero-session data flow.
- [DPL and RunManifest contracts](dpl_and_run_manifest.md) explains DPL v1/v2
  loading compatibility, current DPL v3 writes, and the RunManifest audit record.
- [Normal Hero session tutorial](hero_session.md) covers `--version`, `--help`, a
  minimal offline session, its output bundle, opt-in deterministic template
  explanations with in-repository checks, and the legacy source wrapper.
- [Saved Hero explanation bundle verification](explanation_bundle_verification.md)
  covers the manifest-first, offline, read-only API and distribution CLI.
- [Responsible use](responsible_use.md) records the intended research use and the
  current safety and solver limitations.
- [GitHub Release verification](release_verification.md) explains how to obtain
  and check the exact four release assets without installing them.
- [Maintainer release checklist](releasing.md) covers version update, review,
  tagging, manual workflow approval, prerelease publication, and re-verification.

Generated JSON Schemas are not checked in. Maintainers can generate them with
`python cli/export_schemas.py --out-dir docs/schemas`; the Pydantic models remain
the canonical validators for cross-field semantics.
