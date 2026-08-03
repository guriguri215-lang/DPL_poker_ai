# Documentation

This directory is the entry point for public documentation that does not belong
in the top-level README.

- [Implementation status](implementation-status.md) maps public claims to code,
  tests, and known limitations.
- Generated JSON Schemas are written to `docs/schemas/` by
  `python cli/export_schemas.py --out-dir docs/schemas`.
- Package-level details live beside their implementations:
  [poker_core](../src/poker_core/README.md),
  [poker_ai](../src/poker_ai/README.md),
  [poker_solver](../src/poker_solver/README.md),
  [opponents](../src/opponents/README.md), and
  [explanation](../src/explanation/README.md).

The Pydantic contracts in `src/` are authoritative. Generated schemas document
structure but do not capture every cross-field invariant.
