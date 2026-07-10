"""Shared canonical wire-format helpers for opponent artifacts."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation


def parse_canonical_decimal(value: object, *, field: str) -> Decimal:
    """Parse the unique non-exponent fixed-point spelling of a decimal value."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{field} must be a canonical decimal string") from exc
    if not parsed.is_finite():
        raise ValueError(f"{field} must be a finite canonical decimal string")

    canonical = "0" if parsed == 0 else format(parsed, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    if value != canonical:
        raise ValueError(
            f"{field} must use canonical fixed-point spelling {canonical!r}, got {value!r}"
        )
    return parsed
