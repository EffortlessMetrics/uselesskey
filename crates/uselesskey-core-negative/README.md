# uselesskey-core-negative

Negative fixture helpers for PEM and DER corruption used across test fixture generators.

## Purpose

- Corrupt PEM payloads in deterministic ways for negative-path testing.
- Truncate DER vectors and flip bytes at deterministic offsets.
- Provide deterministic variants for stable `mismatch` and parser-failure fixtures.

The crate intentionally only manipulates byte/text shape and does not parse
or validate cryptographic semantics.
