# uselesskey-core-negative-der

DER-specific negative fixture builders for deterministic corruption used by
`uselesskey` test utilities.

## Purpose

- Truncate DER vectors and flip bytes at deterministic offsets.
- Provide deterministic DER mutation helpers used for parser-failure fixtures.
- Keep DER behavior isolated as a small SRP microcrate.

This crate intentionally only manipulates byte shape and does not parse or
validate cryptographic semantics.
