# uselesskey-core-negative

Negative fixture builders for DER corruption and DER-oriented compatibility APIs.

## Purpose

- Truncate DER vectors and flip bytes at deterministic offsets.
- Provide deterministic DER mutation helpers used for parser-failure fixtures.
- Re-export PEM corruption helpers for existing `uselesskey_core_negative` callers.

This crate intentionally only manipulates byte/text shape and does not parse or
validate cryptographic semantics.
