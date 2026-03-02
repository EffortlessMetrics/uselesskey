# uselesskey-core-negative

Compatibility façade for negative fixture builders.

## Purpose

- Preserve the existing `uselesskey_core_negative` import path.
- Re-export DER helpers from `uselesskey-core-negative-der`.
- Re-export PEM helpers from `uselesskey-core-negative-pem`.

This crate intentionally contains no fixture-generation logic directly; logic
lives in focused SRP microcrates.
