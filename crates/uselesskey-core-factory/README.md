# uselesskey-core-factory

This crate owns the `Factory` type for `uselesskey` and is focused on:

- random vs deterministic modes
- deterministic, thread-safe per-process cache lookup
- id-driven RNG initialization
- deterministic fixture reuse across repeated lookups

The `uselesskey-core` crate re-exports this crate so downstream users keep using the same
public API while preserving a cleaner separation of concerns internally.
