# uselesskey-core-x509

Deterministic X.509 policy helpers shared across `uselesskey` fixture crates.

## Purpose

- Keep X.509 negative-policy types in one place (`X509Negative`, `ChainNegative`),
  now delegated to `uselesskey-core-x509-negative`.
- Re-export X.509 spec types from `uselesskey-core-x509-spec`
  (`X509Spec`, `ChainSpec`, `KeyUsage`, `NotBeforeOffset`).
- Re-export deterministic X.509 derivation helpers from `uselesskey-core-x509-derive`:
  base-time window logic, positive serial generation, and length-prefixed hashing.

This microcrate is intentionally focused on X.509 fixture policy, not certificate parsing or validation.
