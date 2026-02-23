# uselesskey-core-x509

Deterministic X.509 policy helpers shared across `uselesskey` fixture crates.

## Purpose

- Keep X.509 spec and negative-policy types in one place (`X509Spec`, `ChainSpec`, `X509Negative`, `ChainNegative`).
- Re-export deterministic X.509 derivation helpers from `uselesskey-core-x509-derive`:
  base-time window logic, positive serial generation, and length-prefixed hashing.

This microcrate is intentionally focused on X.509 fixture policy, not certificate parsing or validation.
