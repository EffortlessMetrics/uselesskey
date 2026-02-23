# uselesskey-core-x509

Deterministic X.509 policy helpers shared across `uselesskey` fixture crates.

## Purpose

- Keep X.509 spec and negative-policy types in one place (`X509Spec`, `ChainSpec`, `X509Negative`, `ChainNegative`).
- Keep deterministic X.509 time-window logic in one place.
- Generate deterministic positive serial numbers for certificates and CRLs.
- Provide stable, length-prefixed hashing helpers for X.509 artifact identity inputs.

This microcrate is intentionally focused on X.509 fixture policy, not certificate parsing or validation.
