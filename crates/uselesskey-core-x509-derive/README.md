# uselesskey-core-x509-derive

Deterministic X.509 derivation helpers shared across `uselesskey` fixture crates.

## Purpose

- Compute deterministic base times from stable identity parts.
- Generate deterministic positive serial numbers for certificates and CRLs.
- Provide length-prefixed hashing helpers to avoid input-boundary collisions.

This microcrate is intentionally focused on derivation mechanics, not X.509
spec/negative policy modeling or certificate parsing/validation.
