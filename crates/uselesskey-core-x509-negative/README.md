# uselesskey-core-x509-negative

Policy-only X.509 negative-fixture helpers.

## Purpose

- Keep all X.509 negative fixture policies in one crate (`X509Negative`, `ChainNegative`).
- Provide deterministic, stable helpers for negative-variant mutation and metadata.
- Stay intentionally free of encoding/parsing/serialization logic.

## Responsibilities

- `X509Negative`:
  - expired cert fixtures
  - not-yet-valid cert fixtures
  - wrong key usage policy variants
  - CA-policy mismatch variants
- `ChainNegative`:
  - chain-level hostname mismatch
  - unknown root CA identity
  - expired leaf/intermediate cert variants
  - revoked leaf variant metadata hooks

