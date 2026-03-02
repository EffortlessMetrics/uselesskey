# uselesskey-core-x509-negative

Policy-only X.509 certificate negative-fixture helpers.

## Purpose

- Keep certificate-level X.509 negative fixture policies in one crate (`X509Negative`).
- Provide deterministic, stable helpers for negative-variant mutation and metadata.
- Re-export `ChainNegative` from `uselesskey-core-x509-chain-negative` for compatibility.
- Stay intentionally free of encoding/parsing/serialization logic.

## Responsibilities

- `X509Negative`:
  - expired cert fixtures
  - not-yet-valid cert fixtures
  - wrong key usage policy variants
  - CA-policy mismatch variants
