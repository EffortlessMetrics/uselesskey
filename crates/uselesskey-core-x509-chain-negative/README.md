# uselesskey-core-x509-chain-negative

Policy-only X.509 chain negative-fixture helpers.

## Purpose

- Keep chain-level X.509 negative fixture policies in a focused crate (`ChainNegative`).
- Provide deterministic, stable helpers for negative-variant mutation and metadata.
- Stay intentionally free of encoding/parsing/serialization logic.

## Responsibilities

- `ChainNegative`:
  - chain-level hostname mismatch
  - unknown root CA identity
  - expired leaf/intermediate cert variants
  - revoked leaf variant metadata hooks
