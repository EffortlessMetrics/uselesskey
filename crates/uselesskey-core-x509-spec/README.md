# uselesskey-core-x509-spec

X.509 fixture spec models and stable encoding helpers shared by `uselesskey` fixture crates.

## Purpose

- Keep `X509Spec`, `ChainSpec`, `KeyUsage`, and `NotBeforeOffset` in one place.
- Provide stable byte encodings used for cache keys and deterministic derivation inputs.
- Keep spec modeling independent from certificate generation and parsing.

This microcrate is intentionally focused on X.509 spec modeling and encoding only.
