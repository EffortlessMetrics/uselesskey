# uselesskey-core-jwks-order

Deprecated compatibility shim for deterministic, insertion-stable sorting of
JWK-like items by their `kid` value.

- Stable lexicographic ordering by `kid`.
- Deterministic order for duplicate `kid` values using insertion index.
- No knowledge of concrete JWK formats.

The implementation now lives in `uselesskey_jwk::srp::ordering`.
