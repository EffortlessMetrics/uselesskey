# uselesskey-core-jwks-order

SRP microcrate for deterministic, insertion-stable sorting of JWK-like items by
their `kid` value.

- Stable lexicographic ordering by `kid`.
- Deterministic order for duplicate `kid` values using insertion index.
- No knowledge of concrete JWK formats.
