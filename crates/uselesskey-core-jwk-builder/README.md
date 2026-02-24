# uselesskey-core-jwk-builder

SRP microcrate for JWKS composition used by `uselesskey` key fixtures.

- Stable, deterministic ordering by `kid` for JWKS entries.
- Deterministic tie-breakers for duplicate `kid` values based on insertion order.
- Zero secret material leakage in `Debug` output (delegated to JWK models).

The crate is consumed by:
- `uselesskey-jwk` for re-exported `JwksBuilder`
- `uselesskey-core-jwk` consumers that only need JWK model types
