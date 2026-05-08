# uselesskey-core-jwk-builder

Deprecated compatibility shim for JWKS composition now owned by
`uselesskey-jwk`.

- Stable, deterministic ordering by `kid` for JWKS entries.
- Deterministic tie-breakers for duplicate `kid` values based on insertion order.
- Zero secret material leakage in `Debug` output (delegated to JWK models).

Prefer `uselesskey-jwk::JwksBuilder` for new code.
