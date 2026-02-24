# uselesskey-core-jwk

Compatibility façade for JWK/JWKS model types in `uselesskey-core-jwk-shape`.

## Purpose

- Re-export typed JWK/JWKS model types (`PublicJwk`, `PrivateJwk`, `AnyJwk`, `Jwks`).
- Preserve the existing crate-level API path used by downstream fixture crates.
- Keep the shape definitions in `uselesskey-core-jwk-shape` for focused reuse.
