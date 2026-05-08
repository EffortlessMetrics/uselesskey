# uselesskey-core-jwk

Deprecated compatibility shim for JWK/JWKS model types now owned by
`uselesskey-jwk`.

## Purpose

- Preserve the previous crate-level API path for published-internal consumers.
- Re-export typed JWK/JWKS model types and `JwksBuilder` from `uselesskey-jwk`.
- Prefer `uselesskey-jwk` for new code.
