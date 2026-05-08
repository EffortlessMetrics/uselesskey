# uselesskey-core-jwk-shape

Deprecated compatibility shim for typed JWK and JWKS model definitions now owned
by `uselesskey-jwk`.

## Purpose

- Preserve the previous crate-level API path for published-internal consumers.
- Re-export stable JWK shape structures and scanner-safe negative shapes from
  `uselesskey-jwk`.
- Prefer `uselesskey-jwk` for new code.
