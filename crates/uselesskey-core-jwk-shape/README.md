# uselesskey-core-jwk-shape

Core typed JWK and JWKS model definitions for `uselesskey` fixture crates.

## Purpose

- Provide stable JWK shape structures (`PublicJwk`, `PrivateJwk`, `AnyJwk`, and `Jwks`).
- Provide scanner-safe negative JWK/JWKS shapes for downstream parser tests.
- Keep shape modeling separate from ordering/building behavior.
- Re-exported through `uselesskey-core-jwk` for compatibility.
