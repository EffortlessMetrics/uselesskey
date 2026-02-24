# uselesskey-core-jwk

Core typed JWK/JWKS models and deterministic builder behavior for `uselesskey` fixture crates.

## Purpose

- Provide serializable JWK models (`PublicJwk`, `PrivateJwk`, `AnyJwk`).
- Provide JWKS model serialization (`Jwks`).
- Keep JWK domain logic decoupled from key-generation crates.

This crate intentionally models JWK/JWKS shape and serialization behavior only.
