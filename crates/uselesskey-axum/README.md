# uselesskey-axum

Drop-in auth-test helpers for `axum`, built on deterministic `uselesskey` fixtures.

This crate intentionally focuses on test ergonomics:

- `jwks_router()` for a deterministic JWKS endpoint
- `oidc_router()` for OIDC discovery metadata
- `mock_jwt_verifier_layer()` for bearer auth checks in tests
- `TestAuthContext` extractor + injection helpers

It is **not** a production auth middleware package.
