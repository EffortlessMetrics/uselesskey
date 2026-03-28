# uselesskey-axum

Axum-specific auth test helpers for `uselesskey`.

This crate is intentionally test-focused and intentionally small:

- `jwks_router()` for deterministic JWKS test endpoints
- `oidc_router()` for deterministic OIDC discovery test endpoints
- `mock_jwt_verifier_layer()` for bearer-token verification middleware in tests
- `TestAuthContext` extractor for deterministic auth context in handlers
