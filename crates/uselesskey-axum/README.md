# uselesskey-axum

`axum` auth-test helpers for `uselesskey`.

This crate is intentionally test-focused and tiny. It provides:

- `jwks_router(...)` to serve deterministic JWKS fixture JSON.
- `oidc_router(...)` to serve OpenID discovery JSON.
- `mock_jwt_verifier_layer(...)` to verify bearer tokens in integration tests.
- `TestAuthContext` extractor and request-injection helpers for deterministic test contexts.

## Example

```rust
use axum::{routing::get, Router};
use uselesskey_axum::{
    jwks_router, mock_jwt_verifier_layer, MockJwtVerifier, ExpectedAuthValues,
};

let verifier = MockJwtVerifier::new()
    .with_expected(ExpectedAuthValues::new("https://issuer.test", "api://test"));

let app = Router::new()
    .nest("/", jwks_router(vec![]))
    .route("/protected", get(|| async { "ok" }));

let app = mock_jwt_verifier_layer(app, verifier);

let _ = app;
```
