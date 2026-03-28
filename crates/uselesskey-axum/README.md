# uselesskey-axum

Axum-native auth-test helpers for deterministic JWT/JWKS/OIDC fixtures.

## What this crate provides

- `jwks_router(...)` - serves `/.well-known/jwks.json`
- `oidc_router(...)` - serves `/.well-known/openid-configuration`
- `mock_jwt_verifier_layer(...)` - test-only bearer verification middleware
- `TestAuthContext` extractor - deterministic claims access in handlers
- `ExpectedAuthValues` and builder helpers for issuer/audience/kid expectations

## Example

```rust
use axum::{Router, routing::get};
use uselesskey_axum::{
    jwks_router, mock_jwt_verifier_layer, ExpectedAuthValues, MockJwtVerifierConfig,
    TestAuthContext,
};

async fn whoami(ctx: TestAuthContext) -> String {
    ctx.subject().to_owned()
}

let expected = ExpectedAuthValues::new("https://issuer.test", "api://example").with_kid("kid-1");
let verifier = MockJwtVerifierConfig::new(expected);

let app = Router::new()
    .route("/me", get(whoami))
    .merge(jwks_router())
    .layer(mock_jwt_verifier_layer(verifier));
# let _ = app;
```

## Scope

This crate is intentionally test-focused and is **not** production auth middleware.

