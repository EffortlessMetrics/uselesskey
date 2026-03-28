# uselesskey-test-server

Deterministic OIDC discovery + JWKS HTTP fixture server for tests.

This crate is intended for integration tests that need:

- `/.well-known/openid-configuration`
- `/jwks.json`
- deterministic, phase-driven JWKS rotation
- cache header and ETag behavior for cache invalidation tests

## Example

```rust
use uselesskey_core::Factory;
use uselesskey_rsa::RsaSpec;
use uselesskey_test_server::{
    IssuerUrlMode, JwkFixtureSpec, JwksPhase, JwksRotation, JwksSpec, OidcServerSpec,
    OidcTestServer,
};

# #[tokio::main]
# async fn main() {
let fx = Factory::deterministic_from_str("seed");
let spec = OidcServerSpec {
    issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
    jwks_rotation: JwksRotation::Sequence(vec![
        JwksPhase::new(
            "phase-1",
            JwksSpec::new(vec![JwkFixtureSpec::Rsa {
                label: "issuer-key-a".into(),
                spec: RsaSpec::rs256(),
            }]),
        ),
        JwksPhase::new(
            "phase-2",
            JwksSpec::new(vec![JwkFixtureSpec::Rsa {
                label: "issuer-key-b".into(),
                spec: RsaSpec::rs256(),
            }]),
        ),
    ]),
    cache_headers: None,
    serve_discovery: true,
    serve_jwks: true,
};

let server = OidcTestServer::start(fx, spec).await.unwrap();
let _ = server.discovery_url();
server.with_phase("phase-2").unwrap();
server.shutdown().await.unwrap();
# }
```
