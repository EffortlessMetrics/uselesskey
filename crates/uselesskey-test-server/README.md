# uselesskey-test-server

Deterministic OIDC/JWKS HTTP fixture server for integration tests.

This crate is designed for tests that need:

- `/.well-known/openid-configuration`
- `/jwks.json`
- phase-driven key rotation without wall-clock sleeps
- cache behavior assertions using `ETag` and `Cache-Control`
