# uselesskey-test-server

Deterministic OIDC/JWKS HTTP fixture server for integration tests.

This crate serves:

- `/.well-known/openid-configuration`
- `/jwks.json`

and supports deterministic, phase-driven key rotation.
