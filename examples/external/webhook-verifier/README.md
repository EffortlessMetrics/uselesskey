# Webhook Verifier Fixtures

Use this downstream-shaped example when a webhook consumer test needs
deterministic HMAC request fixtures plus realistic rejection cases.

```bash
cargo test
```

This proves fixture generation and near-miss wiring for test code. It does not
prove provider compatibility, production secret management, replay protection
completeness, delivery behavior, or transport security.
