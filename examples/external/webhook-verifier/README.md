# Webhook Verifier Fixtures

Use this downstream-shaped example when a webhook consumer test needs
deterministic HMAC request fixtures plus realistic rejection cases.

```bash
cargo test
```

Installed CLI bundle audit path:

```bash
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey audit-bundle --path target/uselesskey-webhook --out target/uselesskey-webhook-audit
```

This proves fixture generation and near-miss wiring for test code. It does not
prove provider compatibility, production secret management, replay protection
completeness, delivery behavior, or transport security.
