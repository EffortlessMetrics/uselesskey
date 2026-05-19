# Webhook Verifier Fixtures

Use this downstream-shaped example when a webhook consumer test needs
deterministic HMAC request fixtures plus realistic rejection cases.

User job:

```text
I need deterministic valid and invalid webhook request fixtures in Rust tests.
```

Dependency:

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["webhook"] }
```

First imports:

```rust
use uselesskey::{Factory, NearMissScenario, WebhookFactoryExt, WebhookPayloadSpec};
```

Positive path:

```text
Factory::deterministic_from_str("external-webhook-verifier")
  -> fx.webhook_stripe("payment", WebhookPayloadSpec::Canonical)
  -> signed request with Stripe-Signature header and canonical payload
```

Negative paths:

```text
near_miss_stale_timestamp(300) -> stale timestamp rejection
near_miss_wrong_secret()       -> wrong secret rejection
near_miss_tampered_payload()   -> tampered payload rejection
```

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
