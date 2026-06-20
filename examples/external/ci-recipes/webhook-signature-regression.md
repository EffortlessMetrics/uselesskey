# Webhook Signature Regression

Use this when a downstream webhook consumer needs stable positive and negative
HMAC signature fixtures.

## Rust Test Path

```toml
[dev-dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["webhook"] }
```

```rust
use uselesskey::{Factory, WebhookFactoryExt, WebhookPayloadSpec};

let fx = Factory::deterministic_from_str("downstream-webhook");
let fixture = fx.webhook_stripe("payment", WebhookPayloadSpec::Canonical);

let valid_headers = fixture.headers();
let stale = fixture.near_miss_stale_timestamp(300);
let wrong_secret = fixture.near_miss_wrong_secret();
let tampered = fixture.near_miss_tampered_payload();
```

Assert that the verifier accepts the valid fixture and rejects stale timestamp,
wrong-secret, and tampered-body cases distinctly.

## Installed Bundle Path

```bash
uselesskey bundle --profile webhook --out target/uselesskey-webhook
uselesskey verify-bundle target/uselesskey-webhook
uselesskey inspect-bundle target/uselesskey-webhook
uselesskey audit-bundle \
  target/uselesskey-webhook \
  --ci \
  --expect-profile webhook \
  --policy strict \
  --out target/uselesskey-webhook-audit
```

## Boundary

This proves local fixture generation and metadata-only audit receipts. It does
not prove Stripe, GitHub, or other provider compatibility; production secret
handling; replay protection completeness; or transport security.
