# Test webhook signature validation with scanner-safe fixtures

Use this guide when you are building a webhook consumer (Stripe-style,
GitHub-style, Slack-style) and need realistic HMAC-signed payloads
where the signing secret, body, and resulting signature header all
match — but where committing the signing secret would trip secret
scanners. The `uselesskey-webhook` crate emits deterministic
provider-style fixtures for `X-Hub-Signature-256` (GitHub),
`Stripe-Signature` (Stripe), and `X-Slack-Signature` (Slack), plus
near-miss negatives for the three rejection paths your consumer
should enforce.

## Add the dependency

```toml
[dev-dependencies]
uselesskey = { version = "0.7", default-features = false, features = ["webhook"] }
```

Or depend on `uselesskey-webhook` directly if you only need this
surface:

```toml
[dev-dependencies]
uselesskey-webhook = "0.7"
uselesskey-core = "0.7"
```

## Generate the contract pack

Use the bundle profile when you want filesystem fixtures plus receipts
that a reviewer can inspect:

```bash
cargo run -p uselesskey-cli -- bundle \
  --profile webhook \
  --out target/webhook-fixtures

cargo run -p uselesskey-cli -- verify-bundle \
  --path target/webhook-fixtures

cargo run -p uselesskey-cli -- inspect-bundle \
  --path target/webhook-fixtures
```

The contract pack writes:

- `requests/valid.json`
- `requests/negative-tampered-body.json`
- `requests/negative-wrong-secret.json`
- `requests/negative-stale-timestamp.json`
- `requests/negative-missing-signature.json`
- `requests/negative-malformed-signature.json`
- `evidence/webhook-profile.md`
- `receipts/materialization.json`
- `receipts/audit-surface.json`
- `manifest.json`

Each request fixture records `method`, `path`, `timestamp`, `body`,
`headers`, `expected_result`, `rejection_class`, and
`verifier_secret`.

For release-grade evidence that the bundle still reproduces:

```bash
cargo xtask bundle-proof --profile webhook --out target/release-evidence/webhook
cargo xtask no-blob
```

`bundle-proof` writes `webhook-contract-pack-proof.json` and
`webhook-contract-pack-proof.md` under
`target/release-evidence/webhook/`.

## Generate a signed webhook fixture

The Stripe profile is the most common starting point because it
exercises both the signed-body and signed-timestamp halves of the
verifier.

```rust
use uselesskey::{Factory, WebhookFactoryExt, WebhookPayloadSpec};

let fx = Factory::deterministic_from_str("webhook-signature-tests");
let fixture = fx.webhook_stripe("payment-succeeded", WebhookPayloadSpec::Canonical);

let secret = &fixture.secret;          // e.g. "whsec_<64 hex chars>"
let body = &fixture.payload;           // canonical JSON event body
let sig_header = fixture.headers       // "t=<ts>,v1=<hex digest>"
    .get("Stripe-Signature")
    .expect("stripe header is always written");
let timestamp = fixture.timestamp;     // i64 unix epoch seconds used in the signature
```

For GitHub use `fx.webhook_github(...)`; for Slack use
`fx.webhook_slack(...)`. The generic entry point is
`fx.webhook(WebhookProfile::Stripe, label, spec)`.

`WebhookPayloadSpec::Canonical` selects the built-in provider
payload template. To sign your own body use
`WebhookPayloadSpec::Raw("...".to_string())`. The cache key is
keyed on `(profile, payload_spec, label)`, so the same call with the
same factory always returns byte-identical bytes.

## Verify the fixture in your consumer

The fixture is signed with HMAC-SHA256 in every profile. The base
string differs by provider:

| Profile | Header | Base string |
| --- | --- | --- |
| GitHub | `X-Hub-Signature-256: sha256=<hex>` | `body` |
| Stripe | `Stripe-Signature: t=<ts>,v1=<hex>` | `format!("{ts}.{body}")` |
| Slack  | `X-Slack-Signature: v0=<hex>` plus `X-Slack-Request-Timestamp: <ts>` | `format!("v0:{ts}:{body}")` |

A Stripe-style verifier under test should reconstruct the base
string from the header timestamp and the request body, recompute the
HMAC, and compare in constant time:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn verify_stripe(secret: &str, body: &str, sig_header: &str, now: i64, tolerance: i64) -> bool {
    let mut ts = None;
    let mut v1 = None;
    for part in sig_header.split(',') {
        if let Some(v) = part.strip_prefix("t=") { ts = v.parse::<i64>().ok(); }
        if let Some(v) = part.strip_prefix("v1=") { v1 = Some(v); }
    }
    let Some(ts) = ts else { return false; };
    if (now - ts).abs() > tolerance { return false; }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{ts}.{body}").as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    v1 == Some(expected.as_str())
}
```

Drive the verifier with the fixture and assert the happy path:

```rust
assert!(verify_stripe(
    &fixture.secret,
    &fixture.payload,
    fixture.headers.get("Stripe-Signature").unwrap(),
    fixture.timestamp,
    300,
));
```

## Test the failure paths

The `WebhookFixture` exposes three near-miss constructors that
return a `NearMissWebhookFixture` with the same shape, but with one
verification invariant deliberately broken. Each one targets a
distinct rejection path.

```rust
use uselesskey::NearMissScenario;

let stale = fixture.near_miss_stale_timestamp(300);
assert_eq!(stale.scenario, NearMissScenario::StaleTimestamp);
assert!(!verify_stripe(
    &fixture.secret,
    &fixture.payload,
    stale.headers.get("Stripe-Signature").unwrap(),
    fixture.timestamp, // verifier "now"
    300,
));

let wrong = fixture.near_miss_wrong_secret();
assert_eq!(wrong.scenario, NearMissScenario::WrongSecret);
assert!(!verify_stripe(
    &fixture.secret,                  // verifier knows the original secret
    &wrong.payload,
    wrong.headers.get("Stripe-Signature").unwrap(),
    wrong.timestamp,
    300,
));

let tampered = fixture.near_miss_tampered_payload();
assert_eq!(tampered.scenario, NearMissScenario::TamperedPayload);
assert!(!verify_stripe(
    &tampered.secret,
    &fixture.payload,                 // verifier sees the original body
    tampered.headers.get("Stripe-Signature").unwrap(),
    tampered.timestamp,
    300,
));
```

`StaleTimestamp` shifts the header timestamp outside the tolerance
window; the verifier should reject on the freshness check before it
recomputes any HMAC. `WrongSecret` signs the same body with a
different secret; the verifier should reject on signature compare.
`TamperedPayload` mutates the body after signing; the verifier sees
the original body and the signed-body mismatch should surface as a
signature failure.

## What this proves

- Your consumer verifies HMAC-SHA256 signatures over the provider's
  canonical base string.
- Your consumer enforces a replay-window check on the signed
  timestamp.
- Your consumer rejects requests signed by an unknown secret.
- Your consumer rejects requests whose body no longer matches the
  signed bytes.

## What this does not prove

- It does not prove production provider compatibility.
- It does not prove webhook delivery, retry, or back-off semantics.
- It does not prove replay protection beyond the timestamp tolerance
  check; storing seen `(timestamp, signature)` pairs is your
  consumer's responsibility.
- It does not prove provider-specific quirks beyond the three
  encoded profiles (e.g. multi-signature `Stripe-Signature` rotation
  pairs, GitHub legacy `X-Hub-Signature` SHA-1).
- It does not prove production secret custody or rotation policy.
- It does not prove transport security.

## Scanner-safety note

Signing secrets are derived from the factory seed; they are
fixture-shaped (`whsec_<hex>`, `ghs_<base64url>`, `<64 hex chars>`)
but never production HMAC material. Keep generated signed-payload
files under `target/` rather than committing them — even a
deterministic fixture body plus its header pair is the kind of
high-entropy artifact a scanner may flag. The
[`../release/publish-recovery.md`](../release/publish-recovery.md)
recovery doc covers the registry-truth analogue if a real secret
ever lands in a commit.

The `WebhookFixture` `Debug` impl redacts `secret` via
`finish_non_exhaustive()`, so logging a fixture in a failing test
will not leak the secret string into CI logs.

## See also

- [`../../crates/uselesskey-webhook/README.md`](../../crates/uselesskey-webhook/README.md)
  — crate-level overview of the supported providers and header
  shapes.
- [`test-oidc-jwks-validation.md`](test-oidc-jwks-validation.md)
  — the JWKS analogue for asymmetric-signature validation paths.
- [`test-jwt-negative-validation.md`](test-jwt-negative-validation.md)
  — JWT-shaped negative inputs for downstream token validators.
- [`../specs/USELESSKEY-SPEC-0011-webhook-contract-pack.md`](../specs/USELESSKEY-SPEC-0011-webhook-contract-pack.md)
  — contract-pack behavior, evidence, and claim boundary.
