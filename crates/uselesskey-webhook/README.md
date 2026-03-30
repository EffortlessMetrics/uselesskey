# uselesskey-webhook

Webhook fixtures for tests.

Generates deterministic provider-style webhook secrets, payloads, signature base strings,
and signed headers for:
- GitHub (`X-Hub-Signature-256`)
- Stripe (`Stripe-Signature`)
- Slack (`X-Slack-Signature`)

Use this crate in tests when you want realistic webhook signature handling without committing
secret-shaped blobs to source control.
