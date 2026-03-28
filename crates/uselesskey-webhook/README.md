# uselesskey-webhook

Deterministic webhook fixture generation for tests.

This crate provides provider-aware webhook fixtures (GitHub, Stripe, Slack),
including canonical payloads, provider signature headers, and negative-test
near misses (stale timestamp, wrong secret, tampered payload).

Use it as a dev-dependency and generate secrets/payloads at runtime instead of
committing secret-shaped blobs into your repository.
