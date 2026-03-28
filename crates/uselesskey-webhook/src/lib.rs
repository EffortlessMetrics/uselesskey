#![forbid(unsafe_code)]

//! Webhook fixtures built on `uselesskey-core`.
//!
//! Generates deterministic webhook signing secrets, canonical payload bodies,
//! signature inputs, and provider-shaped HTTP headers for tests.

mod webhook;

pub use webhook::{
    DOMAIN_WEBHOOK_FIXTURE, NearMissKind, NearMissWebhookFixture, WebhookFactoryExt, WebhookFixture,
    WebhookPayloadSpec, WebhookProfile,
};
