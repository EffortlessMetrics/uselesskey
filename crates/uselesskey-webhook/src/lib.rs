#![forbid(unsafe_code)]

//! Webhook fixtures built on `uselesskey-core`.
//!
//! This crate generates deterministic webhook payloads, signatures, and headers for
//! provider-specific verifier paths in tests.

mod webhook;

pub use webhook::{
    DOMAIN_WEBHOOK_FIXTURE, NearMissWebhookFixture, WebhookFactoryExt, WebhookFixture,
    WebhookPayloadSpec, WebhookProfile,
};
