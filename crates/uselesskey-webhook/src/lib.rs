#![forbid(unsafe_code)]

//! Webhook fixtures built on `uselesskey-core`.
//!
//! Generates deterministic or random webhook fixtures for common providers,
//! including provider-style signed headers and canonical payload bytes.

mod webhook;

pub use webhook::{
    DOMAIN_WEBHOOK_FIXTURE, NearMissWebhookFixture, WebhookFactoryExt, WebhookFixture,
    WebhookPayloadSpec, WebhookProfile,
};
