use std::collections::BTreeMap;
use std::fmt;

/// Supported webhook signing profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WebhookProfile {
    /// GitHub webhook signature profile.
    GitHub,
    /// Stripe webhook signature profile.
    Stripe,
    /// Slack webhook signature profile.
    Slack,
}

impl WebhookProfile {
    pub(crate) fn stable_tag(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Stripe => "stripe",
            Self::Slack => "slack",
        }
    }
}

/// Canonical payload presets for webhook fixtures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebhookPayloadSpec {
    /// Use the built-in provider canonical payload template.
    Canonical,
    /// Use an explicit payload string.
    Raw(String),
}

impl WebhookPayloadSpec {
    pub(crate) fn stable_bytes(&self) -> Vec<u8> {
        match self {
            Self::Canonical => b"canonical".to_vec(),
            Self::Raw(payload) => {
                let mut out = b"raw:".to_vec();
                out.extend_from_slice(payload.as_bytes());
                out
            }
        }
    }
}

/// A generated webhook fixture.
#[derive(Clone)]
pub struct WebhookFixture {
    /// Profile used to generate fixture semantics.
    pub profile: WebhookProfile,
    /// Signing secret (test-only).
    pub secret: String,
    /// Canonical payload body.
    pub payload: String,
    /// HTTP headers to attach to the request.
    pub headers: BTreeMap<String, String>,
    /// Timestamp used in signature generation (unix epoch seconds).
    pub timestamp: i64,
    /// Canonical signature input/base string.
    pub signature_input: String,
}

impl fmt::Debug for WebhookFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookFixture")
            .field("profile", &self.profile)
            .field("payload", &self.payload)
            .field("headers", &self.headers)
            .field("timestamp", &self.timestamp)
            .field("signature_input", &self.signature_input)
            .finish_non_exhaustive()
    }
}

/// A near-miss webhook fixture for negative tests.
#[derive(Clone)]
pub struct NearMissWebhookFixture {
    /// Negative scenario marker.
    pub scenario: NearMissScenario,
    /// Profile used to generate fixture semantics.
    pub profile: WebhookProfile,
    /// Signing secret (intentionally wrong for `WrongSecret`).
    pub secret: String,
    /// Payload body (intentionally modified for `TamperedPayload`).
    pub payload: String,
    /// HTTP headers to attach to the request.
    pub headers: BTreeMap<String, String>,
    /// Timestamp used in signature generation (may be stale).
    pub timestamp: i64,
    /// Canonical signature input/base string.
    pub signature_input: String,
}

impl fmt::Debug for NearMissWebhookFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NearMissWebhookFixture")
            .field("scenario", &self.scenario)
            .field("profile", &self.profile)
            .field("payload", &self.payload)
            .field("headers", &self.headers)
            .field("timestamp", &self.timestamp)
            .field("signature_input", &self.signature_input)
            .finish_non_exhaustive()
    }
}

/// Supported near-miss negative scenarios.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NearMissScenario {
    /// Header timestamp falls outside the acceptable window.
    StaleTimestamp,
    /// Request signed with an alternate secret not used by verifier.
    WrongSecret,
    /// Payload differs from what was signed.
    TamperedPayload,
}
