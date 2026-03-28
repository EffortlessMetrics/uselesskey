use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use uselesskey_core::Factory;

pub const DOMAIN_WEBHOOK_FIXTURE: &str = "uselesskey:webhook:fixture";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WebhookProfile {
    Github,
    Stripe,
    Slack,
}

impl WebhookProfile {
    fn as_tag(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Stripe => "stripe",
            Self::Slack => "slack",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct WebhookPayloadSpec {
    event_type: String,
}

impl WebhookPayloadSpec {
    pub fn event(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
        }
    }

    pub fn github_push() -> Self {
        Self::event("push")
    }

    pub fn stripe_payment_succeeded() -> Self {
        Self::event("payment_intent.succeeded")
    }

    pub fn slack_event_callback() -> Self {
        Self::event("event_callback")
    }

    fn stable_bytes(&self) -> Vec<u8> {
        self.event_type.as_bytes().to_vec()
    }
}

#[derive(Clone)]
pub struct WebhookFixture {
    pub profile: WebhookProfile,
    pub label: String,
    pub secret: String,
    pub payload: Vec<u8>,
    pub headers: BTreeMap<String, String>,
    pub timestamp: i64,
    pub signature_input: String,
}

impl fmt::Debug for WebhookFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookFixture")
            .field("profile", &self.profile)
            .field("label", &self.label)
            .field("payload_len", &self.payload.len())
            .field("headers", &self.headers)
            .field("timestamp", &self.timestamp)
            .field("signature_input", &self.signature_input)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct NearMissWebhookFixture {
    pub stale_timestamp: i64,
    pub stale_headers: BTreeMap<String, String>,
    pub wrong_secret: String,
    pub tampered_payload: Vec<u8>,
    pub tampered_headers: BTreeMap<String, String>,
}

pub trait WebhookFactoryExt {
    fn webhook(&self, profile: WebhookProfile, label: impl AsRef<str>, spec: WebhookPayloadSpec)
    -> WebhookFixture;

    fn webhook_github(&self, label: impl AsRef<str>, spec: WebhookPayloadSpec) -> WebhookFixture;

    fn webhook_stripe(&self, label: impl AsRef<str>, spec: WebhookPayloadSpec) -> WebhookFixture;

    fn webhook_slack(&self, label: impl AsRef<str>, spec: WebhookPayloadSpec) -> WebhookFixture;

    fn webhook_near_miss(&self, fixture: &WebhookFixture) -> NearMissWebhookFixture;
}

#[derive(Clone)]
struct Inner {
    fixture: WebhookFixture,
}

impl WebhookFactoryExt for Factory {
    fn webhook(
        &self,
        profile: WebhookProfile,
        label: impl AsRef<str>,
        spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        let label = label.as_ref();
        let spec_bytes = stable_spec_bytes(profile, &spec);
        let inner = load_inner(self, profile, label, &spec_bytes, "good", &spec);
        inner.fixture.clone()
    }

    fn webhook_github(&self, label: impl AsRef<str>, spec: WebhookPayloadSpec) -> WebhookFixture {
        self.webhook(WebhookProfile::Github, label, spec)
    }

    fn webhook_stripe(&self, label: impl AsRef<str>, spec: WebhookPayloadSpec) -> WebhookFixture {
        self.webhook(WebhookProfile::Stripe, label, spec)
    }

    fn webhook_slack(&self, label: impl AsRef<str>, spec: WebhookPayloadSpec) -> WebhookFixture {
        self.webhook(WebhookProfile::Slack, label, spec)
    }

    fn webhook_near_miss(&self, fixture: &WebhookFixture) -> NearMissWebhookFixture {
        let stale_timestamp = fixture.timestamp - 60 * 60;
        let stale = build_fixture(
            fixture.profile,
            &fixture.label,
            &fixture.secret,
            &fixture.payload,
            stale_timestamp,
        );
        let wrong_secret = format!("{}-wrong", fixture.secret);

        let mut tampered_payload = fixture.payload.clone();
        if let Some(last) = tampered_payload.last_mut() {
            *last ^= 0x01;
        } else {
            tampered_payload.push(0x01);
        }

        let tampered = build_fixture(
            fixture.profile,
            &fixture.label,
            &fixture.secret,
            &tampered_payload,
            fixture.timestamp,
        );

        NearMissWebhookFixture {
            stale_timestamp,
            stale_headers: stale.headers,
            wrong_secret,
            tampered_payload,
            tampered_headers: tampered.headers,
        }
    }
}

fn stable_spec_bytes(profile: WebhookProfile, spec: &WebhookPayloadSpec) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + spec.event_type.len());
    out.extend_from_slice(profile.as_tag().as_bytes());
    out.push(0x00);
    out.extend_from_slice(&spec.stable_bytes());
    out
}

fn load_inner(
    factory: &Factory,
    profile: WebhookProfile,
    label: &str,
    spec_bytes: &[u8],
    variant: &str,
    spec: &WebhookPayloadSpec,
) -> Arc<Inner> {
    factory.get_or_init(DOMAIN_WEBHOOK_FIXTURE, label, spec_bytes, variant, |seed| {
        let secret = derive_secret(profile, &seed);
        let timestamp = derive_timestamp(&seed);
        let payload = canonical_payload(profile, label, spec, &seed);
        let fixture = build_fixture(profile, label, &secret, &payload, timestamp);
        Inner { fixture }
    })
}

fn derive_secret(profile: WebhookProfile, seed: &uselesskey_core::Seed) -> String {
    let mut bytes = [0u8; 32];
    seed.fill_bytes(&mut bytes);

    match profile {
        WebhookProfile::Github => hex::encode(bytes),
        WebhookProfile::Stripe => format!("whsec_{}", hex::encode(bytes)),
        WebhookProfile::Slack => URL_SAFE_NO_PAD.encode(bytes),
    }
}

fn derive_timestamp(seed: &uselesskey_core::Seed) -> i64 {
    let mut bytes = [0u8; 8];
    seed.fill_bytes(&mut bytes);
    let n = u64::from_le_bytes(bytes);
    1_700_000_000_i64 + (n % 10_000_000) as i64
}

fn canonical_payload(
    profile: WebhookProfile,
    label: &str,
    spec: &WebhookPayloadSpec,
    seed: &uselesskey_core::Seed,
) -> Vec<u8> {
    #[derive(Serialize)]
    struct Payload<'a> {
        provider: &'a str,
        label: &'a str,
        event_type: &'a str,
        delivery_id: String,
        attempt: u8,
    }

    let mut id_bytes = [0u8; 12];
    seed.fill_bytes(&mut id_bytes);

    let payload = Payload {
        provider: profile.as_tag(),
        label,
        event_type: &spec.event_type,
        delivery_id: hex::encode(id_bytes),
        attempt: ((id_bytes[0] % 3) + 1),
    };

    serde_json::to_vec(&payload).expect("serialize canonical payload")
}

fn build_fixture(
    profile: WebhookProfile,
    label: &str,
    secret: &str,
    payload: &[u8],
    timestamp: i64,
) -> WebhookFixture {
    let signature_input = signature_input(profile, timestamp, payload);
    let signature = sign_sha256(secret.as_bytes(), signature_input.as_bytes());

    let mut headers = BTreeMap::new();
    match profile {
        WebhookProfile::Github => {
            headers.insert(
                "X-Hub-Signature-256".to_string(),
                format!("sha256={signature}"),
            );
            headers.insert("X-GitHub-Event".to_string(), "push".to_string());
            headers.insert("X-GitHub-Delivery".to_string(), format!("{label}-{timestamp}"));
        }
        WebhookProfile::Stripe => {
            headers.insert(
                "Stripe-Signature".to_string(),
                format!("t={timestamp},v1={signature}"),
            );
        }
        WebhookProfile::Slack => {
            headers.insert("X-Slack-Request-Timestamp".to_string(), timestamp.to_string());
            headers.insert("X-Slack-Signature".to_string(), format!("v0={signature}"));
        }
    }

    WebhookFixture {
        profile,
        label: label.to_string(),
        secret: secret.to_string(),
        payload: payload.to_vec(),
        headers,
        timestamp,
        signature_input,
    }
}

fn signature_input(profile: WebhookProfile, timestamp: i64, payload: &[u8]) -> String {
    let payload_str = String::from_utf8_lossy(payload);
    match profile {
        WebhookProfile::Github => payload_str.to_string(),
        WebhookProfile::Stripe => format!("{timestamp}.{payload_str}"),
        WebhookProfile::Slack => format!("v0:{timestamp}:{payload_str}"),
    }
}

fn sign_sha256(secret: &[u8], data: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key init");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    hex::encode(out)
}
