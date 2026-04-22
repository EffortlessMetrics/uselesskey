#![forbid(unsafe_code)]

//! Webhook fixtures built on `uselesskey-core`.
//!
//! This crate provides deterministic provider-style webhook fixtures with canonical
//! payloads, signature input strings, and signed headers.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{KeyInit, Mac};
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use serde_json::json;
use sha2::Sha256;
use uselesskey_core::Factory;

/// Cache domain for webhook fixtures.
pub const DOMAIN_WEBHOOK_FIXTURE: &str = "uselesskey:webhook:fixture";

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
    fn stable_tag(self) -> &'static str {
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
    fn stable_bytes(&self) -> Vec<u8> {
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

/// Extension trait to generate webhook fixtures from [`Factory`].
pub trait WebhookFactoryExt {
    /// Generate a webhook fixture for an explicit profile.
    fn webhook(
        &self,
        profile: WebhookProfile,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;

    /// Generate a GitHub webhook fixture.
    fn webhook_github(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;

    /// Generate a Stripe webhook fixture.
    fn webhook_stripe(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;

    /// Generate a Slack webhook fixture.
    fn webhook_slack(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;
}

impl WebhookFactoryExt for Factory {
    fn webhook(
        &self,
        profile: WebhookProfile,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        let label = label.as_ref();
        let spec_bytes = stable_spec_bytes(profile, &payload_spec);
        let cached = self.get_or_init(DOMAIN_WEBHOOK_FIXTURE, label, &spec_bytes, "good", |seed| {
            build_fixture_from_seed(profile, label, payload_spec.clone(), seed.bytes())
        });
        cached.as_ref().clone()
    }

    fn webhook_github(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        self.webhook(WebhookProfile::GitHub, label, payload_spec)
    }

    fn webhook_stripe(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        self.webhook(WebhookProfile::Stripe, label, payload_spec)
    }

    fn webhook_slack(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        self.webhook(WebhookProfile::Slack, label, payload_spec)
    }
}

impl WebhookFixture {
    /// Produce a stale-timestamp variant for replay-window tests.
    pub fn near_miss_stale_timestamp(&self, max_age_secs: i64) -> NearMissWebhookFixture {
        let stale_ts = self.timestamp - max_age_secs - 1;
        let mut f = self.with_timestamp(stale_ts);
        f.scenario = NearMissScenario::StaleTimestamp;
        f
    }

    /// Produce a wrong-secret variant for verifier mismatch tests.
    pub fn near_miss_wrong_secret(&self) -> NearMissWebhookFixture {
        let mut wrong_secret = self.secret.clone();
        wrong_secret.push_str("_wrong");
        let mut f = build_near_miss(
            self.profile,
            wrong_secret,
            self.payload.clone(),
            self.timestamp,
        );
        f.scenario = NearMissScenario::WrongSecret;
        f
    }

    /// Produce a tampered-payload variant for integrity tests.
    pub fn near_miss_tampered_payload(&self) -> NearMissWebhookFixture {
        let tampered = format!("{}{}", self.payload, "\n");
        let mut f = build_near_miss(self.profile, self.secret.clone(), tampered, self.timestamp);
        f.scenario = NearMissScenario::TamperedPayload;
        f
    }

    fn with_timestamp(&self, timestamp: i64) -> NearMissWebhookFixture {
        build_near_miss(
            self.profile,
            self.secret.clone(),
            self.payload.clone(),
            timestamp,
        )
    }
}

fn build_near_miss(
    profile: WebhookProfile,
    secret: String,
    payload: String,
    timestamp: i64,
) -> NearMissWebhookFixture {
    let (headers, signature_input) = sign(profile, &secret, &payload, timestamp);
    NearMissWebhookFixture {
        scenario: NearMissScenario::StaleTimestamp,
        profile,
        secret,
        payload,
        headers,
        timestamp,
        signature_input,
    }
}

fn stable_spec_bytes(profile: WebhookProfile, payload_spec: &WebhookPayloadSpec) -> Vec<u8> {
    let mut out = profile.stable_tag().as_bytes().to_vec();
    out.push(0);
    out.extend_from_slice(&payload_spec.stable_bytes());
    out
}

fn build_fixture_from_seed(
    profile: WebhookProfile,
    label: &str,
    payload_spec: WebhookPayloadSpec,
    seed: &[u8; 32],
) -> WebhookFixture {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let secret = build_secret(profile, &mut rng);
    let timestamp = 1_700_000_000_i64 + (rng.next_u32() as i64 % 200_000_000_i64);
    let payload = canonical_payload(profile, label, payload_spec, rng.next_u32());
    let (headers, signature_input) = sign(profile, &secret, &payload, timestamp);

    WebhookFixture {
        profile,
        secret,
        payload,
        headers,
        timestamp,
        signature_input,
    }
}

fn build_secret(profile: WebhookProfile, rng: &mut ChaCha20Rng) -> String {
    let mut secret_bytes = [0_u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    match profile {
        WebhookProfile::GitHub => format!("ghs_{}", URL_SAFE_NO_PAD.encode(secret_bytes)),
        WebhookProfile::Stripe => format!("whsec_{}", hex::encode(secret_bytes)),
        WebhookProfile::Slack => hex::encode(secret_bytes),
    }
}

fn canonical_payload(
    profile: WebhookProfile,
    label: &str,
    payload_spec: WebhookPayloadSpec,
    nonce: u32,
) -> String {
    match payload_spec {
        WebhookPayloadSpec::Raw(payload) => payload,
        WebhookPayloadSpec::Canonical => match profile {
            WebhookProfile::GitHub => json!({
                "action": "opened",
                "repository": {
                    "full_name": format!("acme/{label}")
                },
                "number": (nonce % 9000) + 1000
            })
            .to_string(),
            WebhookProfile::Stripe => json!({
                "id": format!("evt_{nonce:08x}"),
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "metadata": {
                            "label": label
                        }
                    }
                }
            })
            .to_string(),
            WebhookProfile::Slack => json!({
                "type": "event_callback",
                "team_id": format!("T{nonce:08x}"),
                "event": {
                    "type": "app_mention",
                    "text": format!("ping {label}")
                }
            })
            .to_string(),
        },
    }
}

fn sign(
    profile: WebhookProfile,
    secret: &str,
    payload: &str,
    timestamp: i64,
) -> (BTreeMap<String, String>, String) {
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    match profile {
        WebhookProfile::GitHub => {
            let signature_input = payload.to_string();
            let digest = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
            headers.insert(
                "X-Hub-Signature-256".to_string(),
                format!("sha256={digest}"),
            );
            (headers, signature_input)
        }
        WebhookProfile::Stripe => {
            let signature_input = format!("{timestamp}.{payload}");
            let digest = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
            headers.insert(
                "Stripe-Signature".to_string(),
                format!("t={timestamp},v1={digest}"),
            );
            (headers, signature_input)
        }
        WebhookProfile::Slack => {
            let signature_input = format!("v0:{timestamp}:{payload}");
            let digest = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
            headers.insert(
                "X-Slack-Request-Timestamp".to_string(),
                timestamp.to_string(),
            );
            headers.insert("X-Slack-Signature".to_string(), format!("v0={digest}"));
            (headers, signature_input)
        }
    }
}

fn hmac_sha256_hex(secret: &[u8], msg: &[u8]) -> String {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key is always valid");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    hex::encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    fn verify_github(secret: &str, payload: &str, headers: &BTreeMap<String, String>) -> bool {
        let expected = format!(
            "sha256={}",
            hmac_sha256_hex(secret.as_bytes(), payload.as_bytes())
        );
        headers.get("X-Hub-Signature-256") == Some(&expected)
    }

    fn verify_stripe(
        secret: &str,
        payload: &str,
        headers: &BTreeMap<String, String>,
        now: i64,
        tolerance_secs: i64,
    ) -> bool {
        let Some(sig_header) = headers.get("Stripe-Signature") else {
            return false;
        };
        let mut ts = None;
        let mut v1 = None;
        for part in sig_header.split(',') {
            if let Some(v) = part.strip_prefix("t=") {
                ts = v.parse::<i64>().ok();
            }
            if let Some(v) = part.strip_prefix("v1=") {
                v1 = Some(v.to_string());
            }
        }
        let Some(ts) = ts else {
            return false;
        };
        if (now - ts).abs() > tolerance_secs {
            return false;
        }
        let base = format!("{ts}.{payload}");
        let expected = hmac_sha256_hex(secret.as_bytes(), base.as_bytes());
        v1.as_deref() == Some(expected.as_str())
    }

    fn verify_slack(
        secret: &str,
        payload: &str,
        headers: &BTreeMap<String, String>,
        now: i64,
        tolerance_secs: i64,
    ) -> bool {
        let Some(ts_str) = headers.get("X-Slack-Request-Timestamp") else {
            return false;
        };
        let Ok(ts) = ts_str.parse::<i64>() else {
            return false;
        };
        if (now - ts).abs() > tolerance_secs {
            return false;
        }
        let Some(sig) = headers.get("X-Slack-Signature") else {
            return false;
        };
        let base = format!("v0:{ts}:{payload}");
        let expected = format!("v0={}", hmac_sha256_hex(secret.as_bytes(), base.as_bytes()));
        sig == &expected
    }

    #[test]
    fn deterministic_github_fixture_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-gh").unwrap());
        let a = fx.webhook_github("repo", WebhookPayloadSpec::Canonical);
        let b = fx.webhook_github("repo", WebhookPayloadSpec::Canonical);
        assert_eq!(a.secret, b.secret);
        assert_eq!(a.payload, b.payload);
        assert_eq!(a.headers, b.headers);
        assert!(verify_github(&a.secret, &a.payload, &a.headers));
    }

    #[test]
    fn provider_signature_paths_verify() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-providers").unwrap());
        let gh = fx.webhook(WebhookProfile::GitHub, "a", WebhookPayloadSpec::Canonical);
        let st = fx.webhook_stripe("b", WebhookPayloadSpec::Canonical);
        let sl = fx.webhook_slack("c", WebhookPayloadSpec::Canonical);

        assert!(verify_github(&gh.secret, &gh.payload, &gh.headers));
        assert!(verify_stripe(
            &st.secret,
            &st.payload,
            &st.headers,
            st.timestamp,
            300
        ));
        assert!(verify_slack(
            &sl.secret,
            &sl.payload,
            &sl.headers,
            sl.timestamp,
            300
        ));
    }

    #[test]
    fn header_shape_matches_provider_conventions() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-headers").unwrap());
        let gh = fx.webhook_github("r", WebhookPayloadSpec::Canonical);
        assert!(
            gh.headers
                .get("X-Hub-Signature-256")
                .is_some_and(|v| v.starts_with("sha256="))
        );

        let st = fx.webhook_stripe("r", WebhookPayloadSpec::Canonical);
        let stripe_header = st.headers.get("Stripe-Signature").expect("stripe header");
        assert!(stripe_header.contains("t="));
        assert!(stripe_header.contains(",v1="));

        let sl = fx.webhook_slack("r", WebhookPayloadSpec::Canonical);
        assert!(sl.headers.contains_key("X-Slack-Request-Timestamp"));
        assert!(
            sl.headers
                .get("X-Slack-Signature")
                .is_some_and(|v| v.starts_with("v0="))
        );
    }

    #[test]
    fn near_miss_negatives_fail_provider_verification() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-nearmiss").unwrap());
        let st = fx.webhook_stripe("billing", WebhookPayloadSpec::Canonical);
        let now = st.timestamp;

        let stale = st.near_miss_stale_timestamp(300);
        assert!(!verify_stripe(
            &st.secret,
            &st.payload,
            &stale.headers,
            now,
            300
        ));

        let wrong_secret = st.near_miss_wrong_secret();
        assert!(!verify_stripe(
            &st.secret,
            &wrong_secret.payload,
            &wrong_secret.headers,
            wrong_secret.timestamp,
            300
        ));

        let tampered = st.near_miss_tampered_payload();
        assert!(!verify_stripe(
            &tampered.secret,
            &st.payload,
            &tampered.headers,
            tampered.timestamp,
            300
        ));
    }

    #[test]
    fn debug_redacts_secret() {
        let fx = Factory::random();
        let fixture = fx.webhook_slack("debug", WebhookPayloadSpec::Canonical);
        let out = format!("{fixture:?}");
        assert!(!out.contains(&fixture.secret));
        assert!(out.contains("WebhookFixture"));

        let near_miss = fixture.near_miss_wrong_secret();
        let out = format!("{near_miss:?}");
        assert!(!out.contains(&near_miss.secret));
        assert!(out.contains("NearMissWebhookFixture"));
    }

    #[test]
    fn canonical_payload_escapes_special_characters_in_label() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-label-escape").unwrap());
        let label = "repo\"line\nbreak\\slash";
        let fixtures = [
            fx.webhook_github(label, WebhookPayloadSpec::Canonical),
            fx.webhook_stripe(label, WebhookPayloadSpec::Canonical),
            fx.webhook_slack(label, WebhookPayloadSpec::Canonical),
        ];

        for fixture in fixtures {
            let parsed: serde_json::Value =
                serde_json::from_str(&fixture.payload).expect("canonical payload should be valid");
            let serialized = parsed.to_string();
            assert!(
                serialized.contains("repo\\\"line\\nbreak\\\\slash"),
                "serialized payload should preserve escaped label, got: {serialized}"
            );
        }
    }
}
