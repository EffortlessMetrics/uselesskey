use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uselesskey_core::Factory;

/// Cache domain for webhook fixtures.
pub const DOMAIN_WEBHOOK_FIXTURE: &str = "uselesskey:webhook:fixture";

/// Supported webhook providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WebhookProfile {
    GitHub,
    Stripe,
    Slack,
}

impl WebhookProfile {
    pub const fn stable_bytes(self) -> [u8; 4] {
        match self {
            Self::GitHub => [0, 0, 0, 1],
            Self::Stripe => [0, 0, 0, 2],
            Self::Slack => [0, 0, 0, 3],
        }
    }
}

/// Payload templates for webhook fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WebhookPayloadSpec {
    /// Minimal provider-default event shape.
    Basic,
}

impl WebhookPayloadSpec {
    pub const fn basic() -> Self {
        Self::Basic
    }

    pub const fn stable_bytes(self) -> [u8; 4] {
        match self {
            Self::Basic => [0, 0, 0, 1],
        }
    }
}

/// Complete generated webhook fixture for tests.
#[derive(Clone)]
pub struct WebhookFixture {
    pub secret: String,
    pub payload: String,
    pub headers: BTreeMap<String, String>,
    pub timestamp: i64,
    pub signature_input: String,
}

impl fmt::Debug for WebhookFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookFixture")
            .field("payload", &self.payload)
            .field("headers", &self.headers)
            .field("timestamp", &self.timestamp)
            .field("signature_input", &self.signature_input)
            .finish_non_exhaustive()
    }
}

/// Negative test fixture variant derived from a valid [`WebhookFixture`].
#[derive(Clone, Debug)]
pub struct NearMissWebhookFixture {
    pub kind: NearMissKind,
    pub fixture: WebhookFixture,
}

/// Category of intended verification failure for a near-miss fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NearMissKind {
    StaleTimestamp,
    WrongSecret,
    TamperedPayload,
}

/// Extension trait to hang webhook helpers off [`Factory`].
pub trait WebhookFactoryExt {
    fn webhook(
        &self,
        label: impl AsRef<str>,
        profile: WebhookProfile,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;

    fn webhook_github(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;

    fn webhook_stripe(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;

    fn webhook_slack(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture;
}

impl WebhookFactoryExt for Factory {
    fn webhook(
        &self,
        label: impl AsRef<str>,
        profile: WebhookProfile,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        load_inner(self, label.as_ref(), profile, payload_spec, "good").as_ref().clone()
    }

    fn webhook_github(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        self.webhook(label, WebhookProfile::GitHub, payload_spec)
    }

    fn webhook_stripe(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        self.webhook(label, WebhookProfile::Stripe, payload_spec)
    }

    fn webhook_slack(
        &self,
        label: impl AsRef<str>,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        self.webhook(label, WebhookProfile::Slack, payload_spec)
    }
}

impl WebhookFixture {
    pub fn near_miss_stale_timestamp(&self, stale_by_secs: i64) -> NearMissWebhookFixture {
        let stale_ts = self.timestamp.saturating_sub(stale_by_secs.max(1));
        let mut fixture = self.clone();
        fixture.timestamp = stale_ts;

        if fixture.headers.contains_key("Stripe-Signature") {
            let v1 = fixture
                .headers
                .get("Stripe-Signature")
                .and_then(|v| v.split(',').find_map(|part| part.strip_prefix("v1=")))
                .unwrap_or_default()
                .to_string();
            fixture
                .headers
                .insert("Stripe-Signature".to_string(), format!("t={stale_ts},v1={v1}"));
            fixture.signature_input = format!("{stale_ts}.{}", fixture.payload);
        }

        if fixture.headers.contains_key("X-Slack-Request-Timestamp") {
            fixture.headers.insert(
                "X-Slack-Request-Timestamp".to_string(),
                stale_ts.to_string(),
            );
            fixture.signature_input = format!("v0:{stale_ts}:{}", fixture.payload);
        }

        NearMissWebhookFixture {
            kind: NearMissKind::StaleTimestamp,
            fixture,
        }
    }

    pub fn near_miss_wrong_secret(&self) -> NearMissWebhookFixture {
        let mut fixture = self.clone();
        fixture.secret.push_str("_wrong");
        NearMissWebhookFixture {
            kind: NearMissKind::WrongSecret,
            fixture,
        }
    }

    pub fn near_miss_tampered_payload(&self) -> NearMissWebhookFixture {
        let mut fixture = self.clone();
        fixture.payload.push(' ');
        NearMissWebhookFixture {
            kind: NearMissKind::TamperedPayload,
            fixture,
        }
    }
}

fn load_inner(
    factory: &Factory,
    label: &str,
    profile: WebhookProfile,
    payload_spec: WebhookPayloadSpec,
    variant: &str,
) -> Arc<WebhookFixture> {
    let mut spec_bytes = [0u8; 8];
    spec_bytes[..4].copy_from_slice(&profile.stable_bytes());
    spec_bytes[4..].copy_from_slice(&payload_spec.stable_bytes());

    factory.get_or_init(DOMAIN_WEBHOOK_FIXTURE, label, &spec_bytes, variant, |seed| {
        let timestamp = derive_timestamp(seed.bytes());
        let payload = canonical_payload(profile, payload_spec, label, seed.bytes());
        let secret = derive_secret(profile, seed.bytes());
        let (headers, signature_input) = signed_headers(profile, timestamp, &payload, &secret);

        WebhookFixture {
            secret,
            payload,
            headers,
            timestamp,
            signature_input,
        }
    })
}

fn derive_timestamp(seed: &[u8; 32]) -> i64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&seed[..8]);
    let offset = u64::from_le_bytes(raw) % (365 * 24 * 60 * 60);
    1_700_000_000 + offset as i64
}

fn canonical_payload(
    profile: WebhookProfile,
    payload_spec: WebhookPayloadSpec,
    label: &str,
    seed: &[u8; 32],
) -> String {
    let tag = short_hex(&seed[8..14]);
    match (profile, payload_spec) {
        (WebhookProfile::GitHub, WebhookPayloadSpec::Basic) => serde_json::json!({
            "action": "opened",
            "repository": {"full_name": format!("{label}/demo")},
            "sender": {"login": "octocat"},
            "delivery": format!("gh_{tag}")
        })
        .to_string(),
        (WebhookProfile::Stripe, WebhookPayloadSpec::Basic) => serde_json::json!({
            "id": format!("evt_{tag}"),
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "id": format!("pi_{tag}"),
                    "object": "payment_intent",
                    "amount": 2000,
                    "currency": "usd"
                }
            }
        })
        .to_string(),
        (WebhookProfile::Slack, WebhookPayloadSpec::Basic) => serde_json::json!({
            "token": "verification_token",
            "team_id": "T012345",
            "api_app_id": "A012345",
            "event": {"type": "app_mention", "text": "hello world"},
            "type": "event_callback",
            "event_id": format!("Ev{tag}")
        })
        .to_string(),
    }
}

fn derive_secret(profile: WebhookProfile, seed: &[u8; 32]) -> String {
    match profile {
        WebhookProfile::GitHub => format!("uk_ghs_{}", short_hex(&seed[0..16])),
        WebhookProfile::Stripe => format!("whsec_{}", short_hex(&seed[0..16])),
        WebhookProfile::Slack => short_hex(&seed[0..16]),
    }
}

fn signed_headers(
    profile: WebhookProfile,
    timestamp: i64,
    payload: &str,
    secret: &str,
) -> (BTreeMap<String, String>, String) {
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    match profile {
        WebhookProfile::GitHub => {
            let signature_input = payload.to_string();
            let sig = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
            headers.insert("X-Hub-Signature-256".to_string(), format!("sha256={sig}"));
            (headers, signature_input)
        }
        WebhookProfile::Stripe => {
            let signature_input = format!("{timestamp}.{payload}");
            let sig = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
            headers.insert(
                "Stripe-Signature".to_string(),
                format!("t={timestamp},v1={sig}"),
            );
            (headers, signature_input)
        }
        WebhookProfile::Slack => {
            let signature_input = format!("v0:{timestamp}:{payload}");
            let sig = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
            headers.insert(
                "X-Slack-Request-Timestamp".to_string(),
                timestamp.to_string(),
            );
            headers.insert("X-Slack-Signature".to_string(), format!("v0={sig}"));
            (headers, signature_input)
        }
    }
}

fn hmac_sha256_hex(secret: &[u8], input: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC key setup");
    mac.update(input);
    let output = mac.finalize().into_bytes();
    short_hex(&output)
}

fn short_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    fn verify_github(fx: &WebhookFixture) -> bool {
        let Some(signature) = fx.headers.get("X-Hub-Signature-256") else {
            return false;
        };
        let expected = format!(
            "sha256={}",
            hmac_sha256_hex(fx.secret.as_bytes(), fx.payload.as_bytes())
        );
        &expected == signature
    }

    fn verify_stripe(fx: &WebhookFixture, tolerance_secs: i64, now: i64) -> bool {
        let Some(sig_header) = fx.headers.get("Stripe-Signature") else {
            return false;
        };

        let mut t = None;
        let mut v1 = None;
        for part in sig_header.split(',') {
            if let Some(val) = part.strip_prefix("t=") {
                t = val.parse::<i64>().ok();
            }
            if let Some(val) = part.strip_prefix("v1=") {
                v1 = Some(val);
            }
        }

        let (Some(ts), Some(sig)) = (t, v1) else {
            return false;
        };

        if now.saturating_sub(ts).abs() > tolerance_secs {
            return false;
        }

        let base = format!("{ts}.{}", fx.payload);
        hmac_sha256_hex(fx.secret.as_bytes(), base.as_bytes()) == sig
    }

    fn verify_slack(fx: &WebhookFixture, tolerance_secs: i64, now: i64) -> bool {
        let Some(ts_raw) = fx.headers.get("X-Slack-Request-Timestamp") else {
            return false;
        };
        let Ok(ts) = ts_raw.parse::<i64>() else {
            return false;
        };
        if now.saturating_sub(ts).abs() > tolerance_secs {
            return false;
        }

        let Some(sig) = fx.headers.get("X-Slack-Signature") else {
            return false;
        };
        let expected = format!(
            "v0={}",
            hmac_sha256_hex(
                fx.secret.as_bytes(),
                format!("v0:{ts}:{}", fx.payload).as_bytes()
            )
        );
        expected == *sig
    }

    #[test]
    fn deterministic_is_order_independent() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-det").expect("seed"));
        let a1 = fx.webhook_github("svc", WebhookPayloadSpec::basic());
        let _ignore = fx.webhook_slack("other", WebhookPayloadSpec::basic());
        let a2 = fx.webhook_github("svc", WebhookPayloadSpec::basic());
        assert_eq!(a1.secret, a2.secret);
        assert_eq!(a1.payload, a2.payload);
        assert_eq!(a1.headers, a2.headers);
    }

    #[test]
    fn github_signature_verifies() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-gh").expect("seed"));
        let fixture = fx.webhook_github("repo", WebhookPayloadSpec::basic());
        assert!(verify_github(&fixture));
        assert!(fixture.headers.contains_key("X-Hub-Signature-256"));
    }

    #[test]
    fn stripe_signature_verifies_and_has_shape() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-stripe").expect("seed"));
        let fixture = fx.webhook_stripe("billing", WebhookPayloadSpec::basic());
        assert!(verify_stripe(&fixture, 300, fixture.timestamp));
        assert!(fixture.headers.contains_key("Stripe-Signature"));
    }

    #[test]
    fn slack_signature_verifies_and_has_shape() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-slack").expect("seed"));
        let fixture = fx.webhook_slack("alerts", WebhookPayloadSpec::basic());
        assert!(verify_slack(&fixture, 300, fixture.timestamp));
        assert!(fixture.headers.contains_key("X-Slack-Signature"));
        assert!(fixture.headers.contains_key("X-Slack-Request-Timestamp"));
    }

    #[test]
    fn stale_timestamp_wrong_secret_and_tampered_payload_fail() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-neg").expect("seed"));
        let fixture = fx.webhook_stripe("billing", WebhookPayloadSpec::basic());

        let stale = fixture.near_miss_stale_timestamp(3600);
        assert_eq!(stale.kind, NearMissKind::StaleTimestamp);
        assert!(!verify_stripe(&stale.fixture, 300, fixture.timestamp));

        let wrong_secret = fixture.near_miss_wrong_secret();
        assert_eq!(wrong_secret.kind, NearMissKind::WrongSecret);
        assert!(!verify_stripe(
            &wrong_secret.fixture,
            300,
            wrong_secret.fixture.timestamp
        ));

        let tampered = fixture.near_miss_tampered_payload();
        assert_eq!(tampered.kind, NearMissKind::TamperedPayload);
        assert!(!verify_stripe(&tampered.fixture, 300, tampered.fixture.timestamp));
    }
}
