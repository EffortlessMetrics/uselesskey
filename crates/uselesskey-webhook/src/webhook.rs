use std::collections::BTreeMap;
use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uselesskey_core::{Factory, Seed};

pub const DOMAIN_WEBHOOK_FIXTURE: &str = "uselesskey:webhook:fixture";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WebhookProfile {
    GitHub,
    Stripe,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WebhookPayloadSpec {
    BasicEvent,
    NestedObject,
}

impl WebhookPayloadSpec {
    fn stable_tag(self) -> &'static str {
        match self {
            Self::BasicEvent => "basic_event",
            Self::NestedObject => "nested_object",
        }
    }

    fn render(self, profile: WebhookProfile, label: &str, seed: &Seed) -> String {
        let event_id = derive_hex(seed, "event_id", 12);
        let object_id = derive_hex(seed, "object_id", 8);
        match (profile, self) {
            (WebhookProfile::GitHub, WebhookPayloadSpec::BasicEvent) => format!(
                "{{\"action\":\"opened\",\"repository\":{{\"full_name\":\"{label}/repo\"}},\"installation\":{{\"id\":\"{event_id}\"}}}}"
            ),
            (WebhookProfile::GitHub, WebhookPayloadSpec::NestedObject) => format!(
                "{{\"action\":\"synchronize\",\"pull_request\":{{\"id\":\"{event_id}\",\"head\":{{\"sha\":\"{object_id}\"}}}},\"repository\":{{\"full_name\":\"{label}/repo\"}}}}"
            ),
            (WebhookProfile::Stripe, WebhookPayloadSpec::BasicEvent) => format!(
                "{{\"id\":\"evt_{event_id}\",\"type\":\"payment_intent.succeeded\",\"data\":{{\"object\":{{\"id\":\"pi_{object_id}\",\"status\":\"succeeded\"}}}}}}"
            ),
            (WebhookProfile::Stripe, WebhookPayloadSpec::NestedObject) => format!(
                "{{\"id\":\"evt_{event_id}\",\"type\":\"invoice.paid\",\"data\":{{\"object\":{{\"id\":\"in_{object_id}\",\"lines\":{{\"has_more\":false}}}}}}}}"
            ),
            (WebhookProfile::Slack, WebhookPayloadSpec::BasicEvent) => format!(
                "{{\"type\":\"event_callback\",\"team_id\":\"T{object_id}\",\"event\":{{\"type\":\"app_mention\",\"text\":\"hello {label}\"}},\"event_id\":\"Ev{event_id}\"}}"
            ),
            (WebhookProfile::Slack, WebhookPayloadSpec::NestedObject) => format!(
                "{{\"type\":\"event_callback\",\"api_app_id\":\"A{object_id}\",\"event\":{{\"type\":\"reaction_added\",\"reaction\":\"thumbsup\"}},\"event_id\":\"Ev{event_id}\"}}"
            ),
        }
    }
}

#[derive(Clone)]
pub struct WebhookFixture {
    pub profile: WebhookProfile,
    pub secret: String,
    pub payload: String,
    pub headers: BTreeMap<String, String>,
    pub timestamp: i64,
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

#[derive(Clone, Debug)]
pub struct NearMissWebhookFixture {
    pub stale_timestamp: WebhookFixture,
    pub wrong_secret: WebhookFixture,
    pub tampered_payload: WebhookFixture,
}

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

    fn webhook_near_miss(
        &self,
        label: impl AsRef<str>,
        profile: WebhookProfile,
        payload_spec: WebhookPayloadSpec,
    ) -> NearMissWebhookFixture;
}

impl WebhookFactoryExt for Factory {
    fn webhook(
        &self,
        label: impl AsRef<str>,
        profile: WebhookProfile,
        payload_spec: WebhookPayloadSpec,
    ) -> WebhookFixture {
        let label = label.as_ref();
        let spec = stable_bytes(profile, payload_spec);
        let inner = self.get_or_init(DOMAIN_WEBHOOK_FIXTURE, label, &spec, "good", |seed| {
            build_fixture(profile, payload_spec, label, &seed)
        });
        (*inner).clone()
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

    fn webhook_near_miss(
        &self,
        label: impl AsRef<str>,
        profile: WebhookProfile,
        payload_spec: WebhookPayloadSpec,
    ) -> NearMissWebhookFixture {
        let good = self.webhook(label, profile, payload_spec);
        NearMissWebhookFixture {
            stale_timestamp: stale_timestamp_variant(&good),
            wrong_secret: wrong_secret_variant(&good),
            tampered_payload: tampered_payload_variant(&good),
        }
    }
}

fn stable_bytes(profile: WebhookProfile, payload_spec: WebhookPayloadSpec) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(profile.stable_tag().as_bytes());
    out.push(0);
    out.extend_from_slice(payload_spec.stable_tag().as_bytes());
    out
}

fn build_fixture(
    profile: WebhookProfile,
    payload_spec: WebhookPayloadSpec,
    label: &str,
    seed: &Seed,
) -> WebhookFixture {
    let payload = payload_spec.render(profile, label, seed);
    let timestamp = 1_700_000_000_i64 + i64::from(derive_u16(seed, "timestamp"));
    let secret = match profile {
        WebhookProfile::GitHub => format!("ghs_{}", derive_hex(seed, "secret", 32)),
        WebhookProfile::Stripe => format!("whsec_{}", derive_hex(seed, "secret", 32)),
        WebhookProfile::Slack => derive_hex(seed, "secret", 32),
    };

    let (signature_input, headers) = sign(profile, &secret, &payload, timestamp);

    WebhookFixture {
        profile,
        secret,
        payload,
        headers,
        timestamp,
        signature_input,
    }
}

fn sign(
    profile: WebhookProfile,
    secret: &str,
    payload: &str,
    timestamp: i64,
) -> (String, BTreeMap<String, String>) {
    let signature_input = match profile {
        WebhookProfile::GitHub => payload.to_owned(),
        WebhookProfile::Stripe => format!("{timestamp}.{payload}"),
        WebhookProfile::Slack => format!("v0:{timestamp}:{payload}"),
    };

    let sig_hex = hmac_sha256_hex(secret.as_bytes(), signature_input.as_bytes());
    let mut headers = BTreeMap::new();

    match profile {
        WebhookProfile::GitHub => {
            headers.insert("X-Hub-Signature-256".to_owned(), format!("sha256={sig_hex}"));
        }
        WebhookProfile::Stripe => {
            headers.insert(
                "Stripe-Signature".to_owned(),
                format!("t={timestamp},v1={sig_hex}"),
            );
        }
        WebhookProfile::Slack => {
            headers.insert(
                "X-Slack-Request-Timestamp".to_owned(),
                timestamp.to_string(),
            );
            headers.insert("X-Slack-Signature".to_owned(), format!("v0={sig_hex}"));
        }
    }

    (signature_input, headers)
}

fn hmac_sha256_hex(key: &[u8], input: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(input);
    hex::encode(mac.finalize().into_bytes())
}

fn derive_digest(seed: &Seed, tag: &str) -> [u8; 32] {
    let digest = blake3::keyed_hash(seed.bytes(), tag.as_bytes());
    *digest.as_bytes()
}

fn derive_hex(seed: &Seed, tag: &str, hex_len: usize) -> String {
    let digest = derive_digest(seed, tag);
    hex::encode(digest)[..hex_len].to_owned()
}

fn derive_u16(seed: &Seed, tag: &str) -> u16 {
    let digest = derive_digest(seed, tag);
    u16::from_le_bytes([digest[0], digest[1]])
}

fn stale_timestamp_variant(good: &WebhookFixture) -> WebhookFixture {
    let stale = good.timestamp - 86_400;
    let (signature_input, headers) = sign(good.profile, &good.secret, &good.payload, stale);
    WebhookFixture {
        timestamp: stale,
        signature_input,
        headers,
        ..good.clone()
    }
}

fn wrong_secret_variant(good: &WebhookFixture) -> WebhookFixture {
    let wrong_secret = format!("{}_wrong", good.secret);
    let (signature_input, headers) = sign(
        good.profile,
        &wrong_secret,
        &good.payload,
        good.timestamp,
    );
    WebhookFixture {
        secret: wrong_secret,
        signature_input,
        headers,
        ..good.clone()
    }
}

fn tampered_payload_variant(good: &WebhookFixture) -> WebhookFixture {
    let tampered_payload = format!("{}{}", good.payload, "\n");
    let (signature_input, headers) = sign(good.profile, &good.secret, &tampered_payload, good.timestamp);
    WebhookFixture {
        payload: tampered_payload,
        signature_input,
        headers,
        ..good.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::{Factory, Seed};

    fn verify_github(secret: &str, payload: &str, headers: &BTreeMap<String, String>) -> bool {
        let expected = format!("sha256={}", hmac_sha256_hex(secret.as_bytes(), payload.as_bytes()));
        headers
            .get("X-Hub-Signature-256")
            .is_some_and(|actual| actual == &expected)
    }

    fn verify_stripe(
        secret: &str,
        payload: &str,
        headers: &BTreeMap<String, String>,
    ) -> bool {
        let Some(sig_header) = headers.get("Stripe-Signature") else {
            return false;
        };
        let mut ts = None;
        let mut v1 = None;
        for part in sig_header.split(',') {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("t"), Some(v)) => ts = Some(v),
                (Some("v1"), Some(v)) => v1 = Some(v),
                _ => {}
            }
        }
        let Some(ts) = ts else { return false };
        let Some(v1) = v1 else { return false };
        let signed = format!("{ts}.{payload}");
        v1 == hmac_sha256_hex(secret.as_bytes(), signed.as_bytes())
    }

    fn verify_slack(secret: &str, payload: &str, headers: &BTreeMap<String, String>) -> bool {
        let Some(ts) = headers.get("X-Slack-Request-Timestamp") else {
            return false;
        };
        let Some(sig) = headers.get("X-Slack-Signature") else {
            return false;
        };
        let signed = format!("v0:{ts}:{payload}");
        let expected = format!("v0={}", hmac_sha256_hex(secret.as_bytes(), signed.as_bytes()));
        sig == &expected
    }

    #[test]
    fn deterministic_fixture_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-det").expect("seed"));
        let a = fx.webhook_github("svc", WebhookPayloadSpec::BasicEvent);
        let b = fx.webhook_github("svc", WebhookPayloadSpec::BasicEvent);
        assert_eq!(a.secret, b.secret);
        assert_eq!(a.payload, b.payload);
        assert_eq!(a.headers, b.headers);
    }

    #[test]
    fn provider_verifiers_accept_positive_fixtures() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-positive").expect("seed"));

        let gh = fx.webhook_github("svc-gh", WebhookPayloadSpec::BasicEvent);
        assert!(verify_github(&gh.secret, &gh.payload, &gh.headers));

        let stripe = fx.webhook_stripe("svc-stripe", WebhookPayloadSpec::NestedObject);
        assert!(verify_stripe(&stripe.secret, &stripe.payload, &stripe.headers));

        let slack = fx.webhook_slack("svc-slack", WebhookPayloadSpec::BasicEvent);
        assert!(verify_slack(&slack.secret, &slack.payload, &slack.headers));
    }

    #[test]
    fn header_shape_is_provider_specific() {
        let fx = Factory::random();

        let gh = fx.webhook_github("shape-gh", WebhookPayloadSpec::BasicEvent);
        assert!(gh.headers.contains_key("X-Hub-Signature-256"));

        let stripe = fx.webhook_stripe("shape-stripe", WebhookPayloadSpec::BasicEvent);
        assert!(stripe.headers.contains_key("Stripe-Signature"));

        let slack = fx.webhook_slack("shape-slack", WebhookPayloadSpec::BasicEvent);
        assert!(slack.headers.contains_key("X-Slack-Signature"));
        assert!(slack.headers.contains_key("X-Slack-Request-Timestamp"));
    }

    #[test]
    fn near_miss_negatives_fail_verifier_paths() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-negative").expect("seed"));

        let near = fx.webhook_near_miss(
            "svc-stripe",
            WebhookProfile::Stripe,
            WebhookPayloadSpec::BasicEvent,
        );

        let stale = &near.stale_timestamp;
        assert!(stale.timestamp < fx.webhook_stripe("svc-stripe", WebhookPayloadSpec::BasicEvent).timestamp);

        let good = fx.webhook_stripe("svc-stripe", WebhookPayloadSpec::BasicEvent);
        assert!(!verify_stripe(&good.secret, &good.payload, &near.wrong_secret.headers));
        assert!(!verify_stripe(&good.secret, &good.payload, &near.tampered_payload.headers));
    }
}
