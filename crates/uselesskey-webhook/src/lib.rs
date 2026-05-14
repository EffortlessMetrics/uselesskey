#![forbid(unsafe_code)]

//! Webhook fixtures built on `uselesskey-core`.
//!
//! This crate provides deterministic provider-style webhook fixtures with canonical
//! payloads, signature input strings, and signed headers.

mod fixture;
mod model;
mod payload;
mod secret;
mod signature;

pub use fixture::WebhookFactoryExt;
pub use model::{
    NearMissScenario, NearMissWebhookFixture, WebhookFixture, WebhookPayloadSpec, WebhookProfile,
};

/// Cache domain for webhook fixtures.
pub const DOMAIN_WEBHOOK_FIXTURE: &str = "uselesskey:webhook:fixture";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::fixture::build_fixture_from_seed;
    use crate::payload::{canonical_payload, stable_spec_bytes};
    use crate::secret::build_secret;
    use crate::signature::hmac_sha256_hex;
    use rand_chacha10::ChaCha20Rng;
    use rand_core10::{Rng, SeedableRng};
    use uselesskey_core::{Factory, Seed};

    #[test]
    fn hmac_sha256_matches_rfc4231_test_vector() {
        let key = [0x0b_u8; 20];
        let digest = hmac_sha256_hex(&key, b"Hi There");

        assert_eq!(
            digest,
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn hmac_sha256_preserves_block_sized_key_without_hashing() {
        let key = [0xaa_u8; 64];
        let digest = hmac_sha256_hex(&key, b"block-size boundary");

        assert_eq!(
            digest,
            "4bf714ba9df6b88605adb3e0a8a8b6d0320041fc2577408eaeb6e7120a03cf43"
        );
    }

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
    fn payload_spec_stable_bytes_are_shape_sensitive() {
        assert_eq!(WebhookPayloadSpec::Canonical.stable_bytes(), b"canonical");
        assert_eq!(
            WebhookPayloadSpec::Raw("one".to_string()).stable_bytes(),
            b"raw:one"
        );
        assert_ne!(
            WebhookPayloadSpec::Raw("one".to_string()).stable_bytes(),
            WebhookPayloadSpec::Raw("two".to_string()).stable_bytes()
        );
        assert_ne!(
            stable_spec_bytes(WebhookProfile::GitHub, &WebhookPayloadSpec::Canonical),
            stable_spec_bytes(WebhookProfile::Stripe, &WebhookPayloadSpec::Canonical)
        );
    }

    #[test]
    fn generated_timestamp_uses_expected_seeded_window() {
        let seed = [7_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut secret_bytes = [0_u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let expected = 1_700_000_000_i64 + (rng.next_u32() as i64 % 200_000_000_i64);

        let fixture = build_fixture_from_seed(
            WebhookProfile::Stripe,
            "billing",
            WebhookPayloadSpec::Canonical,
            &seed,
        );

        assert_eq!(fixture.timestamp, expected);
        assert!((1_700_000_000..1_900_000_000).contains(&fixture.timestamp));
    }

    #[test]
    fn generated_secrets_match_provider_shapes() {
        let mut rng = ChaCha20Rng::from_seed([9_u8; 32]);
        let github = build_secret(WebhookProfile::GitHub, &mut rng);
        let stripe = build_secret(WebhookProfile::Stripe, &mut rng);
        let slack = build_secret(WebhookProfile::Slack, &mut rng);

        assert_eq!(github.len(), "ghs_".len() + 43);
        assert!(github.starts_with("ghs_"));
        assert!(
            github["ghs_".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );

        assert_eq!(stripe.len(), "whsec_".len() + 64);
        assert!(stripe.starts_with("whsec_"));
        assert_lower_hex(&stripe["whsec_".len()..]);

        assert_eq!(slack.len(), 64);
        assert_lower_hex(&slack);
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
        assert_eq!(stale.timestamp, st.timestamp - 301);
        assert_eq!(
            stale.signature_input,
            format!("{}.{}", stale.timestamp, stale.payload)
        );
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

    #[test]
    fn canonical_payload_preserves_plain_label_field_order() {
        assert_eq!(
            canonical_payload(
                WebhookProfile::GitHub,
                "repo",
                WebhookPayloadSpec::Canonical,
                12
            ),
            "{\"action\":\"opened\",\"repository\":{\"full_name\":\"acme/repo\"},\"number\":1012}"
        );
        assert_eq!(
            canonical_payload(
                WebhookProfile::Stripe,
                "billing",
                WebhookPayloadSpec::Canonical,
                0x0f
            ),
            "{\"id\":\"evt_0000000f\",\"type\":\"checkout.session.completed\",\"data\":{\"object\":{\"metadata\":{\"label\":\"billing\"}}}}"
        );
        assert_eq!(
            canonical_payload(
                WebhookProfile::Slack,
                "alerts",
                WebhookPayloadSpec::Canonical,
                0x10
            ),
            "{\"type\":\"event_callback\",\"team_id\":\"T00000010\",\"event\":{\"type\":\"app_mention\",\"text\":\"ping alerts\"}}"
        );
    }

    fn assert_lower_hex(value: &str) {
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "expected lowercase hex: {value}"
        );
    }
}
