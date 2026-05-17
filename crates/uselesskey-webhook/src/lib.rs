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

    #[test]
    fn hmac_sha256_hashes_keys_larger_than_block_size() {
        let key = [0xaa_u8; 131];
        let digest = hmac_sha256_hex(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );

        assert_eq!(
            digest,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn raw_payload_is_used_verbatim_for_signature_inputs() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-raw-payload").unwrap());
        let raw = "{\"message\":\"keep exact spacing\", \"n\": 1}\n";

        let github = fx.webhook_github("raw", WebhookPayloadSpec::Raw(raw.to_string()));
        assert_eq!(github.payload, raw);
        assert_eq!(github.signature_input, raw);
        assert!(verify_github(&github.secret, raw, &github.headers));

        let stripe = fx.webhook_stripe("raw", WebhookPayloadSpec::Raw(raw.to_string()));
        assert_eq!(stripe.payload, raw);
        assert_eq!(
            stripe.signature_input,
            format!("{}.{}", stripe.timestamp, raw)
        );
        assert!(verify_stripe(
            &stripe.secret,
            raw,
            &stripe.headers,
            stripe.timestamp,
            300
        ));

        let slack = fx.webhook_slack("raw", WebhookPayloadSpec::Raw(raw.to_string()));
        assert_eq!(slack.payload, raw);
        assert_eq!(
            slack.signature_input,
            format!("v0:{}:{}", slack.timestamp, raw)
        );
        assert!(verify_slack(
            &slack.secret,
            raw,
            &slack.headers,
            slack.timestamp,
            300
        ));
    }

    #[test]
    fn fixture_cache_identity_includes_profile_label_and_payload_spec() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-cache-identity").unwrap());

        let github = fx.webhook_github("repo", WebhookPayloadSpec::Canonical);
        let github_again = fx.webhook_github("repo", WebhookPayloadSpec::Canonical);
        assert_eq!(github.secret, github_again.secret);
        assert_eq!(github.payload, github_again.payload);
        assert_eq!(github.headers, github_again.headers);

        let different_profile = fx.webhook_stripe("repo", WebhookPayloadSpec::Canonical);
        assert_ne!(github.secret, different_profile.secret);
        assert_ne!(github.payload, different_profile.payload);

        let different_label = fx.webhook_github("other-repo", WebhookPayloadSpec::Canonical);
        assert_ne!(github.secret, different_label.secret);
        assert_ne!(github.payload, different_label.payload);

        let different_raw = fx.webhook_github(
            "repo",
            WebhookPayloadSpec::Raw(r#"{"action":"opened"}"#.to_string()),
        );
        assert_ne!(github.secret, different_raw.secret);
        assert_eq!(different_raw.payload, r#"{"action":"opened"}"#);
    }

    #[test]
    fn near_miss_scenarios_are_marked_and_recomputed_for_each_profile() {
        let fx = Factory::deterministic(Seed::from_env_value("webhook-nearmiss-profiles").unwrap());
        let fixtures = [
            fx.webhook_github("repo", WebhookPayloadSpec::Canonical),
            fx.webhook_stripe("billing", WebhookPayloadSpec::Canonical),
            fx.webhook_slack("alerts", WebhookPayloadSpec::Canonical),
        ];

        for fixture in fixtures {
            let stale = fixture.near_miss_stale_timestamp(300);
            assert_eq!(stale.scenario, NearMissScenario::StaleTimestamp);
            assert_eq!(stale.profile, fixture.profile);
            assert_eq!(stale.payload, fixture.payload);
            assert_eq!(stale.timestamp, fixture.timestamp - 301);

            let wrong_secret = fixture.near_miss_wrong_secret();
            assert_eq!(wrong_secret.scenario, NearMissScenario::WrongSecret);
            assert_eq!(wrong_secret.profile, fixture.profile);
            assert_eq!(wrong_secret.payload, fixture.payload);
            assert_ne!(wrong_secret.secret, fixture.secret);
            assert!(wrong_secret.secret.ends_with("_wrong"));

            let tampered = fixture.near_miss_tampered_payload();
            assert_eq!(tampered.scenario, NearMissScenario::TamperedPayload);
            assert_eq!(tampered.profile, fixture.profile);
            assert_eq!(tampered.secret, fixture.secret);
            assert_eq!(tampered.payload, format!("{}\n", fixture.payload));

            match fixture.profile {
                WebhookProfile::GitHub => {
                    assert!(!verify_github(
                        &fixture.secret,
                        &wrong_secret.payload,
                        &wrong_secret.headers
                    ));
                    assert!(!verify_github(
                        &tampered.secret,
                        &fixture.payload,
                        &tampered.headers
                    ));
                }
                WebhookProfile::Stripe => {
                    assert!(!verify_stripe(
                        &fixture.secret,
                        &fixture.payload,
                        &stale.headers,
                        fixture.timestamp,
                        300
                    ));
                    assert!(!verify_stripe(
                        &fixture.secret,
                        &wrong_secret.payload,
                        &wrong_secret.headers,
                        wrong_secret.timestamp,
                        300
                    ));
                    assert!(!verify_stripe(
                        &tampered.secret,
                        &fixture.payload,
                        &tampered.headers,
                        tampered.timestamp,
                        300
                    ));
                }
                WebhookProfile::Slack => {
                    assert!(!verify_slack(
                        &fixture.secret,
                        &fixture.payload,
                        &stale.headers,
                        fixture.timestamp,
                        300
                    ));
                    assert!(!verify_slack(
                        &fixture.secret,
                        &wrong_secret.payload,
                        &wrong_secret.headers,
                        wrong_secret.timestamp,
                        300
                    ));
                    assert!(!verify_slack(
                        &tampered.secret,
                        &fixture.payload,
                        &tampered.headers,
                        tampered.timestamp,
                        300
                    ));
                }
            }
        }
    }

    fn assert_lower_hex(value: &str) {
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "expected lowercase hex: {value}"
        );
    }

    #[test]
    fn webhook_profile_stable_tag_is_unique_per_variant() {
        use crate::model::WebhookProfile;
        let tags = [
            WebhookProfile::GitHub.stable_tag(),
            WebhookProfile::Stripe.stable_tag(),
            WebhookProfile::Slack.stable_tag(),
        ];
        assert_eq!(tags, ["github", "stripe", "slack"]);

        let unique: std::collections::HashSet<&&str> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len(), "stable_tag values must be unique");
    }

    #[test]
    fn raw_payload_spec_is_returned_verbatim() {
        let fx = Factory::deterministic_from_str("webhook-raw-spec");
        let payload = "{\"custom\":\"shape\"}".to_string();
        let fixture = fx.webhook_github("raw-repo", WebhookPayloadSpec::Raw(payload.clone()));

        assert_eq!(fixture.payload, payload);
        assert!(verify_github(
            &fixture.secret,
            &fixture.payload,
            &fixture.headers
        ));
    }

    #[test]
    fn raw_payload_distinct_strings_yield_distinct_cache_identities() {
        let fx = Factory::deterministic_from_str("webhook-raw-cache");
        let one = fx.webhook_stripe("svc", WebhookPayloadSpec::Raw("one".to_string()));
        let two = fx.webhook_stripe("svc", WebhookPayloadSpec::Raw("two".to_string()));

        assert_ne!(one.payload, two.payload);
        assert_ne!(one.signature_input, two.signature_input);
        assert_ne!(
            one.headers.get("Stripe-Signature"),
            two.headers.get("Stripe-Signature")
        );
    }

    #[test]
    fn stale_timestamp_near_miss_works_for_all_profiles() {
        let fx = Factory::deterministic_from_str("webhook-stale-all");
        let max_age = 300_i64;

        for profile in [
            WebhookProfile::GitHub,
            WebhookProfile::Stripe,
            WebhookProfile::Slack,
        ] {
            let base = fx.webhook(profile, "svc", WebhookPayloadSpec::Canonical);
            let stale = base.near_miss_stale_timestamp(max_age);

            assert_eq!(stale.scenario, NearMissScenario::StaleTimestamp);
            assert_eq!(stale.timestamp, base.timestamp - max_age - 1);
            // GitHub does not include a timestamp in its signed input, so the
            // signature_input is just the payload; for Stripe/Slack the input
            // includes the (stale) timestamp.
            match profile {
                WebhookProfile::GitHub => {
                    assert_eq!(stale.signature_input, stale.payload);
                }
                WebhookProfile::Stripe => {
                    assert_eq!(
                        stale.signature_input,
                        format!("{}.{}", stale.timestamp, stale.payload)
                    );
                }
                WebhookProfile::Slack => {
                    assert_eq!(
                        stale.signature_input,
                        format!("v0:{}:{}", stale.timestamp, stale.payload)
                    );
                }
            }
        }
    }

    #[test]
    fn wrong_secret_near_miss_works_for_github_and_slack() {
        let fx = Factory::deterministic_from_str("webhook-wrong-secret");

        let gh = fx.webhook_github("svc", WebhookPayloadSpec::Canonical);
        let gh_wrong = gh.near_miss_wrong_secret();
        assert_eq!(gh_wrong.scenario, NearMissScenario::WrongSecret);
        assert_ne!(gh_wrong.secret, gh.secret);
        assert!(gh_wrong.secret.ends_with("_wrong"));
        assert!(!verify_github(
            &gh.secret,
            &gh_wrong.payload,
            &gh_wrong.headers
        ));

        let sl = fx.webhook_slack("svc", WebhookPayloadSpec::Canonical);
        let sl_wrong = sl.near_miss_wrong_secret();
        assert_eq!(sl_wrong.scenario, NearMissScenario::WrongSecret);
        assert_ne!(sl_wrong.secret, sl.secret);
        assert!(!verify_slack(
            &sl.secret,
            &sl_wrong.payload,
            &sl_wrong.headers,
            sl_wrong.timestamp,
            300
        ));
    }

    #[test]
    fn tampered_payload_near_miss_works_for_github_and_slack() {
        let fx = Factory::deterministic_from_str("webhook-tampered");

        let gh = fx.webhook_github("svc", WebhookPayloadSpec::Canonical);
        let gh_tampered = gh.near_miss_tampered_payload();
        assert_eq!(gh_tampered.scenario, NearMissScenario::TamperedPayload);
        assert_ne!(gh_tampered.payload, gh.payload);
        // The tampered fixture re-signs its own modified payload, so it
        // verifies against itself; verifying the *original* payload with the
        // tampered signature must fail.
        assert!(!verify_github(
            &gh.secret,
            &gh.payload,
            &gh_tampered.headers
        ));

        let sl = fx.webhook_slack("svc", WebhookPayloadSpec::Canonical);
        let sl_tampered = sl.near_miss_tampered_payload();
        assert_eq!(sl_tampered.scenario, NearMissScenario::TamperedPayload);
        assert_ne!(sl_tampered.payload, sl.payload);
        assert!(!verify_slack(
            &sl.secret,
            &sl.payload,
            &sl_tampered.headers,
            sl_tampered.timestamp,
            300
        ));
    }

    #[test]
    fn hmac_sha256_long_key_is_hashed_first() {
        // RFC 4231 test vector 4: 131-byte key (longer than the 64-byte block),
        // exercising the SHA-256 pre-hash branch of hmac_sha256_hex.
        let key = vec![0xaa_u8; 131];
        let digest = hmac_sha256_hex(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            digest,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_sha256_short_key_is_zero_padded() {
        // A short key should be zero-padded into the 64-byte block, not hashed.
        // This exercises the else-branch of hmac_sha256_hex with a sub-block-size key.
        let short = b"key";
        let padded = {
            let mut padded = [0_u8; 64];
            padded[..short.len()].copy_from_slice(short);
            padded.to_vec()
        };
        assert_eq!(
            hmac_sha256_hex(short, b"hello"),
            hmac_sha256_hex(&padded, b"hello"),
            "short key must zero-pad into the same block as the explicitly padded key"
        );
    }

    #[test]
    fn debug_redacts_secret_for_all_profiles() {
        let fx = Factory::deterministic_from_str("webhook-debug-all");

        for profile in [
            WebhookProfile::GitHub,
            WebhookProfile::Stripe,
            WebhookProfile::Slack,
        ] {
            let fixture = fx.webhook(profile, "svc", WebhookPayloadSpec::Canonical);
            let dbg = format!("{fixture:?}");
            assert!(dbg.contains("WebhookFixture"));
            assert!(
                !dbg.contains(&fixture.secret),
                "Debug for {profile:?} must not leak secret: {dbg}"
            );
        }
    }

    #[test]
    fn debug_redacts_secret_for_all_near_miss_scenarios() {
        let fx = Factory::deterministic_from_str("webhook-debug-nm");
        let base = fx.webhook_stripe("svc", WebhookPayloadSpec::Canonical);

        let scenarios = [
            base.near_miss_stale_timestamp(300),
            base.near_miss_wrong_secret(),
            base.near_miss_tampered_payload(),
        ];

        for fixture in scenarios {
            let dbg = format!("{fixture:?}");
            assert!(dbg.contains("NearMissWebhookFixture"));
            assert!(
                !dbg.contains(&fixture.secret),
                "Debug for {:?} must not leak secret: {dbg}",
                fixture.scenario
            );
        }
    }
}
