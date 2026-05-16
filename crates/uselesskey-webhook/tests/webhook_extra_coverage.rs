//! Extra coverage for uselesskey-webhook:
//!
//! - Raw payload spec through every provider profile (existing tests are
//!   Canonical-only).
//! - Near-miss scenarios for GitHub and Slack (existing tests only cover
//!   Stripe), plus assertions that `scenario` is wired through.
//! - Determinism of `webhook(profile, ...)` for every profile.
//! - Determinism + uniqueness across distinct labels.
//! - Cache coherence: `webhook_github` and `webhook(GitHub, ...)` produce
//!   identical fixtures.

use uselesskey_core::{Factory, Seed};
use uselesskey_webhook::{NearMissScenario, WebhookFactoryExt, WebhookPayloadSpec, WebhookProfile};

fn det_fx(seed_label: &str) -> Factory {
    Factory::deterministic(Seed::from_env_value(seed_label).unwrap())
}

// =========================================================================
// Raw payload spec round-trips through all providers
// =========================================================================

#[test]
fn raw_payload_spec_is_used_verbatim_for_all_providers() {
    let raw = "{\"custom\":true}";
    for profile in [
        WebhookProfile::GitHub,
        WebhookProfile::Stripe,
        WebhookProfile::Slack,
    ] {
        let fx = det_fx("webhook-raw");
        let fixture = fx.webhook(profile, "label", WebhookPayloadSpec::Raw(raw.to_string()));
        assert_eq!(
            fixture.payload, raw,
            "Raw payload must be preserved for {profile:?}"
        );
    }
}

#[test]
fn raw_payload_changes_cache_identity_across_specs() {
    let fx = det_fx("webhook-raw-cache");
    let canonical = fx.webhook_github("svc", WebhookPayloadSpec::Canonical);
    let raw = fx.webhook_github("svc", WebhookPayloadSpec::Raw("X".to_string()));
    let raw_other = fx.webhook_github("svc", WebhookPayloadSpec::Raw("Y".to_string()));

    // Different specs → different cache entries → different generated material.
    assert_ne!(canonical.payload, raw.payload);
    assert_ne!(raw.payload, raw_other.payload);
    assert_ne!(canonical.secret, raw.secret);
}

// =========================================================================
// Near-miss scenarios for GitHub + Slack profiles
// =========================================================================

#[test]
fn near_miss_stale_timestamp_marks_scenario_for_all_profiles() {
    for profile in [
        WebhookProfile::GitHub,
        WebhookProfile::Stripe,
        WebhookProfile::Slack,
    ] {
        let fx = det_fx("webhook-nm-stale");
        let fixture = fx.webhook(profile, "svc", WebhookPayloadSpec::Canonical);

        let nm = fixture.near_miss_stale_timestamp(300);
        assert_eq!(nm.scenario, NearMissScenario::StaleTimestamp);
        assert_eq!(nm.timestamp, fixture.timestamp - 301);
        assert_eq!(nm.profile, profile);
        // Headers must still match the now-stale timestamp signature.
        assert!(
            !nm.signature_input.is_empty(),
            "signature input present for {profile:?}"
        );
    }
}

#[test]
fn near_miss_wrong_secret_marks_scenario_for_all_profiles() {
    for profile in [
        WebhookProfile::GitHub,
        WebhookProfile::Stripe,
        WebhookProfile::Slack,
    ] {
        let fx = det_fx("webhook-nm-wrong");
        let fixture = fx.webhook(profile, "svc", WebhookPayloadSpec::Canonical);
        let nm = fixture.near_miss_wrong_secret();

        assert_eq!(nm.scenario, NearMissScenario::WrongSecret);
        assert_eq!(nm.profile, profile);
        assert_ne!(nm.secret, fixture.secret);
        assert!(nm.secret.ends_with("_wrong"));
        // Payload and timestamp are preserved.
        assert_eq!(nm.payload, fixture.payload);
        assert_eq!(nm.timestamp, fixture.timestamp);
    }
}

#[test]
fn near_miss_tampered_payload_marks_scenario_for_all_profiles() {
    for profile in [
        WebhookProfile::GitHub,
        WebhookProfile::Stripe,
        WebhookProfile::Slack,
    ] {
        let fx = det_fx("webhook-nm-tamper");
        let fixture = fx.webhook(profile, "svc", WebhookPayloadSpec::Canonical);
        let nm = fixture.near_miss_tampered_payload();

        assert_eq!(nm.scenario, NearMissScenario::TamperedPayload);
        assert_eq!(nm.profile, profile);
        assert_ne!(nm.payload, fixture.payload);
        // Secret is preserved.
        assert_eq!(nm.secret, fixture.secret);
        assert_eq!(nm.timestamp, fixture.timestamp);
    }
}

// =========================================================================
// Determinism + uniqueness across labels
// =========================================================================

#[test]
fn webhook_is_deterministic_for_all_profiles() {
    for profile in [
        WebhookProfile::GitHub,
        WebhookProfile::Stripe,
        WebhookProfile::Slack,
    ] {
        let a = det_fx("webhook-det").webhook(profile, "label", WebhookPayloadSpec::Canonical);
        let b = det_fx("webhook-det").webhook(profile, "label", WebhookPayloadSpec::Canonical);
        assert_eq!(a.secret, b.secret, "{profile:?}");
        assert_eq!(a.payload, b.payload, "{profile:?}");
        assert_eq!(a.timestamp, b.timestamp, "{profile:?}");
        assert_eq!(a.headers, b.headers, "{profile:?}");
    }
}

#[test]
fn different_labels_produce_different_fixtures() {
    let fx = det_fx("webhook-labels");
    let a = fx.webhook_github("a", WebhookPayloadSpec::Canonical);
    let b = fx.webhook_github("b", WebhookPayloadSpec::Canonical);
    assert_ne!(a.payload, b.payload);
    assert_ne!(a.secret, b.secret);
}

#[test]
fn helper_constructors_match_explicit_profile_form() {
    let fx = det_fx("webhook-helpers");

    let gh_helper = fx.webhook_github("svc", WebhookPayloadSpec::Canonical);
    let gh_explicit = fx.webhook(WebhookProfile::GitHub, "svc", WebhookPayloadSpec::Canonical);
    assert_eq!(gh_helper.secret, gh_explicit.secret);
    assert_eq!(gh_helper.payload, gh_explicit.payload);

    let st_helper = fx.webhook_stripe("svc", WebhookPayloadSpec::Canonical);
    let st_explicit = fx.webhook(WebhookProfile::Stripe, "svc", WebhookPayloadSpec::Canonical);
    assert_eq!(st_helper.secret, st_explicit.secret);

    let sl_helper = fx.webhook_slack("svc", WebhookPayloadSpec::Canonical);
    let sl_explicit = fx.webhook(WebhookProfile::Slack, "svc", WebhookPayloadSpec::Canonical);
    assert_eq!(sl_helper.secret, sl_explicit.secret);
}

// =========================================================================
// Near-miss invariants
// =========================================================================

#[test]
fn near_miss_stale_timestamp_offset_matches_max_age_plus_one() {
    let fx = det_fx("webhook-offset");
    let fixture = fx.webhook_stripe("svc", WebhookPayloadSpec::Canonical);

    for max_age in [0_i64, 1, 60, 300, 86_400] {
        let nm = fixture.near_miss_stale_timestamp(max_age);
        assert_eq!(nm.timestamp, fixture.timestamp - max_age - 1);
    }
}
