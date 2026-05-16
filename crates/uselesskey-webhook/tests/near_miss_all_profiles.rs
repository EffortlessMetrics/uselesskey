//! Cross-profile coverage for webhook near-miss variants and signature
//! round-trips.
//!
//! These tests live in an external integration target (rather than the inline
//! `#[cfg(test)] mod tests` in `lib.rs`) so they exercise the public surface
//! exactly as a downstream user would: `WebhookFactoryExt`, `WebhookFixture`,
//! and the `near_miss_*` helpers. Because `signature::hmac_sha256_hex` is
//! `pub(crate)` and intentionally not exported, this test reimplements the
//! same HMAC-SHA256 procedure locally (RFC 2104) using `sha2`, which is
//! already a regular dependency of the crate.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use uselesskey_core::Factory;
use uselesskey_webhook::{WebhookFactoryExt, WebhookFixture, WebhookPayloadSpec, WebhookProfile};

/// RFC 2104 HMAC-SHA256 returning a lowercase hex digest.
///
/// Mirrors the algorithm used internally by `uselesskey-webhook::signature`
/// so the test can independently recompute the expected signature for a
/// given (secret, message) pair.
fn hmac_sha256_hex(secret: &[u8], msg: &[u8]) -> String {
    const SHA256_BLOCK_LEN: usize = 64;

    let mut key_block = [0_u8; SHA256_BLOCK_LEN];
    if secret.len() > SHA256_BLOCK_LEN {
        let digest = Sha256::digest(secret);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut ipad = [0x36_u8; SHA256_BLOCK_LEN];
    let mut opad = [0x5c_u8; SHA256_BLOCK_LEN];
    for idx in 0..SHA256_BLOCK_LEN {
        ipad[idx] ^= key_block[idx];
        opad[idx] ^= key_block[idx];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    hex_encode(outer.finalize().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Pull the canonical hex signature out of the profile-specific header.
fn extract_signature(profile: WebhookProfile, headers: &BTreeMap<String, String>) -> String {
    match profile {
        WebhookProfile::GitHub => headers
            .get("X-Hub-Signature-256")
            .expect("github header present")
            .strip_prefix("sha256=")
            .expect("github header has sha256= prefix")
            .to_string(),
        WebhookProfile::Stripe => {
            let header = headers
                .get("Stripe-Signature")
                .expect("stripe header present");
            header
                .split(',')
                .find_map(|part| part.strip_prefix("v1=").map(str::to_string))
                .expect("stripe header has v1= component")
        }
        WebhookProfile::Slack => headers
            .get("X-Slack-Signature")
            .expect("slack header present")
            .strip_prefix("v0=")
            .expect("slack header has v0= prefix")
            .to_string(),
    }
}

/// Recompute the expected canonical signature (hex) for a fixture's
/// `(secret, payload, timestamp)` triple under its profile.
fn expected_signature(
    profile: WebhookProfile,
    secret: &str,
    payload: &str,
    timestamp: i64,
) -> String {
    let base = match profile {
        WebhookProfile::GitHub => payload.to_string(),
        WebhookProfile::Stripe => format!("{timestamp}.{payload}"),
        WebhookProfile::Slack => format!("v0:{timestamp}:{payload}"),
    };
    hmac_sha256_hex(secret.as_bytes(), base.as_bytes())
}

/// Sanity-check: the local HMAC implementation matches RFC 4231 test vector 1.
/// Guards against silently-wrong results from this test's reimplementation.
#[test]
fn local_hmac_sha256_matches_rfc4231_vector_1() {
    let key = [0x0b_u8; 20];
    let digest = hmac_sha256_hex(&key, b"Hi There");
    assert_eq!(
        digest,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

/// Coverage gap #1: `near_miss_wrong_secret` for the Stripe profile must
/// produce a fixture whose signature does NOT verify against the documented
/// (original) Stripe secret over the same payload+timestamp.
#[test]
fn stripe_near_miss_wrong_secret_diverges_from_canonical_signature() {
    let fx = Factory::deterministic_from_str("webhook-stripe-wrong-secret");
    let base = fx.webhook_stripe("billing", WebhookPayloadSpec::Canonical);
    let near_miss = base.near_miss_wrong_secret();

    // Recompute what the signature SHOULD have been if the canonical Stripe
    // secret had been used over the (unchanged) payload and timestamp.
    let canonical_sig = expected_signature(
        WebhookProfile::Stripe,
        &base.secret,
        &near_miss.payload,
        near_miss.timestamp,
    );

    let actual_sig = extract_signature(WebhookProfile::Stripe, &near_miss.headers);

    assert_ne!(
        actual_sig, canonical_sig,
        "wrong-secret near-miss must not collide with canonical-secret signature"
    );
    // And the near-miss fixture's own secret must differ from the canonical
    // one, otherwise the scenario is vacuous.
    assert_ne!(near_miss.secret, base.secret);
}

/// Coverage gap #2: `near_miss_tampered_payload` for the Stripe profile must
/// produce a fixture whose payload bytes differ from the canonical payload.
/// The signature in the fixture is over the tampered payload, so verifying it
/// against the canonical (signed-by-someone-else) payload would fail — but
/// the direct, scenario-defining property is that the payload bytes have
/// actually been mutated.
#[test]
fn stripe_near_miss_tampered_payload_bytes_differ_from_canonical() {
    let fx = Factory::deterministic_from_str("webhook-stripe-tampered");
    let base = fx.webhook_stripe("billing", WebhookPayloadSpec::Canonical);
    let near_miss = base.near_miss_tampered_payload();

    assert_ne!(
        near_miss.payload, base.payload,
        "tampered-payload near-miss must mutate the payload bytes"
    );

    // Cross-check: the canonical signature (over the *original* payload with
    // the canonical secret + timestamp) must not equal the tampered fixture's
    // signature, which is over the mutated payload.
    let canonical_sig = expected_signature(
        WebhookProfile::Stripe,
        &base.secret,
        &base.payload,
        near_miss.timestamp,
    );
    let tampered_sig = extract_signature(WebhookProfile::Stripe, &near_miss.headers);
    assert_ne!(
        canonical_sig, tampered_sig,
        "tampered payload must yield a different signature than the canonical payload"
    );
}

/// Coverage gap #3: For each profile, a valid `WebhookFixture` round-trips
/// cleanly — recomputing HMAC-SHA256 over the canonical signing base with the
/// fixture's own secret reproduces the signature in the fixture's headers.
#[test]
fn valid_fixture_signature_round_trips_for_all_profiles() {
    let fx = Factory::deterministic_from_str("webhook-roundtrip-all");

    for profile in [
        WebhookProfile::GitHub,
        WebhookProfile::Stripe,
        WebhookProfile::Slack,
    ] {
        let fixture: WebhookFixture =
            fx.webhook(profile, "round-trip-svc", WebhookPayloadSpec::Canonical);
        let recomputed = expected_signature(
            profile,
            &fixture.secret,
            &fixture.payload,
            fixture.timestamp,
        );
        let observed = extract_signature(profile, &fixture.headers);
        assert_eq!(
            recomputed, observed,
            "valid {profile:?} fixture must round-trip exactly under its own secret"
        );

        // The fixture's signature_input must also match the canonical signing
        // base — i.e. the bytes that were actually fed to HMAC.
        let expected_base = match profile {
            WebhookProfile::GitHub => fixture.payload.clone(),
            WebhookProfile::Stripe => format!("{}.{}", fixture.timestamp, fixture.payload),
            WebhookProfile::Slack => format!("v0:{}:{}", fixture.timestamp, fixture.payload),
        };
        assert_eq!(
            fixture.signature_input, expected_base,
            "{profile:?} signature_input must match its canonical signing base"
        );
    }
}

// Coverage gap #4 (`hmac_sha256_hex` block-length boundary) is intentionally
// skipped: `hmac_sha256_hex` is `pub(crate)` in `crates/uselesskey-webhook/src/signature.rs`
// and is not reachable from an external integration target. The instructions
// explicitly say to skip this gap rather than widen visibility for the test.
// The short/exact/long-key branches are already covered by the inline
// `#[cfg(test)]` tests in `lib.rs` (`hmac_sha256_preserves_block_sized_key_without_hashing`,
// `hmac_sha256_short_key_is_zero_padded`, and `hmac_sha256_long_key_is_hashed_first`).
