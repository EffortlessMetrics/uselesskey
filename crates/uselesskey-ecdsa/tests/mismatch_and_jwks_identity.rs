//! Coverage for the mismatched-public-key variant and JWKS identity.
//!
//! Existing tests in this crate already validate that
//! `mismatched_public_key_spki_der()` returns *some* parseable, different key
//! and that JWK fields look plausible. The cases below close a few specific
//! gaps that survive that net:
//!
//! - mismatch is deterministic across separate factories (P-256 only had this
//!   check; P-384 did not).
//! - repeated mismatch calls on the same fixture return identical bytes (the
//!   `"mismatch"` variant is cached, not regenerated each call).
//! - the mismatched key is on the *same* curve as the original (kills a
//!   theoretical "swap curve" mutant in the variant load path).
//! - distinct labels produce distinct mismatched keys (variant entropy
//!   actually flows through `label`).
//! - JWK x/y/d use base64url with no padding (`=`).
//! - the JWKS-embedded kid matches the standalone `kid()` for *both* curves
//!   (the existing mutation-hardening check only verified the public_jwk()
//!   kid, not the kid wrapped inside JWKS).
//! - `DOMAIN_ECDSA_KEYPAIR` is pinned to its current value so a rename trips
//!   CI rather than silently drifting downstream fixtures.

use uselesskey_core::Factory;
use uselesskey_ecdsa::{DOMAIN_ECDSA_KEYPAIR, EcdsaFactoryExt, EcdsaSpec};

// ---------------------------------------------------------------------------
// Mismatch determinism + caching
// ---------------------------------------------------------------------------

#[test]
fn mismatched_public_key_is_deterministic_across_factories_es256() {
    let fx1 = Factory::deterministic_from_str("ecdsa-mismatch-cross-256");
    let fx2 = Factory::deterministic_from_str("ecdsa-mismatch-cross-256");

    let a = fx1
        .ecdsa("issuer", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();
    let b = fx2
        .ecdsa("issuer", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();

    assert_eq!(
        a, b,
        "mismatched key bytes must be stable across separate factories"
    );
}

#[test]
fn mismatched_public_key_is_deterministic_across_factories_es384() {
    let fx1 = Factory::deterministic_from_str("ecdsa-mismatch-cross-384");
    let fx2 = Factory::deterministic_from_str("ecdsa-mismatch-cross-384");

    let a = fx1
        .ecdsa("issuer", EcdsaSpec::es384())
        .mismatched_public_key_spki_der();
    let b = fx2
        .ecdsa("issuer", EcdsaSpec::es384())
        .mismatched_public_key_spki_der();

    assert_eq!(a, b);
}

#[test]
fn repeated_mismatch_calls_return_identical_bytes() {
    // Random mode: even without a seed, the cache should keep the "mismatch"
    // variant stable across calls on the same fixture.
    let fx = Factory::random();
    let kp = fx.ecdsa("mismatch-repeat", EcdsaSpec::es256());

    let a = kp.mismatched_public_key_spki_der();
    let b = kp.mismatched_public_key_spki_der();

    assert_eq!(
        a, b,
        "the mismatch variant should be cached and stable on the same fixture"
    );
}

#[test]
fn distinct_labels_produce_distinct_mismatched_keys() {
    // The `"mismatch"` variant string is shared, so variation must come from
    // the label flowing through derivation.
    let fx = Factory::deterministic_from_str("ecdsa-mismatch-label-iso");

    let a = fx
        .ecdsa("alpha", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();
    let b = fx
        .ecdsa("beta", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();

    assert_ne!(
        a, b,
        "different labels must produce different mismatched keys"
    );
}

// ---------------------------------------------------------------------------
// Mismatched key stays on the same curve as the original
// ---------------------------------------------------------------------------

#[test]
fn mismatched_key_for_p256_parses_on_p256_curve() {
    use p256::pkcs8::DecodePublicKey as _;

    let fx = Factory::deterministic_from_str("ecdsa-mismatch-curve-256");
    let kp = fx.ecdsa("issuer", EcdsaSpec::es256());
    let mm = kp.mismatched_public_key_spki_der();

    let parsed = p256::PublicKey::from_public_key_der(&mm);
    assert!(parsed.is_ok(), "mismatched key must parse as a P-256 key");
}

#[test]
fn mismatched_key_for_p384_parses_on_p384_curve() {
    use p384::pkcs8::DecodePublicKey as _;

    let fx = Factory::deterministic_from_str("ecdsa-mismatch-curve-384");
    let kp = fx.ecdsa("issuer", EcdsaSpec::es384());
    let mm = kp.mismatched_public_key_spki_der();

    let parsed = p384::PublicKey::from_public_key_der(&mm);
    assert!(parsed.is_ok(), "mismatched key must parse as a P-384 key");
}

// ---------------------------------------------------------------------------
// JWK base64url shape: no padding characters
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
#[test]
fn jwk_coordinates_have_no_base64_padding() {
    let fx = Factory::deterministic_from_str("ecdsa-jwk-no-pad");

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let kp = fx.ecdsa("issuer", spec);

        let pub_jwk = kp.public_jwk().to_value();
        let priv_jwk = kp.private_key_jwk().to_value();

        let fields: [(&str, Option<&str>); 5] = [
            ("public x", pub_jwk["x"].as_str()),
            ("public y", pub_jwk["y"].as_str()),
            ("private x", priv_jwk["x"].as_str()),
            ("private y", priv_jwk["y"].as_str()),
            ("private d", priv_jwk["d"].as_str()),
        ];

        for (name, maybe_s) in fields {
            assert!(
                maybe_s.is_some(),
                "{name} should be a JSON string for {spec:?}"
            );
            let s = maybe_s.unwrap_or("");
            assert!(
                !s.contains('='),
                "{name} must use base64url no-pad for {spec:?}, got `{s}`"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// JWKS-embedded kid matches standalone kid for both curves
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
#[test]
fn jwks_embedded_kid_matches_standalone_kid_for_both_curves() {
    let fx = Factory::deterministic_from_str("ecdsa-jwks-kid");

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let kp = fx.ecdsa("issuer", spec);
        let jwks = kp.public_jwks().to_value();
        let keys_opt = jwks["keys"].as_array();
        assert!(
            keys_opt.is_some(),
            "JWKS keys must be an array for {spec:?}"
        );
        let keys = keys_opt.unwrap_or(&Vec::new()).clone();
        assert_eq!(keys.len(), 1, "JWKS should hold one key for {spec:?}");

        let embedded_kid_opt = keys[0]["kid"].as_str();
        assert!(
            embedded_kid_opt.is_some(),
            "JWKS entry kid must be a string for {spec:?}"
        );
        assert_eq!(
            embedded_kid_opt.unwrap_or(""),
            kp.kid(),
            "JWKS-embedded kid must match standalone kid for {spec:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// JWKS entry preserves use/alg/crv for P-384 specifically
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
#[test]
fn jwks_entry_preserves_use_alg_and_crv_for_p384() {
    let fx = Factory::deterministic_from_str("ecdsa-jwks-fields-384");
    let kp = fx.ecdsa("issuer", EcdsaSpec::es384());

    let jwks = kp.public_jwks().to_value();
    let entry = &jwks["keys"][0];

    assert_eq!(entry["kty"], "EC");
    assert_eq!(entry["use"], "sig");
    assert_eq!(entry["alg"], "ES384");
    assert_eq!(entry["crv"], "P-384");
    assert!(entry["x"].is_string());
    assert!(entry["y"].is_string());
    assert!(entry["d"].is_null(), "JWKS public entry must not expose d");
}

// ---------------------------------------------------------------------------
// Domain constant pin
// ---------------------------------------------------------------------------

#[test]
fn domain_ecdsa_keypair_constant_is_pinned() {
    // Changing this string changes derivation identity for every downstream
    // ECDSA fixture: it must only move with a deliberate derivation-version
    // bump in uselesskey-core.
    assert_eq!(DOMAIN_ECDSA_KEYPAIR, "uselesskey:ecdsa:keypair");
}
