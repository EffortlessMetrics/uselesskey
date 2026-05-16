//! Coverage for the mismatched-public-key variant and JWKS identity.
//!
//! Existing tests in this crate already validate that
//! `mismatched_public_key_spki_der()` returns some parseable, different key
//! and that JWK fields look plausible. The cases below close a few specific
//! behavioural gaps that survive that net:
//!
//! - The mismatch is deterministic across separate factories (not just
//!   stable within the same factory's cache).
//! - Repeated mismatch calls on the same fixture return identical bytes
//!   (the `"mismatch"` variant is cached, not regenerated per call).
//! - Distinct labels produce distinct mismatched keys (variant entropy
//!   actually flows through `label`; the variant string itself is shared).
//! - The mismatched SPKI parses as an RSA key (kills a hypothetical
//!   "swap key type" mutant in the variant load path).
//! - JWK `n`/`e`/`d` use base64url with **no padding** (`=`).
//! - The JWKS-embedded `kid` matches the standalone `kid()`.
//! - The JWKS public entry preserves `kty`/`use`/`alg` and omits `d`.
//! - `DOMAIN_RSA_KEYPAIR` is pinned to its current value so a rename trips
//!   CI rather than silently drifting downstream fixtures.
//!
//! Mirrors the structure of `uselesskey-ecdsa/tests/mismatch_and_jwks_identity.rs`
//! and the `<crate>_extra_coverage.rs` pattern used by `uselesskey-hmac`,
//! `uselesskey-ed25519`, `uselesskey-entropy`, and `uselesskey-jwk`.

use uselesskey_core::Factory;
use uselesskey_rsa::{DOMAIN_RSA_KEYPAIR, RsaFactoryExt, RsaSpec};

// ---------------------------------------------------------------------------
// Mismatch determinism + caching
// ---------------------------------------------------------------------------

#[test]
fn mismatched_public_key_is_deterministic_across_factories() {
    let fx1 = Factory::deterministic_from_str("rsa-mismatch-cross");
    let fx2 = Factory::deterministic_from_str("rsa-mismatch-cross");

    let a = fx1
        .rsa("issuer", RsaSpec::rs256())
        .mismatched_public_key_spki_der();
    let b = fx2
        .rsa("issuer", RsaSpec::rs256())
        .mismatched_public_key_spki_der();

    assert_eq!(
        a, b,
        "mismatched key bytes must be stable across separate factories"
    );
}

#[test]
fn repeated_mismatch_calls_return_identical_bytes() {
    // The cache should keep the "mismatch" variant stable across calls on
    // the same fixture even in random mode.
    let fx = Factory::random();
    let kp = fx.rsa("mismatch-repeat", RsaSpec::rs256());

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
    let fx = Factory::deterministic_from_str("rsa-mismatch-label-iso");

    let a = fx
        .rsa("alpha", RsaSpec::rs256())
        .mismatched_public_key_spki_der();
    let b = fx
        .rsa("beta", RsaSpec::rs256())
        .mismatched_public_key_spki_der();

    assert_ne!(
        a, b,
        "different labels must produce different mismatched keys"
    );
}

#[test]
fn mismatched_key_is_different_from_original_public_key() {
    let fx = Factory::deterministic_from_str("rsa-mismatch-vs-original");
    let kp = fx.rsa("issuer", RsaSpec::rs256());

    assert_ne!(
        kp.mismatched_public_key_spki_der(),
        kp.public_key_spki_der(),
        "mismatched public key must differ from the keypair's own public key"
    );
}

// ---------------------------------------------------------------------------
// Mismatched SPKI parses as an RSA key (kills "swap key type" mutants)
// ---------------------------------------------------------------------------

#[test]
fn mismatched_key_parses_as_rsa_spki() {
    use rsa::RsaPublicKey;
    use rsa::pkcs8::DecodePublicKey as _;

    let fx = Factory::deterministic_from_str("rsa-mismatch-parses");
    let kp = fx.rsa("issuer", RsaSpec::rs256());
    let mm = kp.mismatched_public_key_spki_der();

    let parsed = RsaPublicKey::from_public_key_der(&mm);
    assert!(parsed.is_ok(), "mismatched key must parse as an RSA SPKI");
}

// ---------------------------------------------------------------------------
// JWK base64url shape: no padding characters
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
#[test]
fn jwk_components_have_no_base64_padding() {
    let fx = Factory::deterministic_from_str("rsa-jwk-no-pad");
    let kp = fx.rsa("issuer", RsaSpec::rs256());

    let pub_jwk = kp.public_jwk().to_value();
    let priv_jwk = kp.private_key_jwk().to_value();

    let fields: [(&str, Option<&str>); 4] = [
        ("public n", pub_jwk["n"].as_str()),
        ("public e", pub_jwk["e"].as_str()),
        ("private n", priv_jwk["n"].as_str()),
        ("private d", priv_jwk["d"].as_str()),
    ];

    for (name, maybe_s) in fields {
        assert!(maybe_s.is_some(), "{name} should be a JSON string");
        let s = maybe_s.unwrap_or("");
        assert!(
            !s.contains('='),
            "{name} must use base64url no-pad, got `{s}`"
        );
    }
}

// ---------------------------------------------------------------------------
// JWKS-embedded kid matches standalone kid
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
#[test]
fn jwks_embedded_kid_matches_standalone_kid() {
    let fx = Factory::deterministic_from_str("rsa-jwks-kid");
    let kp = fx.rsa("issuer", RsaSpec::rs256());
    let jwks = kp.public_jwks().to_value();
    let keys_opt = jwks["keys"].as_array();
    assert!(keys_opt.is_some(), "JWKS keys must be an array");
    let keys = keys_opt.unwrap_or(&Vec::new()).clone();
    assert_eq!(keys.len(), 1, "JWKS should hold one key");

    let embedded_kid_opt = keys[0]["kid"].as_str();
    assert!(
        embedded_kid_opt.is_some(),
        "JWKS entry kid must be a string"
    );
    assert_eq!(
        embedded_kid_opt.unwrap_or(""),
        kp.kid(),
        "JWKS-embedded kid must match standalone kid"
    );
}

// ---------------------------------------------------------------------------
// JWKS public entry preserves kty/use/alg and omits d
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
#[test]
fn jwks_public_entry_preserves_metadata_and_omits_private_d() {
    let fx = Factory::deterministic_from_str("rsa-jwks-fields");
    let kp = fx.rsa("issuer", RsaSpec::rs256());

    let jwks = kp.public_jwks().to_value();
    let entry = &jwks["keys"][0];

    assert_eq!(entry["kty"], "RSA");
    assert_eq!(entry["use"], "sig");
    assert_eq!(entry["alg"], "RS256");
    assert!(entry["n"].is_string());
    assert!(entry["e"].is_string());
    assert!(entry["d"].is_null(), "JWKS public entry must not expose d");
}

// ---------------------------------------------------------------------------
// Domain constant pin
// ---------------------------------------------------------------------------

#[test]
fn domain_rsa_keypair_constant_is_pinned() {
    // Changing this string changes derivation identity for every downstream
    // RSA fixture: it must only move with a deliberate derivation-version
    // bump in uselesskey-core.
    assert_eq!(DOMAIN_RSA_KEYPAIR, "uselesskey:rsa:keypair");
}
