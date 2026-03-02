//! KID (Key ID) stability and uniqueness regression tests.
//!
//! Validates that deterministic key IDs are stable, unique, correctly
//! formatted, and consistent across key types and factory instances.

use std::collections::HashSet;

use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

fn factory_from_env(seed_str: &str) -> Factory {
    Factory::deterministic(Seed::from_env_value(seed_str).unwrap())
}

/// Verify that a KID string is valid base64url with no padding,
/// 16 characters long, and contains only URL-safe characters.
fn assert_kid_format(kid: &str, context: &str) {
    assert_eq!(
        kid.len(),
        16,
        "{context}: KID length should be 16, got {} for '{kid}'",
        kid.len()
    );

    for ch in kid.chars() {
        assert!(
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
            "{context}: KID contains non-URL-safe character '{ch}' in '{kid}'"
        );
    }
}

// ---------------------------------------------------------------------------
// 1. KID Stability: same seed + label + spec → same KID
// ---------------------------------------------------------------------------

#[test]
fn kid_stability_rsa_same_factory() {
    let fx = factory_from_env("kid-stability-seed");
    let kid1 = fx.rsa("issuer", RsaSpec::rs256()).kid();
    let kid2 = fx.rsa("issuer", RsaSpec::rs256()).kid();
    assert_eq!(
        kid1, kid2,
        "Same factory, same inputs must produce same KID"
    );
}

#[test]
fn kid_stability_rsa_separate_factories() {
    let kid1 = factory_from_env("kid-stability-seed")
        .rsa("issuer", RsaSpec::rs256())
        .kid();
    let kid2 = factory_from_env("kid-stability-seed")
        .rsa("issuer", RsaSpec::rs256())
        .kid();
    assert_eq!(
        kid1, kid2,
        "Separate factories with same seed must produce same KID"
    );
}

#[test]
fn kid_stability_ecdsa() {
    let fx = factory_from_env("kid-stability-seed");
    let kid1 = fx.ecdsa("svc", EcdsaSpec::es256()).kid();
    let kid2 = fx.ecdsa("svc", EcdsaSpec::es256()).kid();
    assert_eq!(kid1, kid2);
}

#[test]
fn kid_stability_ed25519() {
    let fx = factory_from_env("kid-stability-seed");
    let kid1 = fx.ed25519("svc", Ed25519Spec::new()).kid();
    let kid2 = fx.ed25519("svc", Ed25519Spec::new()).kid();
    assert_eq!(kid1, kid2);
}

#[test]
fn kid_stability_hmac() {
    let fx = factory_from_env("kid-stability-seed");
    let kid1 = fx.hmac("svc", HmacSpec::hs256()).kid();
    let kid2 = fx.hmac("svc", HmacSpec::hs256()).kid();
    assert_eq!(kid1, kid2);
}

// ---------------------------------------------------------------------------
// 2. KID Uniqueness: different seeds/labels/specs → different KIDs
// ---------------------------------------------------------------------------

#[test]
fn kid_uniqueness_different_seeds() {
    let kid_a = factory_from_env("seed-alpha")
        .rsa("svc", RsaSpec::rs256())
        .kid();
    let kid_b = factory_from_env("seed-bravo")
        .rsa("svc", RsaSpec::rs256())
        .kid();
    assert_ne!(kid_a, kid_b, "Different seeds must produce different KIDs");
}

#[test]
fn kid_uniqueness_different_labels() {
    let fx = factory_from_env("kid-unique-labels");
    let kid_a = fx.rsa("label-alpha", RsaSpec::rs256()).kid();
    let kid_b = fx.rsa("label-bravo", RsaSpec::rs256()).kid();
    assert_ne!(kid_a, kid_b, "Different labels must produce different KIDs");
}

#[test]
fn kid_uniqueness_different_specs_rsa() {
    let fx = factory_from_env("kid-unique-specs");
    let kid_2048 = fx.rsa("svc", RsaSpec::rs256()).kid();
    let kid_4096 = fx.rsa("svc", RsaSpec::new(4096)).kid();
    assert_ne!(
        kid_2048, kid_4096,
        "Different RSA bit sizes must produce different KIDs"
    );
}

#[test]
fn kid_uniqueness_different_specs_ecdsa() {
    let fx = factory_from_env("kid-unique-specs");
    let kid_256 = fx.ecdsa("svc", EcdsaSpec::es256()).kid();
    let kid_384 = fx.ecdsa("svc", EcdsaSpec::es384()).kid();
    assert_ne!(
        kid_256, kid_384,
        "Different ECDSA curves must produce different KIDs"
    );
}

#[test]
fn kid_uniqueness_different_specs_hmac() {
    let fx = factory_from_env("kid-unique-specs");
    let kid_256 = fx.hmac("svc", HmacSpec::hs256()).kid();
    let kid_384 = fx.hmac("svc", HmacSpec::hs384()).kid();
    let kid_512 = fx.hmac("svc", HmacSpec::hs512()).kid();
    assert_ne!(kid_256, kid_384);
    assert_ne!(kid_256, kid_512);
    assert_ne!(kid_384, kid_512);
}

// ---------------------------------------------------------------------------
// 3. KID Format: base64url, 16 characters, URL-safe
// ---------------------------------------------------------------------------

#[test]
fn kid_format_rsa() {
    let fx = factory_from_env("kid-format");
    assert_kid_format(&fx.rsa("svc", RsaSpec::rs256()).kid(), "RSA rs256");
    assert_kid_format(&fx.rsa("svc", RsaSpec::new(4096)).kid(), "RSA 4096");
}

#[test]
fn kid_format_ecdsa() {
    let fx = factory_from_env("kid-format");
    assert_kid_format(&fx.ecdsa("svc", EcdsaSpec::es256()).kid(), "ECDSA es256");
    assert_kid_format(&fx.ecdsa("svc", EcdsaSpec::es384()).kid(), "ECDSA es384");
}

#[test]
fn kid_format_ed25519() {
    let fx = factory_from_env("kid-format");
    assert_kid_format(&fx.ed25519("svc", Ed25519Spec::new()).kid(), "Ed25519");
}

#[test]
fn kid_format_hmac() {
    let fx = factory_from_env("kid-format");
    assert_kid_format(&fx.hmac("svc", HmacSpec::hs256()).kid(), "HMAC hs256");
    assert_kid_format(&fx.hmac("svc", HmacSpec::hs384()).kid(), "HMAC hs384");
    assert_kid_format(&fx.hmac("svc", HmacSpec::hs512()).kid(), "HMAC hs512");
}

// ---------------------------------------------------------------------------
// 4. KID Independence: adding fixtures doesn't change existing KIDs
// ---------------------------------------------------------------------------

#[test]
fn kid_independence_rsa_unaffected_by_other_fixtures() {
    // Generate RSA KID alone
    let fx1 = factory_from_env("kid-independence");
    let kid_alone = fx1.rsa("target", RsaSpec::rs256()).kid();

    // Generate RSA KID after generating many other fixtures
    let fx2 = factory_from_env("kid-independence");
    let _noise_ec = fx2.ecdsa("noise1", EcdsaSpec::es256());
    let _noise_ed = fx2.ed25519("noise2", Ed25519Spec::new());
    let _noise_hmac = fx2.hmac("noise3", HmacSpec::hs512());
    let _noise_rsa = fx2.rsa("noise4", RsaSpec::new(4096));
    let kid_with_noise = fx2.rsa("target", RsaSpec::rs256()).kid();

    assert_eq!(
        kid_alone, kid_with_noise,
        "KID must not change when other fixtures are generated first"
    );
}

#[test]
fn kid_independence_ecdsa_unaffected_by_other_fixtures() {
    let fx1 = factory_from_env("kid-independence");
    let kid_alone = fx1.ecdsa("target", EcdsaSpec::es256()).kid();

    let fx2 = factory_from_env("kid-independence");
    let _noise = fx2.rsa("noise", RsaSpec::rs256());
    let _noise2 = fx2.hmac("noise2", HmacSpec::hs256());
    let kid_with_noise = fx2.ecdsa("target", EcdsaSpec::es256()).kid();

    assert_eq!(kid_alone, kid_with_noise);
}

#[test]
fn kid_independence_ed25519_unaffected_by_other_fixtures() {
    let fx1 = factory_from_env("kid-independence");
    let kid_alone = fx1.ed25519("target", Ed25519Spec::new()).kid();

    let fx2 = factory_from_env("kid-independence");
    let _noise = fx2.rsa("noise", RsaSpec::rs256());
    let _noise2 = fx2.ecdsa("noise2", EcdsaSpec::es384());
    let kid_with_noise = fx2.ed25519("target", Ed25519Spec::new()).kid();

    assert_eq!(kid_alone, kid_with_noise);
}

#[test]
fn kid_independence_hmac_unaffected_by_other_fixtures() {
    let fx1 = factory_from_env("kid-independence");
    let kid_alone = fx1.hmac("target", HmacSpec::hs256()).kid();

    let fx2 = factory_from_env("kid-independence");
    let _noise = fx2.rsa("noise", RsaSpec::rs256());
    let _noise2 = fx2.ed25519("noise2", Ed25519Spec::new());
    let kid_with_noise = fx2.hmac("target", HmacSpec::hs256()).kid();

    assert_eq!(kid_alone, kid_with_noise);
}

#[test]
fn kid_independence_generation_order_does_not_matter() {
    // Order A: RSA then ECDSA then Ed25519
    let fx_a = factory_from_env("kid-order");
    let rsa_kid_a = fx_a.rsa("svc", RsaSpec::rs256()).kid();
    let ec_kid_a = fx_a.ecdsa("svc", EcdsaSpec::es256()).kid();
    let ed_kid_a = fx_a.ed25519("svc", Ed25519Spec::new()).kid();

    // Order B: Ed25519 then ECDSA then RSA
    let fx_b = factory_from_env("kid-order");
    let ed_kid_b = fx_b.ed25519("svc", Ed25519Spec::new()).kid();
    let ec_kid_b = fx_b.ecdsa("svc", EcdsaSpec::es256()).kid();
    let rsa_kid_b = fx_b.rsa("svc", RsaSpec::rs256()).kid();

    assert_eq!(rsa_kid_a, rsa_kid_b, "RSA KID must be order-independent");
    assert_eq!(ec_kid_a, ec_kid_b, "ECDSA KID must be order-independent");
    assert_eq!(ed_kid_a, ed_kid_b, "Ed25519 KID must be order-independent");
}

// ---------------------------------------------------------------------------
// 5. KID Collisions: generate many KIDs and verify no collisions
// ---------------------------------------------------------------------------

#[test]
fn kid_no_collisions_many_ecdsa_labels() {
    let fx = factory_from_env("kid-collision");
    let mut kids = HashSet::new();

    for i in 0..200 {
        let kid = fx.ecdsa(format!("svc-{i}"), EcdsaSpec::es256()).kid();
        assert!(
            kids.insert(kid.clone()),
            "KID collision at index {i}: '{kid}'"
        );
    }
    assert_eq!(kids.len(), 200);
}

#[test]
fn kid_no_collisions_many_ed25519_labels() {
    let fx = factory_from_env("kid-collision");
    let mut kids = HashSet::new();

    for i in 0..200 {
        let kid = fx.ed25519(format!("svc-{i}"), Ed25519Spec::new()).kid();
        assert!(
            kids.insert(kid.clone()),
            "KID collision at index {i}: '{kid}'"
        );
    }
    assert_eq!(kids.len(), 200);
}

#[test]
fn kid_no_collisions_many_hmac_labels() {
    let fx = factory_from_env("kid-collision");
    let mut kids = HashSet::new();

    for i in 0..200 {
        let kid = fx.hmac(format!("svc-{i}"), HmacSpec::hs256()).kid();
        assert!(
            kids.insert(kid.clone()),
            "KID collision at index {i}: '{kid}'"
        );
    }
    assert_eq!(kids.len(), 200);
}

#[test]
fn kid_no_collisions_across_seeds() {
    let mut kids = HashSet::new();

    for i in 0u8..50 {
        let seed = Seed::new([i; 32]);
        let fx = Factory::deterministic(seed);
        let kid = fx.ecdsa("same-label", EcdsaSpec::es256()).kid();
        assert!(
            kids.insert(kid.clone()),
            "KID collision for seed byte {i}: '{kid}'"
        );
    }
    assert_eq!(kids.len(), 50);
}

// ---------------------------------------------------------------------------
// 6. KID Consistency Across Key Types: each type gets unique KIDs
// ---------------------------------------------------------------------------

#[test]
fn kid_unique_across_key_types_same_label() {
    let fx = factory_from_env("kid-cross-type");
    let rsa_kid = fx.rsa("shared-label", RsaSpec::rs256()).kid();
    let ec_kid = fx.ecdsa("shared-label", EcdsaSpec::es256()).kid();
    let ed_kid = fx.ed25519("shared-label", Ed25519Spec::new()).kid();
    let hmac_kid = fx.hmac("shared-label", HmacSpec::hs256()).kid();

    let mut kids = HashSet::new();
    kids.insert(rsa_kid.clone());
    kids.insert(ec_kid.clone());
    kids.insert(ed_kid.clone());
    kids.insert(hmac_kid.clone());

    assert_eq!(
        kids.len(),
        4,
        "All key types must produce unique KIDs for the same label. \
         RSA={rsa_kid} EC={ec_kid} Ed25519={ed_kid} HMAC={hmac_kid}"
    );
}

#[test]
fn kid_unique_across_all_specs_and_types() {
    let fx = factory_from_env("kid-all-specs");
    let mut kids = HashSet::new();

    let pairs = [
        ("RSA-2048", fx.rsa("svc", RsaSpec::rs256()).kid()),
        ("RSA-4096", fx.rsa("svc", RsaSpec::new(4096)).kid()),
        ("ECDSA-P256", fx.ecdsa("svc", EcdsaSpec::es256()).kid()),
        ("ECDSA-P384", fx.ecdsa("svc", EcdsaSpec::es384()).kid()),
        ("Ed25519", fx.ed25519("svc", Ed25519Spec::new()).kid()),
        ("HMAC-256", fx.hmac("svc", HmacSpec::hs256()).kid()),
        ("HMAC-384", fx.hmac("svc", HmacSpec::hs384()).kid()),
        ("HMAC-512", fx.hmac("svc", HmacSpec::hs512()).kid()),
    ];

    for (desc, kid) in &pairs {
        assert!(
            kids.insert(kid.clone()),
            "KID collision for {desc}: '{kid}'"
        );
    }

    // Also verify format for all
    for (desc, kid) in &pairs {
        assert_kid_format(kid, desc);
    }
}

// ---------------------------------------------------------------------------
// 7. Known-Value Regression: verify specific seed/label combos
// ---------------------------------------------------------------------------

#[test]
fn kid_regression_rsa_rs256_seed42_label_test() {
    let fx = factory_from_env("42");
    let kid = fx.rsa("test", RsaSpec::rs256()).kid();
    assert_eq!(
        kid, "xlKrVthYc071284I",
        "RSA rs256 with seed='42' label='test' must produce known KID"
    );
}

#[test]
fn kid_regression_rsa_4096_seed42_label_test() {
    let fx = factory_from_env("42");
    let kid = fx.rsa("test", RsaSpec::new(4096)).kid();
    assert_eq!(
        kid, "e23gOS1i5kgaIYl1",
        "RSA 4096 with seed='42' label='test' must produce known KID"
    );
}

#[test]
fn kid_regression_rsa_rs256_seed42_label_other() {
    let fx = factory_from_env("42");
    let kid = fx.rsa("other", RsaSpec::rs256()).kid();
    assert_eq!(
        kid, "K6ji3kg8MqdfE0dF",
        "RSA rs256 with seed='42' label='other' must produce known KID"
    );
}

#[test]
fn kid_regression_ecdsa_es256_seed42_label_test() {
    let fx = factory_from_env("42");
    let kid = fx.ecdsa("test", EcdsaSpec::es256()).kid();
    assert_eq!(
        kid, "1W3Ra1uSb_RYpHbR",
        "ECDSA es256 with seed='42' label='test' must produce known KID"
    );
}

#[test]
fn kid_regression_ecdsa_es384_seed42_label_test() {
    let fx = factory_from_env("42");
    let kid = fx.ecdsa("test", EcdsaSpec::es384()).kid();
    assert_eq!(
        kid, "-zWC10Y-qyh_1WQj",
        "ECDSA es384 with seed='42' label='test' must produce known KID"
    );
}

// ---------------------------------------------------------------------------
// 8. JWK kid Field Matches KID from Keypair
// ---------------------------------------------------------------------------

#[test]
fn jwk_kid_matches_keypair_kid_rsa() {
    let fx = factory_from_env("jwk-kid-match");
    let kp = fx.rsa("issuer", RsaSpec::rs256());
    let kid = kp.kid();

    let pub_jwk = kp.public_jwk().to_value();
    assert_eq!(
        pub_jwk["kid"].as_str().unwrap(),
        kid,
        "Public JWK kid must match keypair kid"
    );

    let priv_jwk = kp.private_key_jwk().to_value();
    assert_eq!(
        priv_jwk["kid"].as_str().unwrap(),
        kid,
        "Private JWK kid must match keypair kid"
    );
}

#[test]
fn jwk_kid_matches_keypair_kid_ecdsa() {
    let fx = factory_from_env("jwk-kid-match");
    let kp = fx.ecdsa("issuer", EcdsaSpec::es256());
    let kid = kp.kid();

    let pub_jwk = kp.public_jwk().to_value();
    assert_eq!(pub_jwk["kid"].as_str().unwrap(), kid);

    let priv_jwk = kp.private_key_jwk().to_value();
    assert_eq!(priv_jwk["kid"].as_str().unwrap(), kid);
}

#[test]
fn jwk_kid_matches_keypair_kid_ed25519() {
    let fx = factory_from_env("jwk-kid-match");
    let kp = fx.ed25519("issuer", Ed25519Spec::new());
    let kid = kp.kid();

    let pub_jwk = kp.public_jwk().to_value();
    assert_eq!(pub_jwk["kid"].as_str().unwrap(), kid);

    let priv_jwk = kp.private_key_jwk().to_value();
    assert_eq!(priv_jwk["kid"].as_str().unwrap(), kid);
}

#[test]
fn jwk_kid_matches_keypair_kid_hmac() {
    let fx = factory_from_env("jwk-kid-match");
    let secret = fx.hmac("issuer", HmacSpec::hs256());
    let kid = secret.kid();

    let jwk = secret.jwk().to_value();
    assert_eq!(jwk["kid"].as_str().unwrap(), kid);
}

#[test]
fn jwks_kid_matches_keypair_kid_rsa() {
    let fx = factory_from_env("jwks-kid-match");
    let kp = fx.rsa("issuer", RsaSpec::rs256());
    let kid = kp.kid();

    let jwks = kp.public_jwks().to_value();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"].as_str().unwrap(), kid);
}
