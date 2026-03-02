//! Builder pattern and API ergonomics tests.
//!
//! Validates that the public builder APIs across the workspace behave correctly:
//! - JwksBuilder: building, ordering, duplicates
//! - Factory: random vs deterministic creation, seed propagation, cloning
//! - Spec types: RsaSpec, EcdsaSpec, HmacSpec, Ed25519Spec defaults and variants
//! - X509Spec: builder chaining, field customization, stable_bytes sensitivity

use std::collections::HashSet;

use uselesskey_core::{Factory, Mode, Seed};
use uselesskey_ecdsa::EcdsaSpec;
use uselesskey_ed25519::Ed25519Spec;
use uselesskey_hmac::HmacSpec;
use uselesskey_jwk::{
    AnyJwk, EcPublicJwk, JwksBuilder, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};
use uselesskey_rsa::RsaSpec;
use uselesskey_x509::{KeyUsage, NotBeforeOffset, X509Spec};

// =========================================================================
// Helpers
// =========================================================================

fn make_rsa_pub(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: format!("n-{kid}"),
        e: "AQAB".to_string(),
    })
}

fn make_ec_pub(kid: &str) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: format!("x-{kid}"),
        y: format!("y-{kid}"),
    })
}

fn make_okp_pub(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: format!("x-{kid}"),
    })
}

fn make_oct_priv(kid: &str, alg: &'static str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg,
        kid: kid.to_string(),
        k: format!("k-{kid}"),
    })
}

// =========================================================================
// 1. JwksBuilder
// =========================================================================

#[test]
fn jwks_builder_empty_build() {
    let jwks = JwksBuilder::new().build();
    assert!(
        jwks.keys.is_empty(),
        "empty builder must produce empty JWKS"
    );
}

#[test]
fn jwks_builder_single_key() {
    let jwks = JwksBuilder::new().add_public(make_rsa_pub("only")).build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "only");
}

#[test]
fn jwks_builder_sorts_by_kid() {
    let jwks = JwksBuilder::new()
        .add_public(make_rsa_pub("charlie"))
        .add_public(make_ec_pub("alpha"))
        .add_public(make_okp_pub("bravo"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    assert_eq!(kids, vec!["alpha", "bravo", "charlie"]);
}

#[test]
fn jwks_builder_mixed_key_types_sorted() {
    let jwks = JwksBuilder::new()
        .add_public(make_rsa_pub("z-rsa"))
        .add_private(make_oct_priv("a-hmac", "HS256"))
        .add_public(make_ec_pub("m-ec"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    assert_eq!(kids, vec!["a-hmac", "m-ec", "z-rsa"]);
}

#[test]
fn jwks_builder_duplicate_kid_preserves_insertion_order() {
    let jwks = JwksBuilder::new()
        .add_public(make_rsa_pub("dup"))
        .add_public(make_ec_pub("dup"))
        .add_public(make_okp_pub("dup"))
        .build();

    assert_eq!(jwks.keys.len(), 3);
    // All have the same kid
    assert!(jwks.keys.iter().all(|k| k.kid() == "dup"));
    // Verify insertion order by checking kty via serialized value
    let ktys: Vec<String> = jwks
        .keys
        .iter()
        .map(|k| k.to_value()["kty"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ktys, vec!["RSA", "EC", "OKP"]);
}

#[test]
fn jwks_builder_add_any_variant() {
    let any_pub = AnyJwk::from(make_rsa_pub("pub-key"));
    let any_priv = AnyJwk::from(make_oct_priv("priv-key", "HS256"));

    let jwks = JwksBuilder::new()
        .add_any(any_pub)
        .add_any(any_priv)
        .build();
    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    assert_eq!(kids, vec!["priv-key", "pub-key"]);
}

#[test]
fn jwks_builder_push_methods_return_self() {
    let mut builder = JwksBuilder::new();
    builder
        .push_public(make_rsa_pub("a"))
        .push_private(make_oct_priv("b", "HS256"))
        .push_any(AnyJwk::from(make_ec_pub("c")));

    let jwks = builder.build();
    assert_eq!(jwks.keys.len(), 3);
}

#[test]
fn jwks_builder_serializes_to_valid_json() {
    let jwks = JwksBuilder::new()
        .add_public(make_rsa_pub("k1"))
        .add_public(make_ec_pub("k2"))
        .build();

    let json_str = jwks.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
    assert!(parsed["keys"].is_array());
    assert_eq!(parsed["keys"].as_array().unwrap().len(), 2);
}

#[test]
fn jwks_builder_clone_independence() {
    let builder1 = JwksBuilder::new().add_public(make_rsa_pub("original"));
    let builder2 = builder1.clone().add_public(make_ec_pub("added"));

    let jwks1 = builder1.build();
    let jwks2 = builder2.build();
    assert_eq!(jwks1.keys.len(), 1);
    assert_eq!(jwks2.keys.len(), 2);
}

// =========================================================================
// 2. Factory builder pattern
// =========================================================================

#[test]
fn factory_random_mode() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn factory_deterministic_mode() {
    let seed = Seed::new([0x42; 32]);
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_deterministic_from_env_value() {
    // Seed::from_env_value hashes arbitrary strings via BLAKE3
    let seed = Seed::from_env_value("my-test-seed").expect("valid seed");
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_deterministic_from_hex_seed() {
    let hex = "0x".to_string() + &"ab".repeat(32);
    let seed = Seed::from_env_value(&hex).expect("valid hex seed");
    assert_eq!(seed, Seed::new([0xAB; 32]));
}

#[test]
fn factory_seed_from_env_value_is_deterministic() {
    let s1 = Seed::from_env_value("same-value").unwrap();
    let s2 = Seed::from_env_value("same-value").unwrap();
    assert_eq!(s1, s2, "same input must produce same seed");
}

#[test]
fn factory_different_seeds_differ() {
    let s1 = Seed::from_env_value("seed-a").unwrap();
    let s2 = Seed::from_env_value("seed-b").unwrap();
    assert_ne!(s1, s2, "different inputs must produce different seeds");
}

#[test]
fn factory_clone_shares_cache() {
    let seed = Seed::new([0x01; 32]);
    let fx1 = Factory::deterministic(seed);

    // Generate a key on fx1
    use uselesskey_ecdsa::EcdsaFactoryExt;
    let kp1 = fx1.ecdsa("shared-label", EcdsaSpec::es256());

    // Clone and retrieve the same key — should hit cache
    let fx2 = fx1.clone();
    let kp2 = fx2.ecdsa("shared-label", EcdsaSpec::es256());

    assert_eq!(
        kp1.public_key_spki_pem(),
        kp2.public_key_spki_pem(),
        "cloned factory must share the same cache"
    );
}

#[test]
fn factory_random_produces_distinct_keys() {
    let fx = Factory::random();
    use uselesskey_ed25519::Ed25519FactoryExt;
    let kp1 = fx.ed25519("label-a", Ed25519Spec::new());
    let kp2 = fx.ed25519("label-b", Ed25519Spec::new());
    assert_ne!(
        kp1.public_key_spki_pem(),
        kp2.public_key_spki_pem(),
        "different labels should produce different keys"
    );
}

#[test]
fn factory_seed_debug_redacts() {
    let seed = Seed::new([0xFF; 32]);
    let dbg = format!("{seed:?}");
    assert!(
        dbg.contains("redacted"),
        "Seed Debug must redact key material, got: {dbg}"
    );
    assert!(
        !dbg.contains("ff"),
        "Seed Debug must not leak hex bytes, got: {dbg}"
    );
}

// =========================================================================
// 3. Spec builders — RsaSpec
// =========================================================================

#[test]
fn rsa_spec_rs256_defaults() {
    let spec = RsaSpec::rs256();
    assert_eq!(spec.bits, 2048);
    assert_eq!(spec.exponent, 65537);
}

#[test]
fn rsa_spec_custom_bits() {
    let spec = RsaSpec::new(4096);
    assert_eq!(spec.bits, 4096);
    assert_eq!(spec.exponent, 65537);
}

#[test]
fn rsa_spec_stable_bytes_deterministic() {
    assert_eq!(
        RsaSpec::rs256().stable_bytes(),
        RsaSpec::rs256().stable_bytes()
    );
}

#[test]
fn rsa_spec_stable_bytes_differ_for_different_sizes() {
    assert_ne!(
        RsaSpec::new(2048).stable_bytes(),
        RsaSpec::new(4096).stable_bytes()
    );
}

#[test]
fn rsa_spec_equality_and_hash() {
    let a = RsaSpec::rs256();
    let b = RsaSpec::rs256();
    assert_eq!(a, b);

    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}

// =========================================================================
// 3. Spec builders — EcdsaSpec
// =========================================================================

#[test]
fn ecdsa_spec_es256() {
    let spec = EcdsaSpec::es256();
    assert_eq!(spec.alg_name(), "ES256");
    assert_eq!(spec.curve_name(), "P-256");
    assert_eq!(spec.coordinate_len_bytes(), 32);
}

#[test]
fn ecdsa_spec_es384() {
    let spec = EcdsaSpec::es384();
    assert_eq!(spec.alg_name(), "ES384");
    assert_eq!(spec.curve_name(), "P-384");
    assert_eq!(spec.coordinate_len_bytes(), 48);
}

#[test]
fn ecdsa_spec_variants_differ() {
    assert_ne!(EcdsaSpec::es256(), EcdsaSpec::es384());
    assert_ne!(
        EcdsaSpec::es256().stable_bytes(),
        EcdsaSpec::es384().stable_bytes()
    );
}

#[test]
fn ecdsa_spec_equality_and_hash() {
    let a = EcdsaSpec::es256();
    let b = EcdsaSpec::es256();
    assert_eq!(a, b);

    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
    set.insert(EcdsaSpec::es384());
    assert_eq!(set.len(), 2);
}

// =========================================================================
// 3. Spec builders — HmacSpec
// =========================================================================

#[test]
fn hmac_spec_variants() {
    let specs = [
        (HmacSpec::hs256(), "HS256", 32),
        (HmacSpec::hs384(), "HS384", 48),
        (HmacSpec::hs512(), "HS512", 64),
    ];

    for (spec, expected_alg, expected_len) in &specs {
        assert_eq!(spec.alg_name(), *expected_alg);
        assert_eq!(spec.byte_len(), *expected_len);
    }
}

#[test]
fn hmac_spec_stable_bytes_unique() {
    let bytes: Vec<[u8; 4]> = [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()]
        .iter()
        .map(|s| s.stable_bytes())
        .collect();

    // All pairs are distinct
    assert_ne!(bytes[0], bytes[1]);
    assert_ne!(bytes[0], bytes[2]);
    assert_ne!(bytes[1], bytes[2]);
}

#[test]
fn hmac_spec_equality_and_hash() {
    let mut set = HashSet::new();
    set.insert(HmacSpec::hs256());
    set.insert(HmacSpec::hs384());
    set.insert(HmacSpec::hs512());
    set.insert(HmacSpec::hs256()); // duplicate
    assert_eq!(set.len(), 3);
}

// =========================================================================
// 3. Spec builders — Ed25519Spec
// =========================================================================

#[test]
fn ed25519_spec_new_equals_default() {
    assert_eq!(Ed25519Spec::new(), Ed25519Spec::default());
}

#[test]
fn ed25519_spec_stable_bytes_deterministic() {
    assert_eq!(
        Ed25519Spec::new().stable_bytes(),
        Ed25519Spec::new().stable_bytes()
    );
}

// =========================================================================
// 4. X509Spec builder
// =========================================================================

#[test]
fn x509_spec_self_signed_defaults() {
    let spec = X509Spec::self_signed("example.com");
    assert_eq!(spec.subject_cn, "example.com");
    assert_eq!(spec.issuer_cn, "example.com");
    assert!(!spec.is_ca);
    assert_eq!(spec.validity_days, 3650);
    assert_eq!(spec.rsa_bits, 2048);
    assert!(spec.sans.is_empty());
    assert_eq!(spec.key_usage, KeyUsage::leaf());
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysAgo(1));
}

#[test]
fn x509_spec_self_signed_ca() {
    let spec = X509Spec::self_signed_ca("My CA");
    assert!(spec.is_ca);
    assert!(spec.key_usage.key_cert_sign);
    assert!(spec.key_usage.crl_sign);
    assert!(spec.key_usage.digital_signature);
    assert!(!spec.key_usage.key_encipherment);
    assert_eq!(spec.subject_cn, "My CA");
    assert_eq!(spec.issuer_cn, "My CA");
}

#[test]
fn x509_spec_builder_chaining() {
    let spec = X509Spec::self_signed("test.example.com")
        .with_validity_days(90)
        .with_not_before(NotBeforeOffset::DaysFromNow(7))
        .with_rsa_bits(4096)
        .with_is_ca(true)
        .with_key_usage(KeyUsage::ca())
        .with_sans(vec!["a.example.com".into(), "b.example.com".into()]);

    assert_eq!(spec.validity_days, 90);
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysFromNow(7));
    assert_eq!(spec.rsa_bits, 4096);
    assert!(spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::ca());
    assert_eq!(spec.sans.len(), 2);
}

#[test]
fn x509_spec_key_usage_leaf_vs_ca() {
    let leaf = KeyUsage::leaf();
    let ca = KeyUsage::ca();

    assert!(leaf.digital_signature);
    assert!(leaf.key_encipherment);
    assert!(!leaf.key_cert_sign);
    assert!(!leaf.crl_sign);

    assert!(ca.digital_signature);
    assert!(!ca.key_encipherment);
    assert!(ca.key_cert_sign);
    assert!(ca.crl_sign);

    assert_ne!(leaf, ca);
    assert_ne!(leaf.stable_bytes(), ca.stable_bytes());
}

#[test]
fn x509_spec_key_usage_default_is_leaf() {
    assert_eq!(KeyUsage::default(), KeyUsage::leaf());
}

#[test]
fn x509_spec_not_before_offset_variants() {
    let ago = NotBeforeOffset::DaysAgo(5);
    let future = NotBeforeOffset::DaysFromNow(5);
    assert_ne!(ago, future);
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}

#[test]
fn x509_spec_stable_bytes_deterministic() {
    let s1 = X509Spec::self_signed("test");
    let s2 = X509Spec::self_signed("test");
    assert_eq!(s1.stable_bytes(), s2.stable_bytes());
}

#[test]
fn x509_spec_stable_bytes_field_sensitivity() {
    let base = X509Spec::self_signed("test");
    let base_bytes = base.stable_bytes();

    // Each field change must produce different stable_bytes
    let mutations: Vec<(&str, X509Spec)> = vec![
        ("validity_days", base.clone().with_validity_days(1)),
        ("is_ca", base.clone().with_is_ca(true)),
        ("rsa_bits", base.clone().with_rsa_bits(4096)),
        (
            "not_before",
            base.clone()
                .with_not_before(NotBeforeOffset::DaysFromNow(30)),
        ),
        ("key_usage", base.clone().with_key_usage(KeyUsage::ca())),
        (
            "sans",
            base.clone().with_sans(vec!["san.example.com".into()]),
        ),
    ];

    for (field, mutated) in mutations {
        assert_ne!(
            mutated.stable_bytes(),
            base_bytes,
            "changing {field} must affect stable_bytes"
        );
    }

    // Changing issuer_cn
    let mut changed = base.clone();
    changed.issuer_cn = "Other Issuer".to_string();
    assert_ne!(
        changed.stable_bytes(),
        base_bytes,
        "changing issuer_cn must affect stable_bytes"
    );
}

#[test]
fn x509_spec_stable_bytes_deduplicates_sans() {
    let with_dupes = X509Spec::self_signed("test").with_sans(vec![
        "a.com".into(),
        "a.com".into(),
        "b.com".into(),
    ]);
    let without_dupes =
        X509Spec::self_signed("test").with_sans(vec!["a.com".into(), "b.com".into()]);
    assert_eq!(with_dupes.stable_bytes(), without_dupes.stable_bytes());
}

#[test]
fn x509_spec_not_before_duration_days_ago() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysAgo(3));
    let expected = std::time::Duration::from_secs(3 * 24 * 60 * 60);
    assert_eq!(spec.not_before_duration(), expected);
}

#[test]
fn x509_spec_not_before_duration_days_from_now() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysFromNow(5));
    assert_eq!(spec.not_before_duration(), std::time::Duration::ZERO);
}

#[test]
fn x509_spec_not_after_duration() {
    let spec = X509Spec::self_signed("test").with_validity_days(30);
    let expected = std::time::Duration::from_secs(30 * 24 * 60 * 60);
    assert_eq!(spec.not_after_duration(), expected);
}

#[test]
fn x509_spec_not_after_with_future_offset() {
    let spec = X509Spec::self_signed("test")
        .with_not_before(NotBeforeOffset::DaysFromNow(10))
        .with_validity_days(20);
    // not_after = offset_duration + validity_duration
    let expected = std::time::Duration::from_secs((10 + 20) * 24 * 60 * 60);
    assert_eq!(spec.not_after_duration(), expected);
}
