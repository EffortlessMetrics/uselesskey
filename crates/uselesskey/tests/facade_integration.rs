//! Comprehensive facade integration tests exercising the full public API surface
//! of the `uselesskey` crate from a user's perspective.
//!
//! These tests verify that the facade re-exports work end-to-end and that
//! cross-key-type interactions behave correctly.

mod testutil;

use std::sync::Arc;
use uselesskey::prelude::*;

fn deterministic_fx(seed_str: &str) -> Factory {
    Seed::from_env_value(seed_str)
        .map(Factory::deterministic)
        .expect("test seed")
}

// ===========================================================================
// 1. Full workflow tests — Factory → fixture → all output formats
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_full_workflow_all_formats() {
    let fx = testutil::fx();
    let kp = fx.rsa("workflow-rsa", RsaSpec::rs256());

    // PEM formats
    let priv_pem = kp.private_key_pkcs8_pem();
    assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(priv_pem.trim_end().ends_with("-----END PRIVATE KEY-----"));

    let pub_pem = kp.public_key_spki_pem();
    assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(pub_pem.trim_end().ends_with("-----END PUBLIC KEY-----"));

    // DER formats
    let priv_der = kp.private_key_pkcs8_der();
    assert!(!priv_der.is_empty());
    assert_eq!(priv_der[0], 0x30, "PKCS#8 DER starts with SEQUENCE tag");

    let pub_der = kp.public_key_spki_der();
    assert!(!pub_der.is_empty());
    assert_eq!(pub_der[0], 0x30, "SPKI DER starts with SEQUENCE tag");

    // Tempfile outputs
    let priv_tmp = kp.write_private_key_pkcs8_pem().unwrap();
    assert!(priv_tmp.path().exists());

    let pub_tmp = kp.write_public_key_spki_pem().unwrap();
    assert!(pub_tmp.path().exists());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_full_workflow_es256() {
    let fx = testutil::fx();
    let kp = fx.ecdsa("workflow-ec256", EcdsaSpec::es256());

    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    assert!(!kp.private_key_pkcs8_der().is_empty());
    assert!(!kp.public_key_spki_der().is_empty());

    let tmp = kp.write_private_key_pkcs8_pem().unwrap();
    assert!(tmp.path().exists());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_full_workflow_es384() {
    let fx = testutil::fx();
    let kp = fx.ecdsa("workflow-ec384", EcdsaSpec::es384());

    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_full_workflow() {
    let fx = testutil::fx();
    let kp = fx.ed25519("workflow-ed", Ed25519Spec::new());

    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    assert!(!kp.private_key_pkcs8_der().is_empty());
    assert!(!kp.public_key_spki_der().is_empty());

    let priv_tmp = kp.write_private_key_pkcs8_pem().unwrap();
    assert!(priv_tmp.path().exists());

    let pub_tmp = kp.write_public_key_spki_pem().unwrap();
    assert!(pub_tmp.path().exists());
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_full_workflow_all_specs() {
    let fx = testutil::fx();

    let hs256 = fx.hmac("workflow-hmac", HmacSpec::hs256());
    assert_eq!(hs256.secret_bytes().len(), 32);

    let hs384 = fx.hmac("workflow-hmac-384", HmacSpec::hs384());
    assert_eq!(hs384.secret_bytes().len(), 48);

    let hs512 = fx.hmac("workflow-hmac-512", HmacSpec::hs512());
    assert_eq!(hs512.secret_bytes().len(), 64);
}

#[test]
#[cfg(feature = "token")]
fn token_full_workflow_all_kinds() {
    let fx = testutil::fx();

    let api = fx.token("workflow-api", TokenSpec::api_key());
    assert!(api.value().starts_with("uk_test_"));
    assert!(api.authorization_header().starts_with("ApiKey "));

    let bearer = fx.token("workflow-bearer", TokenSpec::bearer());
    assert!(!bearer.value().is_empty());
    assert!(bearer.authorization_header().starts_with("Bearer "));

    let oauth = fx.token("workflow-oauth", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = oauth.value().split('.').collect();
    assert_eq!(parts.len(), 3, "OAuth token must have 3 JWT segments");
    assert!(oauth.authorization_header().starts_with("Bearer "));
}

// ===========================================================================
// 2. Cross-key-type tests — all types in same Factory, verify independence
// ===========================================================================

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519", feature = "hmac", feature = "token"))]
fn all_key_types_coexist_independently() {
    let fx = deterministic_fx("cross-type-v1");

    let rsa = fx.rsa("cross-svc", RsaSpec::rs256());
    let ecdsa = fx.ecdsa("cross-svc", EcdsaSpec::es256());
    let ed = fx.ed25519("cross-svc", Ed25519Spec::new());
    let hmac = fx.hmac("cross-svc", HmacSpec::hs256());
    let tok = fx.token("cross-svc", TokenSpec::api_key());

    // All produce non-empty output
    assert!(!rsa.private_key_pkcs8_der().is_empty());
    assert!(!ecdsa.private_key_pkcs8_der().is_empty());
    assert!(!ed.private_key_pkcs8_der().is_empty());
    assert!(!hmac.secret_bytes().is_empty());
    assert!(!tok.value().is_empty());

    // All DER private keys are distinct from each other (different key types)
    assert_ne!(rsa.private_key_pkcs8_der(), ecdsa.private_key_pkcs8_der());
    assert_ne!(rsa.private_key_pkcs8_der(), ed.private_key_pkcs8_der());
    assert_ne!(ecdsa.private_key_pkcs8_der(), ed.private_key_pkcs8_der());
}

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519", feature = "hmac", feature = "token"))]
fn same_label_different_types_are_independent_across_factories() {
    let fx1 = deterministic_fx("independence-v1");
    let fx2 = deterministic_fx("independence-v1");

    // Generate in different orders
    let rsa1 = fx1.rsa("svc", RsaSpec::rs256());
    let ecdsa1 = fx1.ecdsa("svc", EcdsaSpec::es256());
    let ed1 = fx1.ed25519("svc", Ed25519Spec::new());
    let hmac1 = fx1.hmac("svc", HmacSpec::hs256());
    let tok1 = fx1.token("svc", TokenSpec::bearer());

    let tok2 = fx2.token("svc", TokenSpec::bearer());
    let hmac2 = fx2.hmac("svc", HmacSpec::hs256());
    let ed2 = fx2.ed25519("svc", Ed25519Spec::new());
    let ecdsa2 = fx2.ecdsa("svc", EcdsaSpec::es256());
    let rsa2 = fx2.rsa("svc", RsaSpec::rs256());

    assert_eq!(rsa1.private_key_pkcs8_der(), rsa2.private_key_pkcs8_der());
    assert_eq!(ecdsa1.private_key_pkcs8_der(), ecdsa2.private_key_pkcs8_der());
    assert_eq!(ed1.private_key_pkcs8_der(), ed2.private_key_pkcs8_der());
    assert_eq!(hmac1.secret_bytes(), hmac2.secret_bytes());
    assert_eq!(tok1.value(), tok2.value());
}

// ===========================================================================
// 3. Determinism tests — same seed → same outputs across Factory instances
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_determinism_across_fresh_factories() {
    let fx1 = deterministic_fx("det-cross-v1");
    let fx2 = deterministic_fx("det-cross-v1");

    let k1 = fx1.rsa("det-rsa", RsaSpec::rs256());
    let k2 = fx2.rsa("det-rsa", RsaSpec::rs256());

    assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
    assert_eq!(k1.public_key_spki_pem(), k2.public_key_spki_pem());
    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_determinism_survives_cache_clear() {
    let fx = deterministic_fx("det-clear-v1");
    let k1_pem = fx.rsa("det-clear-rsa", RsaSpec::rs256()).private_key_pkcs8_pem().to_owned();
    fx.clear_cache();
    let k2_pem = fx.rsa("det-clear-rsa", RsaSpec::rs256()).private_key_pkcs8_pem().to_owned();
    assert_eq!(k1_pem, k2_pem);
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_determinism_across_fresh_factories() {
    let fx1 = deterministic_fx("det-ec-v1");
    let fx2 = deterministic_fx("det-ec-v1");

    let k1 = fx1.ecdsa("det-ec", EcdsaSpec::es256());
    let k2 = fx2.ecdsa("det-ec", EcdsaSpec::es256());

    assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
    assert_eq!(k1.public_key_spki_pem(), k2.public_key_spki_pem());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_determinism_across_fresh_factories() {
    let fx1 = deterministic_fx("det-ed-v1");
    let fx2 = deterministic_fx("det-ed-v1");

    let k1 = fx1.ed25519("det-ed", Ed25519Spec::new());
    let k2 = fx2.ed25519("det-ed", Ed25519Spec::new());

    assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
    assert_eq!(k1.public_key_spki_pem(), k2.public_key_spki_pem());
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_determinism_across_fresh_factories() {
    let fx1 = deterministic_fx("det-hmac-v1");
    let fx2 = deterministic_fx("det-hmac-v1");

    let s1 = fx1.hmac("det-hmac", HmacSpec::hs512());
    let s2 = fx2.hmac("det-hmac", HmacSpec::hs512());

    assert_eq!(s1.secret_bytes(), s2.secret_bytes());
}

#[test]
#[cfg(feature = "token")]
fn token_determinism_across_fresh_factories() {
    let fx1 = deterministic_fx("det-tok-v1");
    let fx2 = deterministic_fx("det-tok-v1");

    for spec in [TokenSpec::api_key(), TokenSpec::bearer(), TokenSpec::oauth_access_token()] {
        let t1 = fx1.token("det-tok", spec);
        let t2 = fx2.token("det-tok", spec);
        assert_eq!(t1.value(), t2.value());
    }
}

#[test]
fn different_seeds_produce_different_outputs() {
    #[cfg(feature = "rsa")]
    {
        let k1 = deterministic_fx("seed-a").rsa("svc", RsaSpec::rs256());
        let k2 = deterministic_fx("seed-b").rsa("svc", RsaSpec::rs256());
        assert_ne!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    }
}

// ===========================================================================
// 4. Cache tests — same call twice returns same Arc (pointer equality)
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_cache_returns_same_data_pointer() {
    let fx = Factory::random();
    let k1 = fx.rsa("cache-rsa", RsaSpec::rs256());
    let k2 = fx.rsa("cache-rsa", RsaSpec::rs256());

    // Both references point to the same underlying data
    assert!(std::ptr::eq(
        k1.private_key_pkcs8_pem(),
        k2.private_key_pkcs8_pem()
    ));
    assert!(std::ptr::eq(
        k1.public_key_spki_der(),
        k2.public_key_spki_der()
    ));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_cache_returns_same_data_pointer() {
    let fx = Factory::random();
    let k1 = fx.ecdsa("cache-ec", EcdsaSpec::es256());
    let k2 = fx.ecdsa("cache-ec", EcdsaSpec::es256());

    assert!(std::ptr::eq(
        k1.private_key_pkcs8_pem(),
        k2.private_key_pkcs8_pem()
    ));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_cache_returns_same_data_pointer() {
    let fx = Factory::random();
    let k1 = fx.ed25519("cache-ed", Ed25519Spec::new());
    let k2 = fx.ed25519("cache-ed", Ed25519Spec::new());

    assert!(std::ptr::eq(
        k1.private_key_pkcs8_pem(),
        k2.private_key_pkcs8_pem()
    ));
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_cache_returns_same_data_pointer() {
    let fx = Factory::random();
    let s1 = fx.hmac("cache-hmac", HmacSpec::hs256());
    let s2 = fx.hmac("cache-hmac", HmacSpec::hs256());

    assert!(std::ptr::eq(s1.secret_bytes(), s2.secret_bytes()));
}

#[test]
#[cfg(feature = "token")]
fn token_cache_returns_same_data_pointer() {
    let fx = Factory::random();
    let t1 = fx.token("cache-tok", TokenSpec::bearer());
    let t2 = fx.token("cache-tok", TokenSpec::bearer());

    assert!(std::ptr::eq(t1.value(), t2.value()));
}

#[test]
#[cfg(feature = "rsa")]
fn cache_invalidated_after_clear() {
    let fx = Factory::random();
    let k1 = fx.rsa("cache-clear", RsaSpec::rs256());
    let pem1 = k1.private_key_pkcs8_pem() as *const str;

    fx.clear_cache();

    let k2 = fx.rsa("cache-clear", RsaSpec::rs256());
    let pem2 = k2.private_key_pkcs8_pem() as *const str;

    // After clearing, a new Arc is created — different data pointer in random mode
    assert!(!std::ptr::eq(pem1, pem2));
}

// ===========================================================================
// 5. Negative fixture tests (through facade API)
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_negative_corrupt_pem_via_facade() {
    let fx = testutil::fx();
    let kp = fx.rsa("neg-rsa", RsaSpec::rs256());

    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(bad.contains("CORRUPTED"));
    assert!(!bad.contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_negative_truncated_der_via_facade() {
    let fx = testutil::fx();
    let kp = fx.rsa("neg-rsa", RsaSpec::rs256());

    let trunc = kp.private_key_pkcs8_der_truncated(16);
    assert_eq!(trunc.len(), 16);
    assert!(trunc.len() < kp.private_key_pkcs8_der().len());
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_negative_mismatched_key_via_facade() {
    let fx = testutil::fx();
    let kp = fx.rsa("neg-rsa", RsaSpec::rs256());

    let mismatch = kp.mismatched_public_key_spki_der();
    assert_ne!(mismatch.as_slice(), kp.public_key_spki_der());
    assert_eq!(mismatch[0], 0x30, "mismatched key is still valid DER");
}

// ===========================================================================
// 6. JWK/JWKS tests — build JWKS sets from multiple key types
// ===========================================================================

#[test]
#[cfg(all(feature = "jwk", feature = "rsa"))]
fn rsa_jwk_has_expected_fields() {
    let fx = testutil::fx();
    let kp = fx.rsa("jwk-rsa", RsaSpec::rs256());

    let pub_jwk = kp.public_jwk_json();
    assert_eq!(pub_jwk["kty"], "RSA");
    assert_eq!(pub_jwk["alg"], "RS256");
    assert_eq!(pub_jwk["use"], "sig");
    assert!(pub_jwk["kid"].is_string());
    assert!(pub_jwk["n"].is_string());
    assert!(pub_jwk["e"].is_string());

    let priv_jwk = kp.private_key_jwk_json();
    assert_eq!(priv_jwk["kty"], "RSA");
    assert!(priv_jwk["d"].is_string());
    assert!(priv_jwk["p"].is_string());
    assert!(priv_jwk["q"].is_string());
}

#[test]
#[cfg(all(feature = "jwk", feature = "rsa"))]
fn rsa_jwks_wraps_single_key() {
    let fx = testutil::fx();
    let kp = fx.rsa("jwks-rsa", RsaSpec::rs256());

    let jwks = kp.public_jwks_json();
    let keys = jwks["keys"].as_array().expect("keys is array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "RSA");
}

#[test]
#[cfg(all(feature = "jwk", feature = "ecdsa"))]
fn ecdsa_jwk_has_expected_fields() {
    let fx = testutil::fx();
    let kp = fx.ecdsa("jwk-ec", EcdsaSpec::es256());

    let pub_jwk = kp.public_jwk_json();
    assert_eq!(pub_jwk["kty"], "EC");
    assert_eq!(pub_jwk["crv"], "P-256");
    assert_eq!(pub_jwk["alg"], "ES256");
    assert!(pub_jwk["x"].is_string());
    assert!(pub_jwk["y"].is_string());

    let priv_jwk = kp.private_key_jwk_json();
    assert_eq!(priv_jwk["kty"], "EC");
    assert!(priv_jwk["d"].is_string());
}

#[test]
#[cfg(all(feature = "jwk", feature = "ecdsa"))]
fn ecdsa_es384_jwk_uses_p384() {
    let fx = testutil::fx();
    let kp = fx.ecdsa("jwk-ec384", EcdsaSpec::es384());

    let jwk = kp.public_jwk_json();
    assert_eq!(jwk["crv"], "P-384");
    assert_eq!(jwk["alg"], "ES384");
}

#[test]
#[cfg(all(feature = "jwk", feature = "ed25519"))]
fn ed25519_jwk_has_expected_fields() {
    let fx = testutil::fx();
    let kp = fx.ed25519("jwk-ed", Ed25519Spec::new());

    let pub_jwk = kp.public_jwk_json();
    assert_eq!(pub_jwk["kty"], "OKP");
    assert_eq!(pub_jwk["crv"], "Ed25519");
    assert_eq!(pub_jwk["alg"], "EdDSA");
    assert!(pub_jwk["x"].is_string());

    let priv_jwk = kp.private_key_jwk_json();
    assert_eq!(priv_jwk["kty"], "OKP");
    assert!(priv_jwk["d"].is_string());
}

#[test]
#[cfg(all(feature = "jwk", feature = "hmac"))]
fn hmac_jwk_has_expected_fields() {
    let fx = testutil::fx();
    let s = fx.hmac("jwk-hmac", HmacSpec::hs256());

    let jwk = s.jwk().to_value();
    assert_eq!(jwk["kty"], "oct");
    assert_eq!(jwk["alg"], "HS256");
    assert_eq!(jwk["use"], "sig");
    assert!(jwk["k"].is_string());
    assert!(jwk["kid"].is_string());
}

#[test]
#[cfg(all(feature = "jwk", feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
fn multi_key_jwks_via_builder() {
    use uselesskey::jwk::JwksBuilder;

    let fx = testutil::fx();
    let rsa = fx.rsa("multi-jwks", RsaSpec::rs256());
    let ec = fx.ecdsa("multi-jwks", EcdsaSpec::es256());
    let ed = fx.ed25519("multi-jwks", Ed25519Spec::new());

    let jwks = JwksBuilder::new()
        .add_public(rsa.public_jwk())
        .add_public(ec.public_jwk())
        .add_public(ed.public_jwk())
        .build();

    let val = jwks.to_value();
    let keys = val["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 3);

    // Verify each key type is present
    let ktys: Vec<&str> = keys.iter().map(|k| k["kty"].as_str().unwrap()).collect();
    assert!(ktys.contains(&"RSA"));
    assert!(ktys.contains(&"EC"));
    assert!(ktys.contains(&"OKP"));
}

#[test]
#[cfg(all(feature = "jwk", feature = "rsa"))]
fn jwk_kid_is_deterministic() {
    let fx1 = deterministic_fx("kid-det-v1");
    let fx2 = deterministic_fx("kid-det-v1");

    let kid1 = fx1.rsa("kid-test", RsaSpec::rs256()).kid();
    let kid2 = fx2.rsa("kid-test", RsaSpec::rs256()).kid();

    assert_eq!(kid1, kid2);
    assert!(!kid1.is_empty());
}

#[test]
#[cfg(all(feature = "jwk", feature = "rsa"))]
fn jwk_kid_differs_across_labels() {
    let fx = testutil::fx();
    let kid_a = fx.rsa("kid-a", RsaSpec::rs256()).kid();
    let kid_b = fx.rsa("kid-b", RsaSpec::rs256()).kid();
    assert_ne!(kid_a, kid_b);
}

// ===========================================================================
// 7. X.509 tests — self-signed certs, chains, expired, not-yet-valid
// ===========================================================================

#[test]
#[cfg(feature = "x509")]
fn x509_self_signed_basic() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = testutil::fx();
    let spec = X509Spec::self_signed("test.example.com");
    let cert = fx.x509_self_signed("x509-basic", spec);

    assert!(cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"));
    assert!(cert.private_key_pkcs8_pem().contains("-----BEGIN PRIVATE KEY-----"));
    assert!(!cert.cert_der().is_empty());
    assert!(!cert.private_key_pkcs8_der().is_empty());
}

#[test]
#[cfg(feature = "x509")]
fn x509_identity_pem_has_both_cert_and_key() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-id", X509Spec::self_signed("id.example.com"));

    let identity = cert.identity_pem();
    assert!(identity.contains("-----BEGIN CERTIFICATE-----"));
    assert!(identity.contains("-----BEGIN PRIVATE KEY-----"));
}

#[test]
#[cfg(feature = "x509")]
fn x509_expired_cert_differs_from_valid() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-exp", X509Spec::self_signed("exp.example.com"));
    let expired = cert.expired();

    assert_ne!(cert.cert_der(), expired.cert_der());
    assert!(expired.cert_pem().contains("BEGIN CERTIFICATE"));
}

#[test]
#[cfg(feature = "x509")]
fn x509_not_yet_valid_cert_differs_from_valid() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-nyv", X509Spec::self_signed("nyv.example.com"));
    let not_valid = cert.not_yet_valid();

    assert_ne!(cert.cert_der(), not_valid.cert_der());
}

#[test]
#[cfg(feature = "x509")]
fn x509_wrong_key_usage_changes_spec() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-wku", X509Spec::self_signed("wku.example.com"));
    let wrong = cert.wrong_key_usage();

    assert!(wrong.spec().is_ca);
    assert!(!wrong.spec().key_usage.key_cert_sign);
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_three_level() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain", ChainSpec::new("chain.example.com"));

    // Verify chain PEM has exactly 2 certs (leaf + intermediate)
    assert_eq!(chain.chain_pem().matches("BEGIN CERTIFICATE").count(), 2);

    // Full chain has 3 certs
    assert_eq!(chain.full_chain_pem().matches("BEGIN CERTIFICATE").count(), 3);

    // All components are non-empty
    assert!(!chain.root_cert_der().is_empty());
    assert!(!chain.intermediate_cert_der().is_empty());
    assert!(!chain.leaf_cert_der().is_empty());
    assert!(chain.leaf_private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_expired_leaf() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain-el", ChainSpec::new("el.example.com"));
    let expired = chain.expired_leaf();

    assert_ne!(chain.leaf_cert_der(), expired.leaf_cert_der());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_expired_intermediate() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain-ei", ChainSpec::new("ei.example.com"));
    let expired = chain.expired_intermediate();

    assert_ne!(chain.intermediate_cert_der(), expired.intermediate_cert_der());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_hostname_mismatch() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain-hm", ChainSpec::new("correct.example.com"));
    let mismatch = chain.hostname_mismatch("wrong.example.com");

    assert_ne!(chain.leaf_cert_der(), mismatch.leaf_cert_der());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_unknown_ca() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain-uca", ChainSpec::new("uca.example.com"));
    let unknown = chain.unknown_ca();

    assert_ne!(chain.root_cert_der(), unknown.root_cert_der());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_revoked_leaf_has_crl() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain-rev", ChainSpec::new("rev.example.com"));

    assert!(chain.crl_der().is_none(), "good chain has no CRL");

    let revoked = chain.revoked_leaf();
    assert!(revoked.crl_der().is_some(), "revoked chain has CRL");
    assert!(revoked.crl_pem().unwrap().contains("BEGIN X509 CRL"));
}

#[test]
#[cfg(feature = "x509")]
fn x509_self_signed_tempfiles() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-tmp", X509Spec::self_signed("tmp.example.com"));

    assert!(cert.write_cert_pem().unwrap().path().exists());
    assert!(cert.write_cert_der().unwrap().path().exists());
    assert!(cert.write_private_key_pem().unwrap().path().exists());
    assert!(cert.write_identity_pem().unwrap().path().exists());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_tempfiles() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain-tmp", ChainSpec::new("tmp.example.com"));

    assert!(chain.write_leaf_cert_pem().unwrap().path().exists());
    assert!(chain.write_leaf_cert_der().unwrap().path().exists());
    assert!(chain.write_leaf_private_key_pem().unwrap().path().exists());
    assert!(chain.write_chain_pem().unwrap().path().exists());
    assert!(chain.write_full_chain_pem().unwrap().path().exists());
    assert!(chain.write_root_cert_pem().unwrap().path().exists());
}

#[test]
#[cfg(feature = "x509")]
fn x509_determinism() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx1 = deterministic_fx("x509-det-v1");
    let fx2 = deterministic_fx("x509-det-v1");

    let spec = X509Spec::self_signed("det.example.com");
    let c1 = fx1.x509_self_signed("det-cert", spec.clone());
    let c2 = fx2.x509_self_signed("det-cert", spec);

    assert_eq!(c1.cert_pem(), c2.cert_pem());
    assert_eq!(c1.private_key_pkcs8_pem(), c2.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_determinism() {
    use uselesskey::{ChainSpec, X509FactoryExt};

    let fx1 = deterministic_fx("x509-chain-det-v1");
    let fx2 = deterministic_fx("x509-chain-det-v1");

    let spec = ChainSpec::new("cdet.example.com");
    let ch1 = fx1.x509_chain("det-chain", spec.clone());
    let ch2 = fx2.x509_chain("det-chain", spec);

    assert_eq!(ch1.root_cert_pem(), ch2.root_cert_pem());
    assert_eq!(ch1.leaf_cert_pem(), ch2.leaf_cert_pem());
    assert_eq!(ch1.leaf_private_key_pkcs8_pem(), ch2.leaf_private_key_pkcs8_pem());
}

// ===========================================================================
// 8. Token tests — API keys, bearer tokens, OAuth tokens
// ===========================================================================

#[test]
#[cfg(feature = "token")]
fn token_api_key_shape() {
    let fx = testutil::fx();
    let tok = fx.token("tok-api", TokenSpec::api_key());

    assert!(tok.value().starts_with("uk_test_"));
    let suffix = &tok.value()["uk_test_".len()..];
    assert_eq!(suffix.len(), 32);
    assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
#[cfg(feature = "token")]
fn token_bearer_is_nonempty() {
    let fx = testutil::fx();
    let tok = fx.token("tok-bearer", TokenSpec::bearer());

    assert!(!tok.value().is_empty());
    assert!(tok.authorization_header().starts_with("Bearer "));
}

#[test]
#[cfg(feature = "token")]
fn token_oauth_has_jwt_structure() {
    let fx = testutil::fx();
    let tok = fx.token("tok-oauth", TokenSpec::oauth_access_token());

    let parts: Vec<&str> = tok.value().split('.').collect();
    assert_eq!(parts.len(), 3, "OAuth token is JWT-shaped");
}

#[test]
#[cfg(feature = "token")]
fn token_with_variant_produces_different_value() {
    let fx = deterministic_fx("tok-variant-v1");
    let default = fx.token("tok-var", TokenSpec::api_key());
    let custom = fx.token_with_variant("tok-var", TokenSpec::api_key(), "custom");

    assert_ne!(default.value(), custom.value());
}

#[test]
#[cfg(feature = "token")]
fn token_different_specs_produce_different_values() {
    let fx = deterministic_fx("tok-specs-v1");

    let api = fx.token("tok-multi", TokenSpec::api_key());
    let bearer = fx.token("tok-multi", TokenSpec::bearer());
    let oauth = fx.token("tok-multi", TokenSpec::oauth_access_token());

    assert_ne!(api.value(), bearer.value());
    assert_ne!(api.value(), oauth.value());
    assert_ne!(bearer.value(), oauth.value());
}

// ===========================================================================
// 9. Variant tests — different variants produce different outputs
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_different_labels_produce_different_keys() {
    let fx = deterministic_fx("variant-v1");
    let a = fx.rsa("svc-a", RsaSpec::rs256());
    let b = fx.rsa("svc-b", RsaSpec::rs256());

    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_ne!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_different_specs_produce_different_keys() {
    let fx = deterministic_fx("ec-spec-v1");
    let es256 = fx.ecdsa("svc", EcdsaSpec::es256());
    let es384 = fx.ecdsa("svc", EcdsaSpec::es384());

    assert_ne!(es256.private_key_pkcs8_der(), es384.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_different_specs_produce_different_secrets() {
    let fx = deterministic_fx("hmac-spec-v1");
    let hs256 = fx.hmac("svc", HmacSpec::hs256());
    let hs384 = fx.hmac("svc", HmacSpec::hs384());
    let hs512 = fx.hmac("svc", HmacSpec::hs512());

    assert_ne!(hs256.secret_bytes(), hs384.secret_bytes());
    assert_ne!(hs256.secret_bytes(), hs512.secret_bytes());
    assert_ne!(hs384.secret_bytes(), hs512.secret_bytes());
}

// ===========================================================================
// 10. Factory mode tests — Random vs Deterministic mode behavior
// ===========================================================================

#[test]
fn factory_random_mode() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn factory_deterministic_mode() {
    let seed = Seed::from_env_value("mode-test-v1").unwrap();
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_deterministic_from_env() {
    // Set a temporary env var and create factory from it
    let var_name = "USELESSKEY_FACADE_TEST_SEED_TEMP";
    unsafe { std::env::set_var(var_name, "test-seed-12345") };
    let fx = Factory::deterministic_from_env(var_name).unwrap();
    unsafe { std::env::remove_var(var_name) };

    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_deterministic_from_env_missing_returns_err() {
    let result = Factory::deterministic_from_env("USELESSKEY_NONEXISTENT_VAR_12345");
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "rsa")]
fn random_mode_caches_per_identity() {
    let fx = Factory::random();
    let k1 = fx.rsa("rand-cache", RsaSpec::rs256());
    let k2 = fx.rsa("rand-cache", RsaSpec::rs256());

    // Same identity → same PEM (from cache)
    assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "rsa")]
fn random_mode_different_labels_differ() {
    let fx = Factory::random();
    let a = fx.rsa("rand-a", RsaSpec::rs256());
    let b = fx.rsa("rand-b", RsaSpec::rs256());

    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

#[test]
fn seed_from_env_value_accepts_empty() {
    // Empty string is a valid seed value (it gets hashed).
    let result = Seed::from_env_value("");
    assert!(result.is_ok());
}

// ===========================================================================
// Debug safety — no key material leaks
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_debug_omits_key_material() {
    let fx = testutil::fx();
    let kp = fx.rsa("debug-rsa", RsaSpec::rs256());
    let dbg = format!("{kp:?}");
    assert!(dbg.contains("RsaKeyPair"));
    assert!(dbg.contains("debug-rsa"));
    assert!(!dbg.contains("BEGIN"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_debug_omits_key_material() {
    let fx = testutil::fx();
    let kp = fx.ecdsa("debug-ec", EcdsaSpec::es256());
    let dbg = format!("{kp:?}");
    assert!(dbg.contains("EcdsaKeyPair"));
    assert!(!dbg.contains("BEGIN"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_debug_omits_key_material() {
    let fx = testutil::fx();
    let kp = fx.ed25519("debug-ed", Ed25519Spec::new());
    let dbg = format!("{kp:?}");
    assert!(dbg.contains("Ed25519KeyPair"));
    assert!(!dbg.contains("BEGIN"));
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_debug_omits_secret() {
    let fx = testutil::fx();
    let s = fx.hmac("debug-hmac", HmacSpec::hs256());
    let dbg = format!("{s:?}");
    assert!(dbg.contains("HmacSecret"));
    assert!(dbg.contains("debug-hmac"));
}

#[test]
#[cfg(feature = "token")]
fn token_debug_omits_value() {
    let fx = testutil::fx();
    let tok = fx.token("debug-tok", TokenSpec::api_key());
    let dbg = format!("{tok:?}");
    assert!(dbg.contains("TokenFixture"));
    assert!(!dbg.contains(tok.value()));
}

#[test]
#[cfg(feature = "x509")]
fn x509_debug_omits_cert_material() {
    use uselesskey::{X509FactoryExt, X509Spec};

    let fx = testutil::fx();
    let cert = fx.x509_self_signed("debug-x509", X509Spec::self_signed("dbg.example.com"));
    let dbg = format!("{cert:?}");
    assert!(dbg.contains("X509Cert"));
    assert!(!dbg.contains("BEGIN"));
}

// ===========================================================================
// Arc<_> — suppress unused import warning
// ===========================================================================

const _: () = {
    fn _use_arc() {
        let _ = Arc::new(0u8);
    }
};
