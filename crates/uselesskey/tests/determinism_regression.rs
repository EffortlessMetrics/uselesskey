//! Determinism regression tests.
//!
//! These tests lock down the exact byte-level output of deterministic
//! derivation. Every hardcoded value was computed from `Seed::from_env_value("42")`
//! and must never change across releases — any change would silently break
//! downstream snapshot tests that depend on derivation stability.
//!
//! Run: `cargo test -p uselesskey --features full --test determinism_regression`

use uselesskey::{Factory, Seed};

#[cfg(feature = "rsa")]
use uselesskey::{RsaFactoryExt, RsaSpec};

#[cfg(feature = "ecdsa")]
use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

#[cfg(feature = "ed25519")]
use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

#[cfg(feature = "hmac")]
use uselesskey::{HmacFactoryExt, HmacSpec};

#[cfg(feature = "token")]
use uselesskey::{TokenFactoryExt, TokenSpec};

/// Canonical factory: seed "42", deterministic mode.
fn fx42() -> Factory {
    let seed = Seed::from_env_value("42").unwrap();
    Factory::deterministic(seed)
}

// ── 1. Seed derivation stability ──────────────────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn rsa_kid_regression() {
    let fx = fx42();
    let keys = fx.rsa("test", RsaSpec::rs256());
    assert_eq!(
        keys.kid(),
        "xlKrVthYc071284I",
        "RSA RS256 KID for seed 42 + label \"test\" must be stable across releases"
    );
}

// ── 2. Order independence ─────────────────────────────────────────────────

#[test]
#[cfg(feature = "rsa")]
fn order_independence_rsa() {
    let fx = fx42();

    // Generate A then B
    let a1 = fx.rsa("alpha", RsaSpec::rs256());
    let b1 = fx.rsa("beta", RsaSpec::rs256());

    // New factory, generate B then A
    let fx2 = fx42();
    let b2 = fx2.rsa("beta", RsaSpec::rs256());
    let a2 = fx2.rsa("alpha", RsaSpec::rs256());

    assert_eq!(a1.private_key_pkcs8_pem(), a2.private_key_pkcs8_pem());
    assert_eq!(b1.private_key_pkcs8_pem(), b2.private_key_pkcs8_pem());
}

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa"))]
fn order_independence_mixed_algorithms() {
    let fx = fx42();
    let rsa1 = fx.rsa("label", RsaSpec::rs256());
    let ec1 = fx.ecdsa("label", EcdsaSpec::es256());

    let fx2 = fx42();
    let ec2 = fx2.ecdsa("label", EcdsaSpec::es256());
    let rsa2 = fx2.rsa("label", RsaSpec::rs256());

    assert_eq!(rsa1.private_key_pkcs8_pem(), rsa2.private_key_pkcs8_pem());
    assert_eq!(ec1.private_key_pkcs8_pem(), ec2.private_key_pkcs8_pem());
}

// ── 3. Cross-run stability ────────────────────────────────────────────────

#[test]
#[cfg(feature = "rsa")]
fn rsa_pem_cross_run_stability() {
    let fx = fx42();
    let keys = fx.rsa("test", RsaSpec::rs256());
    let pem = keys.private_key_pkcs8_pem();

    // The PEM length must be stable.
    assert_eq!(pem.len(), 1704, "RSA RS256 PEM length must be stable");

    // The first line of base64 body is a fingerprint of the encoded key.
    let line2 = pem.lines().nth(1).unwrap();
    assert_eq!(
        line2, "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDp8O8xi/W4lQUc",
        "RSA RS256 PEM body must be byte-identical across runs"
    );
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_pem_cross_run_stability() {
    let fx = fx42();
    let keys1 = fx.ecdsa("test", EcdsaSpec::es256());
    let pem1 = keys1.private_key_pkcs8_pem();

    let fx2 = fx42();
    let keys2 = fx2.ecdsa("test", EcdsaSpec::es256());
    let pem2 = keys2.private_key_pkcs8_pem();
    assert_eq!(
        pem1, pem2,
        "ECDSA PEM must be identical across factory instances"
    );
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_pem_cross_run_stability() {
    let fx = fx42();
    let keys1 = fx.ed25519("test", Ed25519Spec::new());
    let pem1 = keys1.private_key_pkcs8_pem();

    let fx2 = fx42();
    let keys2 = fx2.ed25519("test", Ed25519Spec::new());
    let pem2 = keys2.private_key_pkcs8_pem();
    assert_eq!(
        pem1, pem2,
        "Ed25519 PEM must be identical across factory instances"
    );
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_bytes_cross_run_stability() {
    let fx = fx42();
    let s1 = fx.hmac("test", HmacSpec::hs256());
    let fx2 = fx42();
    let s2 = fx2.hmac("test", HmacSpec::hs256());
    assert_eq!(
        s1.secret_bytes(),
        s2.secret_bytes(),
        "HMAC secret bytes must be identical across factory instances"
    );
}

// ── 4. Variant isolation ──────────────────────────────────────────────────

#[test]
#[cfg(feature = "rsa")]
fn variant_isolation_default_vs_mismatch() {
    let fx = fx42();
    let default_key = fx.rsa("variant-test", RsaSpec::rs256());
    let mismatch_pub = default_key.mismatched_public_key_spki_der();

    // The mismatched public key must differ from the real public key.
    assert_ne!(
        default_key.public_key_spki_der(),
        mismatch_pub,
        "mismatched public key must differ from the default public key"
    );

    // But both must be non-empty valid-looking DER.
    assert!(!default_key.public_key_spki_der().is_empty());
    assert!(!mismatch_pub.is_empty());
}

// ── 5. Spec sensitivity ──────────────────────────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn spec_sensitivity_rsa_bit_sizes() {
    let fx = fx42();
    let k2048 = fx.rsa("test", RsaSpec::rs256());
    let k3072 = fx.rsa("test", RsaSpec::new(3072));
    let k4096 = fx.rsa("test", RsaSpec::new(4096));

    // Same seed + same label but different specs → different KIDs.
    let kids = [k2048.kid(), k3072.kid(), k4096.kid()];
    assert_eq!(kids[0], "xlKrVthYc071284I");
    assert_eq!(kids[1], "5qYvnTIlSq2V_Z78");
    assert_eq!(kids[2], "e23gOS1i5kgaIYl1");

    // Sanity: all three are unique.
    assert_ne!(kids[0], kids[1]);
    assert_ne!(kids[1], kids[2]);
    assert_ne!(kids[0], kids[2]);
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn spec_sensitivity_ecdsa_curves() {
    let fx = fx42();
    let p256 = fx.ecdsa("test", EcdsaSpec::es256());
    let p384 = fx.ecdsa("test", EcdsaSpec::es384());

    assert_ne!(
        p256.kid(),
        p384.kid(),
        "P-256 and P-384 must produce different KIDs from the same seed+label"
    );
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn spec_sensitivity_hmac_lengths() {
    let fx = fx42();
    let hs256 = fx.hmac("test", HmacSpec::hs256());
    let hs384 = fx.hmac("test", HmacSpec::hs384());
    let hs512 = fx.hmac("test", HmacSpec::hs512());

    assert_ne!(hs256.kid(), hs384.kid());
    assert_ne!(hs384.kid(), hs512.kid());
    assert_ne!(hs256.kid(), hs512.kid());
}

// ── 6. Multi-algorithm stability ─────────────────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519", feature = "hmac", feature = "jwk"))]
fn multi_algorithm_kid_regression() {
    let fx = fx42();
    let rsa = fx.rsa("multi", RsaSpec::rs256());
    let ecdsa = fx.ecdsa("multi", EcdsaSpec::es256());
    let ed25519 = fx.ed25519("multi", Ed25519Spec::new());
    let hmac = fx.hmac("multi", HmacSpec::hs256());

    assert_eq!(rsa.kid(), "ZiddOV2ePSrf3wFF", "RSA KID regression");
    assert_eq!(ecdsa.kid(), "w9u8SHl-97v4t-ZC", "ECDSA KID regression");
    assert_eq!(ed25519.kid(), "fPrxQYN1irgb0AZu", "Ed25519 KID regression");
    assert_eq!(hmac.kid(), "vL4_UQjjdBPSwc6r", "HMAC KID regression");
}

// ── 7. Factory isolation ──────────────────────────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn factory_isolation_different_seeds() {
    let fx42 = {
        let seed = Seed::from_env_value("42").unwrap();
        Factory::deterministic(seed)
    };
    let fx99 = {
        let seed = Seed::from_env_value("99").unwrap();
        Factory::deterministic(seed)
    };

    let k42 = fx42.rsa("same-label", RsaSpec::rs256());
    let k99 = fx99.rsa("same-label", RsaSpec::rs256());

    assert_eq!(k42.kid(), "3YgkkBKJ80e1gKjP", "Seed 42 KID regression");
    assert_eq!(k99.kid(), "6nOfKTzK-dlUJ1Ue", "Seed 99 KID regression");
    assert_ne!(
        k42.private_key_pkcs8_pem(),
        k99.private_key_pkcs8_pem(),
        "Different seeds must produce different keys for the same label"
    );
}

// ── 8. Factory equality ──────────────────────────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn factory_equality_same_seed() {
    let fx_a = fx42();
    let fx_b = fx42();

    let ka = fx_a.rsa("shared", RsaSpec::rs256());
    let kb = fx_b.rsa("shared", RsaSpec::rs256());

    assert_eq!(
        ka.private_key_pkcs8_pem(),
        kb.private_key_pkcs8_pem(),
        "Two factories with the same seed must produce identical keys"
    );
    assert_eq!(ka.kid(), kb.kid());
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "ed25519", feature = "hmac"))]
fn factory_equality_all_algorithms() {
    let fx_a = fx42();
    let fx_b = fx42();

    assert_eq!(
        fx_a.ecdsa("eq", EcdsaSpec::es256()).private_key_pkcs8_pem(),
        fx_b.ecdsa("eq", EcdsaSpec::es256()).private_key_pkcs8_pem(),
    );
    assert_eq!(
        fx_a.ed25519("eq", Ed25519Spec::new())
            .private_key_pkcs8_pem(),
        fx_b.ed25519("eq", Ed25519Spec::new())
            .private_key_pkcs8_pem(),
    );
    assert_eq!(
        fx_a.hmac("eq", HmacSpec::hs256()).secret_bytes(),
        fx_b.hmac("eq", HmacSpec::hs256()).secret_bytes(),
    );
}

// ── 9. PEM header pinning ─────────────────────────────────────────────────

#[test]
#[cfg(feature = "rsa")]
fn determinism_pem_header_rsa() {
    let fx = fx42();
    let kp = fx.rsa("test", RsaSpec::rs256());
    assert!(kp.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(kp.public_key_spki_pem().starts_with("-----BEGIN PUBLIC KEY-----"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn determinism_pem_header_ecdsa() {
    let fx = fx42();
    let kp = fx.ecdsa("test", EcdsaSpec::es256());
    assert!(kp.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(kp.public_key_spki_pem().starts_with("-----BEGIN PUBLIC KEY-----"));
}

#[test]
#[cfg(feature = "ed25519")]
fn determinism_pem_header_ed25519() {
    let fx = fx42();
    let kp = fx.ed25519("test", Ed25519Spec::new());
    assert!(kp.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(kp.public_key_spki_pem().starts_with("-----BEGIN PUBLIC KEY-----"));
}

// ── 10. DER length pinning ────────────────────────────────────────────────

#[test]
#[cfg(feature = "rsa")]
fn determinism_der_length_rsa_rs256() {
    let fx = fx42();
    let kp = fx.rsa("test", RsaSpec::rs256());
    assert_eq!(kp.private_key_pkcs8_der().len(), 1218);
    assert_eq!(kp.public_key_spki_der().len(), 294);
}

#[test]
#[cfg(feature = "ecdsa")]
fn determinism_der_length_ecdsa_es256() {
    let fx = fx42();
    let kp = fx.ecdsa("test", EcdsaSpec::es256());
    assert_eq!(kp.private_key_pkcs8_der().len(), 138);
    assert_eq!(kp.public_key_spki_der().len(), 91);
}

#[test]
#[cfg(feature = "ed25519")]
fn determinism_der_length_ed25519() {
    let fx = fx42();
    let kp = fx.ed25519("test", Ed25519Spec::new());
    assert_eq!(kp.private_key_pkcs8_der().len(), 83);
    assert_eq!(kp.public_key_spki_der().len(), 44);
}

#[test]
#[cfg(feature = "hmac")]
fn determinism_secret_length_hmac() {
    let fx = fx42();
    assert_eq!(fx.hmac("test", HmacSpec::hs256()).secret_bytes().len(), 32);
    assert_eq!(fx.hmac("test", HmacSpec::hs384()).secret_bytes().len(), 48);
    assert_eq!(fx.hmac("test", HmacSpec::hs512()).secret_bytes().len(), 64);
}

// ── 11. JWK field pinning ─────────────────────────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn determinism_jwk_fields_rsa() {
    let fx = fx42();
    let jwk = fx.rsa("test", RsaSpec::rs256()).public_jwk_json();
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["alg"], "RS256");
    assert_eq!(jwk["kid"], "xlKrVthYc071284I");
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn determinism_jwk_fields_ecdsa() {
    let fx = fx42();
    let jwk = fx.ecdsa("test", EcdsaSpec::es256()).public_jwk_json();
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["alg"], "ES256");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["kid"], "1W3Ra1uSb_RYpHbR");
}

#[test]
#[cfg(all(feature = "ed25519", feature = "jwk"))]
fn determinism_jwk_fields_ed25519() {
    let fx = fx42();
    let jwk = fx.ed25519("test", Ed25519Spec::new()).public_jwk_json();
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["alg"], "EdDSA");
    assert_eq!(jwk["kid"], "-8aYg4DZAzxCruMR");
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn determinism_jwk_fields_hmac() {
    let fx = fx42();
    let jwk = fx.hmac("test", HmacSpec::hs256()).jwk().to_value();
    assert_eq!(jwk["kty"], "oct");
    assert_eq!(jwk["alg"], "HS256");
    assert_eq!(jwk["kid"], "1L5s00uGtPf4fgJK");
}

// ── 12. Token determinism ─────────────────────────────────────────────────

#[test]
#[cfg(feature = "token")]
fn determinism_cross_run_token() {
    let fx_a = fx42();
    let fx_b = fx42();
    let a = fx_a.token("cross", TokenSpec::api_key());
    let b = fx_b.token("cross", TokenSpec::api_key());
    assert_eq!(a.value(), b.value());
}

#[test]
#[cfg(feature = "token")]
fn determinism_token_api_key_pinned() {
    let fx = fx42();
    let tok = fx.token("test", TokenSpec::api_key());
    assert_eq!(tok.value(), "uk_test_3wyUzlnc8lS8d3H4khcY0I4zoTtq52Aa");
}

#[test]
#[cfg(feature = "token")]
fn determinism_variant_independence_token() {
    let fx = fx42();
    let good = fx.token("vtok", TokenSpec::api_key());
    let alt = fx.token_with_variant("vtok", TokenSpec::api_key(), "alt");
    assert_ne!(good.value(), alt.value());
    // The good variant is stable regardless of alt generation.
    let good2 = fx.token("vtok", TokenSpec::api_key());
    assert_eq!(good.value(), good2.value());
}

#[test]
#[cfg(feature = "token")]
fn determinism_seed_sensitivity_token() {
    let fx_42 = fx42();
    let fx_43 = Factory::deterministic(Seed::from_env_value("43").unwrap());
    let t42 = fx_42.token("test", TokenSpec::api_key()).value().to_string();
    let t43 = fx_43.token("test", TokenSpec::api_key()).value().to_string();
    assert_ne!(t42, t43);
}

// ── 13. Seed sensitivity ──────────────────────────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn determinism_seed_sensitivity_rsa() {
    let fx_42 = fx42();
    let fx_43 = Factory::deterministic(Seed::from_env_value("43").unwrap());
    let kid42 = fx_42.rsa("test", RsaSpec::rs256()).kid();
    let kid43 = fx_43.rsa("test", RsaSpec::rs256()).kid();
    assert_eq!(kid42, "xlKrVthYc071284I");
    assert_eq!(kid43, "L37RYoD-QRMS-YDL");
    assert_ne!(kid42, kid43);
}

#[test]
#[cfg(feature = "ecdsa")]
fn determinism_seed_sensitivity_ecdsa() {
    let fx_42 = fx42();
    let fx_43 = Factory::deterministic(Seed::from_env_value("43").unwrap());
    let pem42 = fx_42.ecdsa("test", EcdsaSpec::es256()).private_key_pkcs8_pem().to_string();
    let pem43 = fx_43.ecdsa("test", EcdsaSpec::es256()).private_key_pkcs8_pem().to_string();
    assert_ne!(pem42, pem43);
}

#[test]
#[cfg(feature = "ed25519")]
fn determinism_seed_sensitivity_ed25519() {
    let fx_42 = fx42();
    let fx_43 = Factory::deterministic(Seed::from_env_value("43").unwrap());
    let der42 = fx_42.ed25519("test", Ed25519Spec::new()).private_key_pkcs8_der().to_vec();
    let der43 = fx_43.ed25519("test", Ed25519Spec::new()).private_key_pkcs8_der().to_vec();
    assert_ne!(der42, der43);
}

#[test]
#[cfg(feature = "hmac")]
fn determinism_seed_sensitivity_hmac() {
    let fx_42 = fx42();
    let fx_43 = Factory::deterministic(Seed::from_env_value("43").unwrap());
    let s42 = fx_42.hmac("test", HmacSpec::hs256()).secret_bytes().to_vec();
    let s43 = fx_43.hmac("test", HmacSpec::hs256()).secret_bytes().to_vec();
    assert_ne!(s42, s43);
}

// ── 14. HMAC secret bytes pinning ─────────────────────────────────────────

#[test]
#[cfg(feature = "hmac")]
fn determinism_hmac_secret_bytes_prefix_pinned() {
    let fx = fx42();
    let bytes = fx.hmac("test", HmacSpec::hs256()).secret_bytes().to_vec();
    assert_eq!(bytes[0], 0x97);
    assert_eq!(bytes[1], 0x72);
    assert_eq!(bytes[2], 0xd8);
    assert_eq!(bytes[3], 0xe2);
}

// ── 15. Order independence across key types ───────────────────────────────

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
fn determinism_order_independence_all_key_types() {
    // Generate in order: RSA, ECDSA, Ed25519
    let fx1 = fx42();
    let rsa_first = fx1.rsa("alpha", RsaSpec::rs256());
    let ecdsa_first = fx1.ecdsa("beta", EcdsaSpec::es256());
    let ed_first = fx1.ed25519("gamma", Ed25519Spec::new());

    // Generate in reverse order: Ed25519, ECDSA, RSA
    let fx2 = fx42();
    let ed_second = fx2.ed25519("gamma", Ed25519Spec::new());
    let ecdsa_second = fx2.ecdsa("beta", EcdsaSpec::es256());
    let rsa_second = fx2.rsa("alpha", RsaSpec::rs256());

    assert_eq!(rsa_first.private_key_pkcs8_pem(), rsa_second.private_key_pkcs8_pem());
    assert_eq!(ecdsa_first.private_key_pkcs8_pem(), ecdsa_second.private_key_pkcs8_pem());
    assert_eq!(ed_first.private_key_pkcs8_pem(), ed_second.private_key_pkcs8_pem());
}

#[test]
#[cfg(all(feature = "hmac", feature = "token"))]
fn determinism_order_independence_hmac_token() {
    let fx1 = fx42();
    let hmac_first = fx1.hmac("key", HmacSpec::hs256());
    let tok_first = fx1.token("tok", TokenSpec::bearer());

    let fx2 = fx42();
    let tok_second = fx2.token("tok", TokenSpec::bearer());
    let hmac_second = fx2.hmac("key", HmacSpec::hs256());

    assert_eq!(hmac_first.secret_bytes(), hmac_second.secret_bytes());
    assert_eq!(tok_first.value(), tok_second.value());
}
