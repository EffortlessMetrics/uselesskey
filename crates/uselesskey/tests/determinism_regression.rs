//! Determinism regression tests.
//!
//! These tests lock down the exact byte-level output of deterministic
//! derivation. Every hardcoded value was computed from `Seed::from_env_value("42")`
//! and must never change across releases — any change would silently break
//! downstream snapshot tests that depend on derivation stability.
//!
//! Run: `cargo test -p uselesskey --features full --test determinism_regression`

use uselesskey::{
    EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt, HmacSpec,
    RsaFactoryExt, RsaSpec, Seed,
};

/// Canonical factory: seed "42", deterministic mode.
fn fx42() -> Factory {
    let seed = Seed::from_env_value("42").unwrap();
    Factory::deterministic(seed)
}

// ── 1. Seed derivation stability ──────────────────────────────────────────

#[test]
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
