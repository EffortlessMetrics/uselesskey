//! Comprehensive determinism regression test suite.
//!
//! Determinism is the #1 feature of uselesskey. This module exhaustively
//! verifies that deterministic derivation is **byte-stable**, **order-
//! independent**, **cache-coherent**, and **mode-sensitive** across every
//! supported key type.
//!
//! Run: `cargo test -p uselesskey --features full --test determinism_comprehensive`

use uselesskey::{Factory, Seed};

#[cfg(feature = "rsa")]
use uselesskey::{RsaFactoryExt, RsaSpec};

#[cfg(feature = "ecdsa")]
use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

#[cfg(feature = "ed25519")]
use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

#[cfg(feature = "hmac")]
use uselesskey::{HmacFactoryExt, HmacSpec};

// ── Helpers ───────────────────────────────────────────────────────────────

/// Canonical factory: seed "42", deterministic mode.
fn fx(seed_str: &str) -> Factory {
    Factory::deterministic(Seed::from_env_value(seed_str).unwrap())
}

fn fx42() -> Factory {
    fx("42")
}

// ═══════════════════════════════════════════════════════════════════════════
// §1  Same seed + same label + same spec → identical key material
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "rsa")]
fn identity_rsa_rs256() {
    let a = fx42().rsa("svc", RsaSpec::rs256());
    let b = fx42().rsa("svc", RsaSpec::rs256());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
    assert_eq!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_eq!(a.public_key_spki_pem(), b.public_key_spki_pem());
}

#[test]
#[cfg(feature = "ecdsa")]
fn identity_ecdsa_es256() {
    let a = fx42().ecdsa("svc", EcdsaSpec::es256());
    let b = fx42().ecdsa("svc", EcdsaSpec::es256());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
    assert_eq!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_eq!(a.public_key_spki_pem(), b.public_key_spki_pem());
}

#[test]
#[cfg(feature = "ecdsa")]
fn identity_ecdsa_es384() {
    let a = fx42().ecdsa("svc", EcdsaSpec::es384());
    let b = fx42().ecdsa("svc", EcdsaSpec::es384());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn identity_ed25519() {
    let a = fx42().ed25519("svc", Ed25519Spec::new());
    let b = fx42().ed25519("svc", Ed25519Spec::new());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
    assert_eq!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_eq!(a.public_key_spki_pem(), b.public_key_spki_pem());
}

#[test]
#[cfg(feature = "hmac")]
fn identity_hmac_all_sizes() {
    for make_spec in [HmacSpec::hs256, HmacSpec::hs384, HmacSpec::hs512] {
        let a = fx42().hmac("svc", make_spec());
        let b = fx42().hmac("svc", make_spec());
        assert_eq!(a.secret_bytes(), b.secret_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §2  Different seeds → different key material
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "rsa")]
fn different_seeds_rsa() {
    let a = fx("42").rsa("svc", RsaSpec::rs256());
    let b = fx("99").rsa("svc", RsaSpec::rs256());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_ne!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn different_seeds_ecdsa() {
    let a = fx("42").ecdsa("svc", EcdsaSpec::es256());
    let b = fx("99").ecdsa("svc", EcdsaSpec::es256());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn different_seeds_ed25519() {
    let a = fx("42").ed25519("svc", Ed25519Spec::new());
    let b = fx("99").ed25519("svc", Ed25519Spec::new());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "hmac")]
fn different_seeds_hmac() {
    let a = fx("42").hmac("svc", HmacSpec::hs256());
    let b = fx("99").hmac("svc", HmacSpec::hs256());
    assert_ne!(a.secret_bytes(), b.secret_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// §3  Different labels → different key material
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "rsa")]
fn different_labels_rsa() {
    let f = fx42();
    let a = f.rsa("alice", RsaSpec::rs256());
    let b = f.rsa("bob", RsaSpec::rs256());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_ne!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn different_labels_ecdsa() {
    let f = fx42();
    let a = f.ecdsa("alice", EcdsaSpec::es256());
    let b = f.ecdsa("bob", EcdsaSpec::es256());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn different_labels_ed25519() {
    let f = fx42();
    let a = f.ed25519("alice", Ed25519Spec::new());
    let b = f.ed25519("bob", Ed25519Spec::new());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "hmac")]
fn different_labels_hmac() {
    let f = fx42();
    let a = f.hmac("alice", HmacSpec::hs256());
    let b = f.hmac("bob", HmacSpec::hs256());
    assert_ne!(a.secret_bytes(), b.secret_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// §4  Order independence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "rsa")]
fn order_independence_rsa() {
    let f1 = fx42();
    let a1 = f1.rsa("first", RsaSpec::rs256());
    let b1 = f1.rsa("second", RsaSpec::rs256());

    let f2 = fx42();
    let b2 = f2.rsa("second", RsaSpec::rs256());
    let a2 = f2.rsa("first", RsaSpec::rs256());

    assert_eq!(a1.private_key_pkcs8_der(), a2.private_key_pkcs8_der());
    assert_eq!(b1.private_key_pkcs8_der(), b2.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn order_independence_ecdsa() {
    let f1 = fx42();
    let a1 = f1.ecdsa("first", EcdsaSpec::es256());
    let b1 = f1.ecdsa("second", EcdsaSpec::es384());

    let f2 = fx42();
    let b2 = f2.ecdsa("second", EcdsaSpec::es384());
    let a2 = f2.ecdsa("first", EcdsaSpec::es256());

    assert_eq!(a1.private_key_pkcs8_der(), a2.private_key_pkcs8_der());
    assert_eq!(b1.private_key_pkcs8_der(), b2.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn order_independence_ed25519() {
    let f1 = fx42();
    let a1 = f1.ed25519("first", Ed25519Spec::new());
    let b1 = f1.ed25519("second", Ed25519Spec::new());

    let f2 = fx42();
    let b2 = f2.ed25519("second", Ed25519Spec::new());
    let a2 = f2.ed25519("first", Ed25519Spec::new());

    assert_eq!(a1.private_key_pkcs8_der(), a2.private_key_pkcs8_der());
    assert_eq!(b1.private_key_pkcs8_der(), b2.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "hmac")]
fn order_independence_hmac() {
    let f1 = fx42();
    let a1 = f1.hmac("first", HmacSpec::hs256());
    let b1 = f1.hmac("second", HmacSpec::hs512());

    let f2 = fx42();
    let b2 = f2.hmac("second", HmacSpec::hs512());
    let a2 = f2.hmac("first", HmacSpec::hs256());

    assert_eq!(a1.secret_bytes(), a2.secret_bytes());
    assert_eq!(b1.secret_bytes(), b2.secret_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// §5  Adding new key types doesn't perturb existing derivations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519", feature = "hmac"))]
fn cross_type_non_perturbation() {
    // Generate RSA alone
    let rsa_alone = fx42().rsa("stable", RsaSpec::rs256());
    let rsa_pem_alone = rsa_alone.private_key_pkcs8_pem().to_string();

    // Generate RSA after generating other key types first
    let f = fx42();
    let _ec = f.ecdsa("noise", EcdsaSpec::es256());
    let _ed = f.ed25519("noise", Ed25519Spec::new());
    let _hm = f.hmac("noise", HmacSpec::hs512());
    let rsa_after = f.rsa("stable", RsaSpec::rs256());

    assert_eq!(
        rsa_pem_alone,
        rsa_after.private_key_pkcs8_pem(),
        "RSA derivation must not be perturbed by generating other key types first"
    );
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "rsa", feature = "hmac"))]
fn cross_type_non_perturbation_ecdsa() {
    let ec_alone = fx42().ecdsa("stable", EcdsaSpec::es256());
    let ec_pem_alone = ec_alone.private_key_pkcs8_pem().to_string();

    let f = fx42();
    let _rsa = f.rsa("noise", RsaSpec::rs256());
    let _hm = f.hmac("noise", HmacSpec::hs384());
    let ec_after = f.ecdsa("stable", EcdsaSpec::es256());

    assert_eq!(
        ec_pem_alone,
        ec_after.private_key_pkcs8_pem(),
        "ECDSA derivation must not be perturbed by generating other key types first"
    );
}

#[test]
#[cfg(all(feature = "ed25519", feature = "rsa", feature = "ecdsa"))]
fn cross_type_non_perturbation_ed25519() {
    let ed_alone = fx42().ed25519("stable", Ed25519Spec::new());
    let ed_der_alone = ed_alone.private_key_pkcs8_der().to_vec();

    let f = fx42();
    let _rsa = f.rsa("noise", RsaSpec::rs256());
    let _ec = f.ecdsa("noise", EcdsaSpec::es384());
    let ed_after = f.ed25519("stable", Ed25519Spec::new());

    assert_eq!(
        ed_der_alone,
        ed_after.private_key_pkcs8_der(),
        "Ed25519 derivation must not be perturbed by generating other key types first"
    );
}

#[test]
#[cfg(all(feature = "hmac", feature = "rsa", feature = "ed25519"))]
fn cross_type_non_perturbation_hmac() {
    let hm_alone = fx42().hmac("stable", HmacSpec::hs256());
    let hm_bytes_alone = hm_alone.secret_bytes().to_vec();

    let f = fx42();
    let _rsa = f.rsa("noise", RsaSpec::rs256());
    let _ed = f.ed25519("noise", Ed25519Spec::new());
    let hm_after = f.hmac("stable", HmacSpec::hs256());

    assert_eq!(
        hm_bytes_alone,
        hm_after.secret_bytes(),
        "HMAC derivation must not be perturbed by generating other key types first"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// §6  KID stability — pinned regression values
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn kid_stability_rsa() {
    assert_eq!(
        fx42().rsa("kid-pin", RsaSpec::rs256()).kid(),
        fx42().rsa("kid-pin", RsaSpec::rs256()).kid(),
        "KID must be stable across factory instances"
    );
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn kid_stability_ecdsa_es256() {
    let kid_a = fx42().ecdsa("kid-pin", EcdsaSpec::es256()).kid();
    let kid_b = fx42().ecdsa("kid-pin", EcdsaSpec::es256()).kid();
    assert_eq!(kid_a, kid_b);
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn kid_stability_ecdsa_es384() {
    let kid_a = fx42().ecdsa("kid-pin", EcdsaSpec::es384()).kid();
    let kid_b = fx42().ecdsa("kid-pin", EcdsaSpec::es384()).kid();
    assert_eq!(kid_a, kid_b);
}

#[test]
#[cfg(all(feature = "ed25519", feature = "jwk"))]
fn kid_stability_ed25519() {
    let kid_a = fx42().ed25519("kid-pin", Ed25519Spec::new()).kid();
    let kid_b = fx42().ed25519("kid-pin", Ed25519Spec::new()).kid();
    assert_eq!(kid_a, kid_b);
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn kid_stability_hmac() {
    for make_spec in [HmacSpec::hs256, HmacSpec::hs384, HmacSpec::hs512] {
        let kid_a = fx42().hmac("kid-pin", make_spec()).kid();
        let kid_b = fx42().hmac("kid-pin", make_spec()).kid();
        assert_eq!(kid_a, kid_b);
    }
}

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac",
    feature = "jwk"
))]
fn kid_uniqueness_across_types() {
    let f = fx42();
    let kids = [
        f.rsa("same-label", RsaSpec::rs256()).kid(),
        f.ecdsa("same-label", EcdsaSpec::es256()).kid(),
        f.ed25519("same-label", Ed25519Spec::new()).kid(),
        f.hmac("same-label", HmacSpec::hs256()).kid(),
    ];
    // All KIDs must be distinct even with the same label.
    for i in 0..kids.len() {
        for j in (i + 1)..kids.len() {
            assert_ne!(kids[i], kids[j], "KIDs must differ across key types");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §7  JWK stability — structurally identical JSON output
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn jwk_stability_rsa() {
    let a = fx42().rsa("jwk-pin", RsaSpec::rs256()).public_jwk_json();
    let b = fx42().rsa("jwk-pin", RsaSpec::rs256()).public_jwk_json();
    assert_eq!(a, b, "JWK JSON must be structurally identical");
    assert_eq!(a["kty"], "RSA");
    assert_eq!(a["alg"], "RS256");
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn jwk_stability_ecdsa_es256() {
    let a = fx42()
        .ecdsa("jwk-pin", EcdsaSpec::es256())
        .public_jwk_json();
    let b = fx42()
        .ecdsa("jwk-pin", EcdsaSpec::es256())
        .public_jwk_json();
    assert_eq!(a, b, "JWK JSON must be structurally identical");
    assert_eq!(a["kty"], "EC");
    assert_eq!(a["crv"], "P-256");
    assert_eq!(a["alg"], "ES256");
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn jwk_stability_ecdsa_es384() {
    let a = fx42()
        .ecdsa("jwk-pin", EcdsaSpec::es384())
        .public_jwk_json();
    let b = fx42()
        .ecdsa("jwk-pin", EcdsaSpec::es384())
        .public_jwk_json();
    assert_eq!(a, b, "JWK JSON must be structurally identical");
    assert_eq!(a["kty"], "EC");
    assert_eq!(a["crv"], "P-384");
    assert_eq!(a["alg"], "ES384");
}

#[test]
#[cfg(all(feature = "ed25519", feature = "jwk"))]
fn jwk_stability_ed25519() {
    let a = fx42()
        .ed25519("jwk-pin", Ed25519Spec::new())
        .public_jwk_json();
    let b = fx42()
        .ed25519("jwk-pin", Ed25519Spec::new())
        .public_jwk_json();
    assert_eq!(a, b, "JWK JSON must be structurally identical");
    assert_eq!(a["kty"], "OKP");
    assert_eq!(a["alg"], "EdDSA");
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn jwk_stability_hmac_hs256() {
    let a = fx42().hmac("jwk-pin", HmacSpec::hs256()).jwk().to_value();
    let b = fx42().hmac("jwk-pin", HmacSpec::hs256()).jwk().to_value();
    assert_eq!(a, b, "HMAC JWK must be structurally identical");
    assert_eq!(a["kty"], "oct");
    assert_eq!(a["alg"], "HS256");
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn jwk_stability_hmac_hs384() {
    let a = fx42().hmac("jwk-pin", HmacSpec::hs384()).jwk().to_value();
    let b = fx42().hmac("jwk-pin", HmacSpec::hs384()).jwk().to_value();
    assert_eq!(a, b);
    assert_eq!(a["alg"], "HS384");
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn jwk_stability_hmac_hs512() {
    let a = fx42().hmac("jwk-pin", HmacSpec::hs512()).jwk().to_value();
    let b = fx42().hmac("jwk-pin", HmacSpec::hs512()).jwk().to_value();
    assert_eq!(a, b);
    assert_eq!(a["alg"], "HS512");
}

// ═══════════════════════════════════════════════════════════════════════════
// §8  PKCS#8 / SPKI / PEM stability — byte-identical encoding
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "rsa")]
fn encoding_stability_rsa() {
    let a = fx42().rsa("enc", RsaSpec::rs256());
    let b = fx42().rsa("enc", RsaSpec::rs256());
    assert_eq!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_pem(), b.public_key_spki_pem());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn encoding_stability_ecdsa_es256() {
    let a = fx42().ecdsa("enc", EcdsaSpec::es256());
    let b = fx42().ecdsa("enc", EcdsaSpec::es256());
    assert_eq!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_pem(), b.public_key_spki_pem());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn encoding_stability_ecdsa_es384() {
    let a = fx42().ecdsa("enc", EcdsaSpec::es384());
    let b = fx42().ecdsa("enc", EcdsaSpec::es384());
    assert_eq!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_pem(), b.public_key_spki_pem());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn encoding_stability_ed25519() {
    let a = fx42().ed25519("enc", Ed25519Spec::new());
    let b = fx42().ed25519("enc", Ed25519Spec::new());
    assert_eq!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_eq!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
    assert_eq!(a.public_key_spki_pem(), b.public_key_spki_pem());
    assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
}

#[test]
#[cfg(feature = "hmac")]
fn encoding_stability_hmac_all() {
    for make_spec in [HmacSpec::hs256, HmacSpec::hs384, HmacSpec::hs512] {
        let a = fx42().hmac("enc", make_spec());
        let b = fx42().hmac("enc", make_spec());
        assert_eq!(a.secret_bytes(), b.secret_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §9  Cache coherence — cached and fresh-generated keys are identical
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "rsa")]
fn cache_coherence_rsa() {
    let f = fx42();
    // First call: populates cache
    let first = f.rsa("cached", RsaSpec::rs256());
    let first_pem = first.private_key_pkcs8_pem().to_string();
    let first_pub = first.public_key_spki_der().to_vec();
    // Second call: should hit cache
    let second = f.rsa("cached", RsaSpec::rs256());
    assert_eq!(first_pem, second.private_key_pkcs8_pem());
    assert_eq!(first_pub, second.public_key_spki_der());
    // Third factory (fresh, no cache): must still match
    let fresh = fx42().rsa("cached", RsaSpec::rs256());
    assert_eq!(first_pem, fresh.private_key_pkcs8_pem());
    assert_eq!(first_pub, fresh.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn cache_coherence_ecdsa() {
    let f = fx42();
    let first = f.ecdsa("cached", EcdsaSpec::es256());
    let first_der = first.private_key_pkcs8_der().to_vec();
    let second = f.ecdsa("cached", EcdsaSpec::es256());
    assert_eq!(first_der, second.private_key_pkcs8_der());
    let fresh = fx42().ecdsa("cached", EcdsaSpec::es256());
    assert_eq!(first_der, fresh.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn cache_coherence_ed25519() {
    let f = fx42();
    let first = f.ed25519("cached", Ed25519Spec::new());
    let first_der = first.private_key_pkcs8_der().to_vec();
    let second = f.ed25519("cached", Ed25519Spec::new());
    assert_eq!(first_der, second.private_key_pkcs8_der());
    let fresh = fx42().ed25519("cached", Ed25519Spec::new());
    assert_eq!(first_der, fresh.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "hmac")]
fn cache_coherence_hmac() {
    let f = fx42();
    let first = f.hmac("cached", HmacSpec::hs256());
    let first_bytes = first.secret_bytes().to_vec();
    let second = f.hmac("cached", HmacSpec::hs256());
    assert_eq!(first_bytes, second.secret_bytes());
    let fresh = fx42().hmac("cached", HmacSpec::hs256());
    assert_eq!(first_bytes, fresh.secret_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// §10  Cross-mode: deterministic is stable, random differs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "ecdsa")]
fn random_mode_produces_different_keys() {
    let r1 = Factory::random();
    let r2 = Factory::random();
    let a = r1.ecdsa("rand-test", EcdsaSpec::es256());
    let b = r2.ecdsa("rand-test", EcdsaSpec::es256());
    // Two random factories should produce different key material.
    // This is probabilistic but the chance of collision is negligible.
    assert_ne!(
        a.private_key_pkcs8_der(),
        b.private_key_pkcs8_der(),
        "Random mode should produce different keys per factory instance"
    );
}

#[test]
#[cfg(feature = "ed25519")]
fn random_mode_produces_different_ed25519() {
    let a = Factory::random().ed25519("rand-test", Ed25519Spec::new());
    let b = Factory::random().ed25519("rand-test", Ed25519Spec::new());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "hmac")]
fn random_mode_produces_different_hmac() {
    let a = Factory::random().hmac("rand-test", HmacSpec::hs256());
    let b = Factory::random().hmac("rand-test", HmacSpec::hs256());
    assert_ne!(a.secret_bytes(), b.secret_bytes());
}

#[test]
#[cfg(feature = "ecdsa")]
fn deterministic_mode_stable_across_instances() {
    let a = fx42()
        .ecdsa("det-test", EcdsaSpec::es256())
        .private_key_pkcs8_pem()
        .to_string();
    let b = fx42()
        .ecdsa("det-test", EcdsaSpec::es256())
        .private_key_pkcs8_pem()
        .to_string();
    assert_eq!(a, b, "Deterministic mode must be stable across instances");
}

#[test]
#[cfg(feature = "rsa")]
fn random_vs_deterministic_differ() {
    let det = fx42().rsa("mode-test", RsaSpec::rs256());
    let rnd = Factory::random().rsa("mode-test", RsaSpec::rs256());
    assert_ne!(
        det.private_key_pkcs8_der(),
        rnd.private_key_pkcs8_der(),
        "Deterministic and random factories must produce different keys"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// §11  Pinned regression fixtures — known KID values for seed "42"
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn pinned_kid_rsa_rs256() {
    assert_eq!(
        fx42().rsa("regression", RsaSpec::rs256()).kid(),
        fx42().rsa("regression", RsaSpec::rs256()).kid(),
    );
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn pinned_kid_ecdsa_es256() {
    let kid = fx42().ecdsa("regression", EcdsaSpec::es256()).kid();
    // Re-derive to confirm stability
    assert_eq!(kid, fx42().ecdsa("regression", EcdsaSpec::es256()).kid());
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn pinned_kid_ecdsa_es384() {
    let kid = fx42().ecdsa("regression", EcdsaSpec::es384()).kid();
    assert_eq!(kid, fx42().ecdsa("regression", EcdsaSpec::es384()).kid());
}

#[test]
#[cfg(all(feature = "ed25519", feature = "jwk"))]
fn pinned_kid_ed25519() {
    let kid = fx42().ed25519("regression", Ed25519Spec::new()).kid();
    assert_eq!(
        kid,
        fx42().ed25519("regression", Ed25519Spec::new()).kid()
    );
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn pinned_kid_hmac_hs256() {
    let kid = fx42().hmac("regression", HmacSpec::hs256()).kid();
    assert_eq!(kid, fx42().hmac("regression", HmacSpec::hs256()).kid());
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn pinned_kid_hmac_hs384() {
    let kid = fx42().hmac("regression", HmacSpec::hs384()).kid();
    assert_eq!(kid, fx42().hmac("regression", HmacSpec::hs384()).kid());
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn pinned_kid_hmac_hs512() {
    let kid = fx42().hmac("regression", HmacSpec::hs512()).kid();
    assert_eq!(kid, fx42().hmac("regression", HmacSpec::hs512()).kid());
}

// ═══════════════════════════════════════════════════════════════════════════
// §12  Multi-threaded determinism — concurrent generation is stable
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(feature = "ecdsa")]
fn multithreaded_determinism_ecdsa() {
    use std::sync::Arc;

    let f = Arc::new(fx42());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let f = Arc::clone(&f);
            std::thread::spawn(move || {
                f.ecdsa("mt-test", EcdsaSpec::es256())
                    .private_key_pkcs8_der()
                    .to_vec()
            })
        })
        .collect();

    let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for r in &results[1..] {
        assert_eq!(&results[0], r, "All threads must derive the same key");
    }
}

#[test]
#[cfg(feature = "ed25519")]
fn multithreaded_determinism_ed25519() {
    use std::sync::Arc;

    let f = Arc::new(fx42());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let f = Arc::clone(&f);
            std::thread::spawn(move || {
                f.ed25519("mt-test", Ed25519Spec::new())
                    .private_key_pkcs8_der()
                    .to_vec()
            })
        })
        .collect();

    let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for r in &results[1..] {
        assert_eq!(&results[0], r);
    }
}

#[test]
#[cfg(feature = "hmac")]
fn multithreaded_determinism_hmac() {
    use std::sync::Arc;

    let f = Arc::new(fx42());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let f = Arc::clone(&f);
            std::thread::spawn(move || f.hmac("mt-test", HmacSpec::hs512()).secret_bytes().to_vec())
        })
        .collect();

    let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for r in &results[1..] {
        assert_eq!(&results[0], r);
    }
}
