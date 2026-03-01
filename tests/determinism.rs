//! Cross-crate determinism tests.
//!
//! Validates the core invariant: deterministic mode produces the same output
//! for the same seed + identity inputs, regardless of generation order,
//! interleaving with other key types, caching, or threading.

use std::sync::Arc;
use std::thread;

use uselesskey::prelude::*;

fn deterministic_factory() -> Factory {
    Factory::deterministic(Seed::new([0xAB; 32]))
}

// ---------------------------------------------------------------------------
// 1. Order Independence
// ---------------------------------------------------------------------------

#[test]
fn order_independence_rsa() {
    let fx1 = deterministic_factory();
    let a1 = fx1.rsa("alpha", RsaSpec::rs256());
    let b1 = fx1.rsa("bravo", RsaSpec::rs256());
    let c1 = fx1.rsa("charlie", RsaSpec::rs256());

    let fx2 = deterministic_factory();
    let c2 = fx2.rsa("charlie", RsaSpec::rs256());
    let a2 = fx2.rsa("alpha", RsaSpec::rs256());
    let b2 = fx2.rsa("bravo", RsaSpec::rs256());

    assert_eq!(a1.private_key_pkcs8_pem(), a2.private_key_pkcs8_pem());
    assert_eq!(b1.private_key_pkcs8_pem(), b2.private_key_pkcs8_pem());
    assert_eq!(c1.private_key_pkcs8_pem(), c2.private_key_pkcs8_pem());
}

#[test]
fn order_independence_ecdsa() {
    let fx1 = deterministic_factory();
    let a1 = fx1.ecdsa("alpha", EcdsaSpec::es256());
    let b1 = fx1.ecdsa("bravo", EcdsaSpec::es384());

    let fx2 = deterministic_factory();
    let b2 = fx2.ecdsa("bravo", EcdsaSpec::es384());
    let a2 = fx2.ecdsa("alpha", EcdsaSpec::es256());

    assert_eq!(a1.private_key_pkcs8_pem(), a2.private_key_pkcs8_pem());
    assert_eq!(b1.private_key_pkcs8_pem(), b2.private_key_pkcs8_pem());
}

#[test]
fn order_independence_ed25519() {
    let fx1 = deterministic_factory();
    let a1 = fx1.ed25519("alpha", Ed25519Spec::new());
    let b1 = fx1.ed25519("bravo", Ed25519Spec::new());

    let fx2 = deterministic_factory();
    let b2 = fx2.ed25519("bravo", Ed25519Spec::new());
    let a2 = fx2.ed25519("alpha", Ed25519Spec::new());

    assert_eq!(a1.private_key_pkcs8_pem(), a2.private_key_pkcs8_pem());
    assert_eq!(b1.private_key_pkcs8_pem(), b2.private_key_pkcs8_pem());
}

#[test]
fn order_independence_hmac() {
    let fx1 = deterministic_factory();
    let a1 = fx1.hmac("alpha", HmacSpec::hs256());
    let b1 = fx1.hmac("bravo", HmacSpec::hs512());

    let fx2 = deterministic_factory();
    let b2 = fx2.hmac("bravo", HmacSpec::hs512());
    let a2 = fx2.hmac("alpha", HmacSpec::hs256());

    assert_eq!(a1.secret_bytes(), a2.secret_bytes());
    assert_eq!(b1.secret_bytes(), b2.secret_bytes());
}

// ---------------------------------------------------------------------------
// 2. Cross-key-type Independence
// ---------------------------------------------------------------------------

#[test]
fn cross_key_type_independence_rsa_unaffected_by_ecdsa() {
    let fx1 = deterministic_factory();
    let rsa1 = fx1.rsa("service", RsaSpec::rs256());

    let fx2 = deterministic_factory();
    let _ecdsa = fx2.ecdsa("other", EcdsaSpec::es256());
    let _ed25519 = fx2.ed25519("another", Ed25519Spec::new());
    let _hmac = fx2.hmac("yet-another", HmacSpec::hs256());
    let rsa2 = fx2.rsa("service", RsaSpec::rs256());

    assert_eq!(
        rsa1.private_key_pkcs8_pem(),
        rsa2.private_key_pkcs8_pem(),
        "RSA output must not change when other key types are generated first"
    );
}

#[test]
fn cross_key_type_independence_ecdsa_unaffected_by_rsa() {
    let fx1 = deterministic_factory();
    let ec1 = fx1.ecdsa("service", EcdsaSpec::es256());

    let fx2 = deterministic_factory();
    let _rsa = fx2.rsa("other", RsaSpec::rs256());
    let _hmac = fx2.hmac("yet-another", HmacSpec::hs512());
    let ec2 = fx2.ecdsa("service", EcdsaSpec::es256());

    assert_eq!(
        ec1.private_key_pkcs8_pem(),
        ec2.private_key_pkcs8_pem(),
        "ECDSA output must not change when other key types are generated first"
    );
}

#[test]
fn cross_key_type_independence_ed25519_unaffected_by_others() {
    let fx1 = deterministic_factory();
    let ed1 = fx1.ed25519("service", Ed25519Spec::new());

    let fx2 = deterministic_factory();
    let _rsa = fx2.rsa("noise", RsaSpec::rs256());
    let _ecdsa = fx2.ecdsa("noise", EcdsaSpec::es384());
    let ed2 = fx2.ed25519("service", Ed25519Spec::new());

    assert_eq!(
        ed1.private_key_pkcs8_pem(),
        ed2.private_key_pkcs8_pem(),
        "Ed25519 output must not change when other key types are generated first"
    );
}

#[test]
fn cross_key_type_independence_hmac_unaffected_by_others() {
    let fx1 = deterministic_factory();
    let h1 = fx1.hmac("service", HmacSpec::hs256());

    let fx2 = deterministic_factory();
    let _rsa = fx2.rsa("noise", RsaSpec::rs256());
    let _ecdsa = fx2.ecdsa("noise", EcdsaSpec::es256());
    let _ed = fx2.ed25519("noise", Ed25519Spec::new());
    let h2 = fx2.hmac("service", HmacSpec::hs256());

    assert_eq!(
        h1.secret_bytes(),
        h2.secret_bytes(),
        "HMAC output must not change when other key types are generated first"
    );
}

// ---------------------------------------------------------------------------
// 3. Seed Stability
// ---------------------------------------------------------------------------

#[test]
fn seed_stability_rsa_across_factory_instances() {
    let pems: Vec<String> = (0..3)
        .map(|_| {
            let fx = deterministic_factory();
            fx.rsa("stable", RsaSpec::rs256())
                .private_key_pkcs8_pem()
                .to_string()
        })
        .collect();

    assert_eq!(pems[0], pems[1]);
    assert_eq!(pems[1], pems[2]);
}

#[test]
fn seed_stability_ecdsa_across_factory_instances() {
    let pems: Vec<String> = (0..3)
        .map(|_| {
            let fx = deterministic_factory();
            fx.ecdsa("stable", EcdsaSpec::es256())
                .private_key_pkcs8_pem()
                .to_string()
        })
        .collect();

    assert_eq!(pems[0], pems[1]);
    assert_eq!(pems[1], pems[2]);
}

#[test]
fn seed_stability_ed25519_across_factory_instances() {
    let pems: Vec<String> = (0..3)
        .map(|_| {
            let fx = deterministic_factory();
            fx.ed25519("stable", Ed25519Spec::new())
                .private_key_pkcs8_pem()
                .to_string()
        })
        .collect();

    assert_eq!(pems[0], pems[1]);
    assert_eq!(pems[1], pems[2]);
}

#[test]
fn seed_stability_hmac_across_factory_instances() {
    let secrets: Vec<Vec<u8>> = (0..3)
        .map(|_| {
            let fx = deterministic_factory();
            fx.hmac("stable", HmacSpec::hs256()).secret_bytes().to_vec()
        })
        .collect();

    assert_eq!(secrets[0], secrets[1]);
    assert_eq!(secrets[1], secrets[2]);
}

#[test]
fn different_seeds_produce_different_output() {
    let fx_a = Factory::deterministic(Seed::new([0xAA; 32]));
    let fx_b = Factory::deterministic(Seed::new([0xBB; 32]));

    assert_ne!(
        fx_a.ecdsa("same", EcdsaSpec::es256())
            .private_key_pkcs8_pem(),
        fx_b.ecdsa("same", EcdsaSpec::es256())
            .private_key_pkcs8_pem(),
    );
}

// ---------------------------------------------------------------------------
// 4. Cache Transparency
// ---------------------------------------------------------------------------

#[test]
fn cache_transparency_rsa() {
    let fx = deterministic_factory();

    let first = fx.rsa("cached", RsaSpec::rs256());
    let cached = fx.rsa("cached", RsaSpec::rs256());

    assert_eq!(
        first.private_key_pkcs8_pem(),
        cached.private_key_pkcs8_pem()
    );
    assert_eq!(first.public_key_spki_pem(), cached.public_key_spki_pem());

    // Compare against a fresh factory (no cache)
    let fx2 = deterministic_factory();
    let fresh = fx2.rsa("cached", RsaSpec::rs256());
    assert_eq!(
        first.private_key_pkcs8_pem(),
        fresh.private_key_pkcs8_pem(),
        "cached and fresh generation must be identical"
    );
}

#[test]
fn cache_transparency_ecdsa() {
    let fx = deterministic_factory();

    let first = fx.ecdsa("cached", EcdsaSpec::es256());
    let cached = fx.ecdsa("cached", EcdsaSpec::es256());

    assert_eq!(
        first.private_key_pkcs8_der(),
        cached.private_key_pkcs8_der()
    );

    let fx2 = deterministic_factory();
    let fresh = fx2.ecdsa("cached", EcdsaSpec::es256());
    assert_eq!(first.private_key_pkcs8_der(), fresh.private_key_pkcs8_der());
}

#[test]
fn cache_transparency_ed25519() {
    let fx = deterministic_factory();

    let first = fx.ed25519("cached", Ed25519Spec::new());
    let cached = fx.ed25519("cached", Ed25519Spec::new());

    assert_eq!(
        first.private_key_pkcs8_der(),
        cached.private_key_pkcs8_der()
    );

    let fx2 = deterministic_factory();
    let fresh = fx2.ed25519("cached", Ed25519Spec::new());
    assert_eq!(first.private_key_pkcs8_der(), fresh.private_key_pkcs8_der());
}

#[test]
fn cache_transparency_hmac() {
    let fx = deterministic_factory();

    let first = fx.hmac("cached", HmacSpec::hs256());
    let cached = fx.hmac("cached", HmacSpec::hs256());

    assert_eq!(first.secret_bytes(), cached.secret_bytes());

    let fx2 = deterministic_factory();
    let fresh = fx2.hmac("cached", HmacSpec::hs256());
    assert_eq!(first.secret_bytes(), fresh.secret_bytes());
}

// ---------------------------------------------------------------------------
// 5. Label Sensitivity
// ---------------------------------------------------------------------------

#[test]
fn label_sensitivity_rsa() {
    let fx = deterministic_factory();
    let a = fx.rsa("label-a", RsaSpec::rs256());
    let b = fx.rsa("label-b", RsaSpec::rs256());

    assert_ne!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
    assert_ne!(a.public_key_spki_pem(), b.public_key_spki_pem());
}

#[test]
fn label_sensitivity_ecdsa() {
    let fx = deterministic_factory();
    let a = fx.ecdsa("label-a", EcdsaSpec::es256());
    let b = fx.ecdsa("label-b", EcdsaSpec::es256());

    assert_ne!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
}

#[test]
fn label_sensitivity_ed25519() {
    let fx = deterministic_factory();
    let a = fx.ed25519("label-a", Ed25519Spec::new());
    let b = fx.ed25519("label-b", Ed25519Spec::new());

    assert_ne!(a.private_key_pkcs8_pem(), b.private_key_pkcs8_pem());
}

#[test]
fn label_sensitivity_hmac() {
    let fx = deterministic_factory();
    let a = fx.hmac("label-a", HmacSpec::hs256());
    let b = fx.hmac("label-b", HmacSpec::hs256());

    assert_ne!(a.secret_bytes(), b.secret_bytes());
}

// ---------------------------------------------------------------------------
// 6. Spec Sensitivity
// ---------------------------------------------------------------------------

#[test]
fn spec_sensitivity_rsa_different_bit_sizes() {
    let fx = deterministic_factory();
    let rs256 = fx.rsa("service", RsaSpec::rs256());
    let rs4096 = fx.rsa("service", RsaSpec::new(4096));

    assert_ne!(
        rs256.private_key_pkcs8_der(),
        rs4096.private_key_pkcs8_der(),
        "different RSA bit sizes must produce different keys"
    );
}

#[test]
fn spec_sensitivity_ecdsa_different_curves() {
    let fx = deterministic_factory();
    let es256 = fx.ecdsa("service", EcdsaSpec::es256());
    let es384 = fx.ecdsa("service", EcdsaSpec::es384());

    assert_ne!(
        es256.private_key_pkcs8_der(),
        es384.private_key_pkcs8_der(),
        "different ECDSA curves must produce different keys"
    );
}

#[test]
fn spec_sensitivity_hmac_different_sizes() {
    let fx = deterministic_factory();
    let hs256 = fx.hmac("service", HmacSpec::hs256());
    let hs512 = fx.hmac("service", HmacSpec::hs512());

    assert_ne!(
        hs256.secret_bytes(),
        hs512.secret_bytes(),
        "different HMAC specs must produce different secrets"
    );
}

// ---------------------------------------------------------------------------
// 7. Variant Sensitivity
// ---------------------------------------------------------------------------

#[test]
fn variant_sensitivity_rsa_mismatch() {
    let fx = deterministic_factory();
    let kp = fx.rsa("service", RsaSpec::rs256());

    let normal_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();

    assert_ne!(
        normal_pub,
        &mismatched_pub[..],
        "mismatched variant must produce a different public key"
    );
}

#[test]
fn variant_sensitivity_ecdsa_mismatch() {
    let fx = deterministic_factory();
    let kp = fx.ecdsa("service", EcdsaSpec::es256());

    let normal_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();

    assert_ne!(
        normal_pub,
        &mismatched_pub[..],
        "mismatched variant must produce a different public key"
    );
}

#[test]
fn variant_sensitivity_ed25519_mismatch() {
    let fx = deterministic_factory();
    let kp = fx.ed25519("service", Ed25519Spec::new());

    let normal_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();

    assert_ne!(
        normal_pub,
        &mismatched_pub[..],
        "mismatched variant must produce a different public key"
    );
}

#[test]
fn variant_sensitivity_corrupt_pem_differs_from_normal() {
    let fx = deterministic_factory();
    let kp = fx.rsa("service", RsaSpec::rs256());

    let normal = kp.private_key_pkcs8_pem();
    let corrupt = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);

    assert_ne!(normal, corrupt);
}

// ---------------------------------------------------------------------------
// 8. Multi-thread Determinism
// ---------------------------------------------------------------------------

#[test]
fn multi_thread_determinism_shared_factory() {
    let fx = deterministic_factory();

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                fx.ecdsa("threaded", EcdsaSpec::es256())
                    .private_key_pkcs8_pem()
                    .to_string()
            })
        })
        .collect();

    let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for r in &results[1..] {
        assert_eq!(&results[0], r, "all threads must produce the same key");
    }
}

#[test]
fn multi_thread_determinism_separate_factories() {
    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                let fx = deterministic_factory();
                (
                    fx.rsa("threaded-rsa", RsaSpec::rs256())
                        .private_key_pkcs8_pem()
                        .to_string(),
                    fx.ecdsa("threaded-ec", EcdsaSpec::es256())
                        .private_key_pkcs8_pem()
                        .to_string(),
                    fx.ed25519("threaded-ed", Ed25519Spec::new())
                        .private_key_pkcs8_pem()
                        .to_string(),
                    fx.hmac("threaded-hmac", HmacSpec::hs256())
                        .secret_bytes()
                        .to_vec(),
                )
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for r in &results[1..] {
        assert_eq!(results[0].0, r.0, "RSA must be identical across threads");
        assert_eq!(results[0].1, r.1, "ECDSA must be identical across threads");
        assert_eq!(
            results[0].2, r.2,
            "Ed25519 must be identical across threads"
        );
        assert_eq!(results[0].3, r.3, "HMAC must be identical across threads");
    }
}

#[test]
fn multi_thread_determinism_interleaved_key_types() {
    let reference = {
        let fx = deterministic_factory();
        Arc::new((
            fx.rsa("mt-rsa", RsaSpec::rs256())
                .private_key_pkcs8_pem()
                .to_string(),
            fx.ecdsa("mt-ec", EcdsaSpec::es256())
                .private_key_pkcs8_pem()
                .to_string(),
            fx.ed25519("mt-ed", Ed25519Spec::new())
                .private_key_pkcs8_pem()
                .to_string(),
        ))
    };

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let _reference = Arc::clone(&reference);
            thread::spawn(move || {
                let fx = deterministic_factory();
                // Interleave in different orders per thread
                match i % 3 {
                    0 => {
                        let r = fx
                            .rsa("mt-rsa", RsaSpec::rs256())
                            .private_key_pkcs8_pem()
                            .to_string();
                        let e = fx
                            .ecdsa("mt-ec", EcdsaSpec::es256())
                            .private_key_pkcs8_pem()
                            .to_string();
                        let d = fx
                            .ed25519("mt-ed", Ed25519Spec::new())
                            .private_key_pkcs8_pem()
                            .to_string();
                        (r, e, d)
                    }
                    1 => {
                        let d = fx
                            .ed25519("mt-ed", Ed25519Spec::new())
                            .private_key_pkcs8_pem()
                            .to_string();
                        let r = fx
                            .rsa("mt-rsa", RsaSpec::rs256())
                            .private_key_pkcs8_pem()
                            .to_string();
                        let e = fx
                            .ecdsa("mt-ec", EcdsaSpec::es256())
                            .private_key_pkcs8_pem()
                            .to_string();
                        (r, e, d)
                    }
                    _ => {
                        let e = fx
                            .ecdsa("mt-ec", EcdsaSpec::es256())
                            .private_key_pkcs8_pem()
                            .to_string();
                        let d = fx
                            .ed25519("mt-ed", Ed25519Spec::new())
                            .private_key_pkcs8_pem()
                            .to_string();
                        let r = fx
                            .rsa("mt-rsa", RsaSpec::rs256())
                            .private_key_pkcs8_pem()
                            .to_string();
                        (r, e, d)
                    }
                }
            })
        })
        .collect();

    for h in handles {
        let (r, e, d) = h.join().unwrap();
        assert_eq!(reference.0, r, "RSA must match reference across threads");
        assert_eq!(reference.1, e, "ECDSA must match reference across threads");
        assert_eq!(
            reference.2, d,
            "Ed25519 must match reference across threads"
        );
    }
}
