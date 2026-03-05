//! Multi-algorithm isolation tests.
//!
//! Verifies that generating keys of different algorithm types from the
//! same factory does not interfere with each other, and that generation
//! order does not affect outputs.

#![cfg(feature = "full")]

mod testutil;

use testutil::fx;
use uselesskey::prelude::*;

/// Generating RSA, ECDSA, and Ed25519 from the same factory produces
/// distinct, algorithm-appropriate keys.
#[test]
fn different_algorithms_produce_independent_keys() {
    let fx = fx();
    let rsa = fx.rsa("multi-alg", RsaSpec::rs256());
    let ecdsa = fx.ecdsa("multi-alg", EcdsaSpec::es256());
    let ed = fx.ed25519("multi-alg", Ed25519Spec::new());

    // Each algorithm domain is independent (keys differ by nature)
    let rsa_der = rsa.private_key_pkcs8_der();
    let ecdsa_der = ecdsa.private_key_pkcs8_der();
    let ed_der = ed.private_key_pkcs8_der();

    assert_ne!(rsa_der, ecdsa_der, "RSA and ECDSA keys must differ");
    assert_ne!(rsa_der, ed_der, "RSA and Ed25519 keys must differ");
    assert_ne!(ecdsa_der, ed_der, "ECDSA and Ed25519 keys must differ");
}

/// Order of generation must not affect the output of any algorithm.
#[test]
fn generation_order_does_not_affect_outputs() {
    let seed = Seed::from_env_value("order-test-seed-v1").unwrap();

    // Generate in order: RSA → ECDSA → Ed25519
    let fx1 = Factory::deterministic(seed);
    let rsa1 = fx1.rsa("order-test", RsaSpec::rs256());
    let ecdsa1 = fx1.ecdsa("order-test", EcdsaSpec::es256());
    let ed1 = fx1.ed25519("order-test", Ed25519Spec::new());

    // Generate in reverse order: Ed25519 → ECDSA → RSA
    let fx2 = Factory::deterministic(seed);
    let ed2 = fx2.ed25519("order-test", Ed25519Spec::new());
    let ecdsa2 = fx2.ecdsa("order-test", EcdsaSpec::es256());
    let rsa2 = fx2.rsa("order-test", RsaSpec::rs256());

    assert_eq!(
        rsa1.private_key_pkcs8_der(),
        rsa2.private_key_pkcs8_der(),
        "RSA key must be identical regardless of generation order"
    );
    assert_eq!(
        ecdsa1.private_key_pkcs8_der(),
        ecdsa2.private_key_pkcs8_der(),
        "ECDSA key must be identical regardless of generation order"
    );
    assert_eq!(
        ed1.private_key_pkcs8_der(),
        ed2.private_key_pkcs8_der(),
        "Ed25519 key must be identical regardless of generation order"
    );
}

/// HMAC and token generation does not interfere with asymmetric keys.
#[test]
fn symmetric_and_asymmetric_do_not_interfere() {
    let seed = Seed::from_env_value("sym-asym-test-v1").unwrap();

    // Generate HMAC first, then RSA
    let fx1 = Factory::deterministic(seed);
    let _hmac1 = fx1.hmac("interference", HmacSpec::hs256());
    let rsa1 = fx1.rsa("interference", RsaSpec::rs256());

    // Generate RSA first, then HMAC
    let fx2 = Factory::deterministic(seed);
    let rsa2 = fx2.rsa("interference", RsaSpec::rs256());
    let _hmac2 = fx2.hmac("interference", HmacSpec::hs256());

    assert_eq!(
        rsa1.private_key_pkcs8_der(),
        rsa2.private_key_pkcs8_der(),
        "HMAC generation must not affect RSA output"
    );
}
