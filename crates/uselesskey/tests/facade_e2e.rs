//! End-to-end integration tests verifying deterministic behavior
//! across all key types through the uselesskey facade.
//!
//! These tests confirm that the deterministic derivation contract
//! holds when accessed through the public facade API.

use uselesskey::prelude::*;

fn deterministic_fx(seed_str: &str) -> Factory {
    let seed = Seed::from_env_value(seed_str).expect("test seed");
    Factory::deterministic(seed)
}

// =========================================================================
// Deterministic derivation contract
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_deterministic_through_facade() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx1 = deterministic_fx("facade-e2e-v1");
    let fx2 = deterministic_fx("facade-e2e-v1");

    let kp1 = fx1.rsa("e2e-rsa", RsaSpec::rs256());
    let kp2 = fx2.rsa("e2e-rsa", RsaSpec::rs256());

    assert_eq!(
        kp1.private_key_pkcs8_der(),
        kp2.private_key_pkcs8_der(),
        "deterministic RSA keys must match through facade"
    );
    assert_eq!(kp1.public_key_spki_der(), kp2.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_deterministic_through_facade() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    let fx1 = deterministic_fx("facade-e2e-v1");
    let fx2 = deterministic_fx("facade-e2e-v1");

    let kp1 = fx1.ecdsa("e2e-ecdsa", EcdsaSpec::es256());
    let kp2 = fx2.ecdsa("e2e-ecdsa", EcdsaSpec::es256());

    assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_deterministic_through_facade() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    let fx1 = deterministic_fx("facade-e2e-v1");
    let fx2 = deterministic_fx("facade-e2e-v1");

    let kp1 = fx1.ed25519("e2e-ed", Ed25519Spec::new());
    let kp2 = fx2.ed25519("e2e-ed", Ed25519Spec::new());

    assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_deterministic_through_facade() {
    use uselesskey::{HmacFactoryExt, HmacSpec};

    let fx1 = deterministic_fx("facade-e2e-v1");
    let fx2 = deterministic_fx("facade-e2e-v1");

    let s1 = fx1.hmac("e2e-hmac", HmacSpec::hs256());
    let s2 = fx2.hmac("e2e-hmac", HmacSpec::hs256());

    assert_eq!(s1.secret_bytes(), s2.secret_bytes());
}

#[test]
#[cfg(feature = "token")]
fn token_deterministic_through_facade() {
    use uselesskey::{TokenFactoryExt, TokenSpec};

    let fx1 = deterministic_fx("facade-e2e-v1");
    let fx2 = deterministic_fx("facade-e2e-v1");

    let t1 = fx1.token("e2e-token", TokenSpec::api_key());
    let t2 = fx2.token("e2e-token", TokenSpec::api_key());

    assert_eq!(t1.value(), t2.value());
}

// =========================================================================
// Order-independent derivation
// =========================================================================

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
fn order_independent_derivation() {
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, RsaFactoryExt, RsaSpec,
    };

    // Generate in order: RSA then ECDSA then Ed25519
    let fx_abc = deterministic_fx("facade-order-v1");
    let rsa_a = fx_abc.rsa("order-rsa", RsaSpec::rs256());
    let ec_a = fx_abc.ecdsa("order-ec", EcdsaSpec::es256());
    let ed_a = fx_abc.ed25519("order-ed", Ed25519Spec::new());

    // Generate in reverse order: Ed25519 then ECDSA then RSA
    let fx_cba = deterministic_fx("facade-order-v1");
    let ed_b = fx_cba.ed25519("order-ed", Ed25519Spec::new());
    let ec_b = fx_cba.ecdsa("order-ec", EcdsaSpec::es256());
    let rsa_b = fx_cba.rsa("order-rsa", RsaSpec::rs256());

    assert_eq!(
        rsa_a.private_key_pkcs8_der(),
        rsa_b.private_key_pkcs8_der(),
        "RSA key must be the same regardless of generation order"
    );
    assert_eq!(
        ec_a.private_key_pkcs8_der(),
        ec_b.private_key_pkcs8_der(),
        "ECDSA key must be the same regardless of generation order"
    );
    assert_eq!(
        ed_a.private_key_pkcs8_der(),
        ed_b.private_key_pkcs8_der(),
        "Ed25519 key must be the same regardless of generation order"
    );
}

// =========================================================================
// Different labels never collide
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn different_labels_different_rsa_keys() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = deterministic_fx("facade-labels-v1");
    let a = fx.rsa("service-a", RsaSpec::rs256());
    let b = fx.rsa("service-b", RsaSpec::rs256());

    assert_ne!(
        a.private_key_pkcs8_der(),
        b.private_key_pkcs8_der(),
        "different labels must produce different keys"
    );
}

#[test]
#[cfg(feature = "ecdsa")]
fn different_labels_different_ecdsa_keys() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    let fx = deterministic_fx("facade-labels-v1");
    let a = fx.ecdsa("service-a", EcdsaSpec::es256());
    let b = fx.ecdsa("service-b", EcdsaSpec::es256());

    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

// =========================================================================
// Debug safety across all types
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_debug_is_safe() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = Factory::random();
    let kp = fx.rsa("debug-safe", RsaSpec::rs256());
    let debug = format!("{:?}", kp);
    assert!(!debug.contains("BEGIN"), "Debug must not leak PEM");
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_debug_is_safe() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    let fx = Factory::random();
    let kp = fx.ecdsa("debug-safe", EcdsaSpec::es256());
    let debug = format!("{:?}", kp);
    assert!(!debug.contains("BEGIN"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_debug_is_safe() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    let fx = Factory::random();
    let kp = fx.ed25519("debug-safe", Ed25519Spec::new());
    let debug = format!("{:?}", kp);
    assert!(!debug.contains("BEGIN"));
}

// =========================================================================
// Negative fixtures through facade
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn corrupt_pem_produces_bad_output() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = Factory::deterministic_from_str("facade-e2e-negative");
    let kp = fx.rsa("negative-pem", RsaSpec::rs256());
    let pem = kp.private_key_pkcs8_pem();
    let corrupted = corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(
        !corrupted.contains("BEGIN PRIVATE KEY"),
        "corrupted PEM should not have original header"
    );
}

#[test]
#[cfg(feature = "rsa")]
fn corrupt_pem_all_variants_differ() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = Factory::deterministic_from_str("facade-e2e-negative");
    let kp = fx.rsa("negative-pem", RsaSpec::rs256());
    let pem = kp.private_key_pkcs8_pem();

    let bad_header = corrupt_pem(pem, CorruptPem::BadHeader);
    let bad_footer = corrupt_pem(pem, CorruptPem::BadFooter);
    let bad_base64 = corrupt_pem(pem, CorruptPem::BadBase64);

    assert_ne!(bad_header, bad_footer);
    assert_ne!(bad_header, bad_base64);
    assert_ne!(bad_footer, bad_base64);
}

// =========================================================================
// PEM format invariants
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_pem_format_is_valid() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = Factory::random();
    let kp = fx.rsa("pem-test", RsaSpec::rs256());

    let priv_pem = kp.private_key_pkcs8_pem();
    assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(priv_pem.trim_end().ends_with("-----END PRIVATE KEY-----"));

    let pub_pem = kp.public_key_spki_pem();
    assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(pub_pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_pem_format_is_valid() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    let fx = Factory::random();
    let kp = fx.ecdsa("pem-test", EcdsaSpec::es256());

    let priv_pem = kp.private_key_pkcs8_pem();
    assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(priv_pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
}

// =========================================================================
// Factory modes
// =========================================================================

#[test]
fn random_factory_mode() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn deterministic_factory_mode() {
    let fx = deterministic_fx("mode-test-v1");
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn seed_round_trip() {
    let original = "my-test-seed-value";
    let seed = Seed::from_env_value(original).expect("seed");
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}
