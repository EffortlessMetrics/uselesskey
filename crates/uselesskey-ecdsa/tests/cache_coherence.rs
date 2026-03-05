//! Cache coherence integration tests for ECDSA.

mod testutil;

use testutil::fx;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

#[test]
fn same_label_same_spec_returns_identical_bytes() {
    let fx = fx();
    let kp1 = fx.ecdsa("cache-eq", EcdsaSpec::es256());
    let kp2 = fx.ecdsa("cache-eq", EcdsaSpec::es256());
    assert_eq!(
        kp1.private_key_pkcs8_der(),
        kp2.private_key_pkcs8_der(),
        "same label+spec must return identical private key bytes"
    );
}

#[test]
fn different_labels_produce_different_keys() {
    let fx = fx();
    let kp_a = fx.ecdsa("ecdsa-a", EcdsaSpec::es256());
    let kp_b = fx.ecdsa("ecdsa-b", EcdsaSpec::es256());
    assert_ne!(
        kp_a.private_key_pkcs8_der(),
        kp_b.private_key_pkcs8_der(),
        "different labels must produce different keys"
    );
}

#[test]
fn different_curves_produce_different_keys() {
    let fx = fx();
    let kp_256 = fx.ecdsa("curve-diff", EcdsaSpec::es256());
    let kp_384 = fx.ecdsa("curve-diff", EcdsaSpec::es384());
    assert_ne!(
        kp_256.private_key_pkcs8_der(),
        kp_384.private_key_pkcs8_der(),
        "different curves must produce different keys"
    );
}

#[test]
fn cache_survives_factory_clone() {
    let fx = fx();
    let _warm = fx.ecdsa("ecdsa-clone", EcdsaSpec::es256());
    let fx2 = fx.clone();
    let from_clone = fx2.ecdsa("ecdsa-clone", EcdsaSpec::es256());
    assert_eq!(
        _warm.private_key_pkcs8_der(),
        from_clone.private_key_pkcs8_der(),
        "cloned factory must share the cache"
    );
}
