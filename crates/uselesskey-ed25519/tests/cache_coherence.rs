//! Cache coherence integration tests for Ed25519.

mod testutil;

use testutil::fx;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

#[test]
fn same_label_returns_identical_bytes() {
    let fx = fx();
    let kp1 = fx.ed25519("cache-eq", Ed25519Spec::new());
    let kp2 = fx.ed25519("cache-eq", Ed25519Spec::new());
    assert_eq!(
        kp1.private_key_pkcs8_der(),
        kp2.private_key_pkcs8_der(),
        "same label must return identical private key bytes"
    );
}

#[test]
fn different_labels_produce_different_keys() {
    let fx = fx();
    let kp_a = fx.ed25519("ed-a", Ed25519Spec::new());
    let kp_b = fx.ed25519("ed-b", Ed25519Spec::new());
    assert_ne!(
        kp_a.private_key_pkcs8_der(),
        kp_b.private_key_pkcs8_der(),
        "different labels must produce different keys"
    );
}

#[test]
fn cache_survives_factory_clone() {
    let fx = fx();
    let _warm = fx.ed25519("ed-clone", Ed25519Spec::new());
    let fx2 = fx.clone();
    let from_clone = fx2.ed25519("ed-clone", Ed25519Spec::new());
    assert_eq!(
        _warm.private_key_pkcs8_der(),
        from_clone.private_key_pkcs8_der(),
        "cloned factory must share the cache"
    );
}
