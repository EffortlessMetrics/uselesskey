//! Cache coherence integration tests for RSA.
//!
//! Verifies that the factory cache behaves correctly across repeated
//! calls, different labels, and factory clones.

mod testutil;

use testutil::fx;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[test]
fn same_label_same_spec_returns_identical_bytes() {
    let fx = fx();
    let kp1 = fx.rsa("cache-eq", RsaSpec::rs256());
    let kp2 = fx.rsa("cache-eq", RsaSpec::rs256());
    assert_eq!(
        kp1.private_key_pkcs8_der(),
        kp2.private_key_pkcs8_der(),
        "same label+spec must return identical private key bytes"
    );
    assert_eq!(
        kp1.public_key_spki_der(),
        kp2.public_key_spki_der(),
        "same label+spec must return identical public key bytes"
    );
}

#[test]
fn different_labels_produce_different_keys() {
    let fx = fx();
    let kp_a = fx.rsa("label-a", RsaSpec::rs256());
    let kp_b = fx.rsa("label-b", RsaSpec::rs256());
    assert_ne!(
        kp_a.private_key_pkcs8_der(),
        kp_b.private_key_pkcs8_der(),
        "different labels must produce different private keys"
    );
}

#[test]
fn cache_survives_factory_clone() {
    let fx = fx();
    let _warm = fx.rsa("clone-test", RsaSpec::rs256());
    let fx2 = fx.clone();
    let from_clone = fx2.rsa("clone-test", RsaSpec::rs256());
    assert_eq!(
        _warm.private_key_pkcs8_der(),
        from_clone.private_key_pkcs8_der(),
        "cloned factory must share the cache"
    );
}

#[test]
fn different_specs_produce_different_keys() {
    let fx = fx();
    let kp_2048 = fx.rsa("spec-diff", RsaSpec::rs256());
    let kp_4096 = fx.rsa("spec-diff", RsaSpec::new(4096));
    assert_ne!(
        kp_2048.private_key_pkcs8_der(),
        kp_4096.private_key_pkcs8_der(),
        "different specs must produce different keys"
    );
}
