//! Cache coherence integration tests for X.509.

mod testutil;

use testutil::fx;
use uselesskey_x509::{X509FactoryExt, X509Spec};

#[test]
fn same_label_same_spec_returns_identical_cert() {
    let fx = fx();
    let spec = X509Spec::self_signed("cache.example.com");
    let c1 = fx.x509_self_signed("cache-eq", spec);
    let spec = X509Spec::self_signed("cache.example.com");
    let c2 = fx.x509_self_signed("cache-eq", spec);
    assert_eq!(
        c1.cert_der(),
        c2.cert_der(),
        "same label+spec must return identical cert DER"
    );
}

#[test]
fn different_labels_produce_different_certs() {
    let fx = fx();
    let c_a = fx.x509_self_signed("x509-a", X509Spec::self_signed("a.example.com"));
    let c_b = fx.x509_self_signed("x509-b", X509Spec::self_signed("a.example.com"));
    assert_ne!(
        c_a.cert_der(),
        c_b.cert_der(),
        "different labels must produce different certs"
    );
}

#[test]
fn cache_survives_factory_clone() {
    let fx = fx();
    let spec = X509Spec::self_signed("clone.example.com");
    let _warm = fx.x509_self_signed("x509-clone", spec);
    let fx2 = fx.clone();
    let spec2 = X509Spec::self_signed("clone.example.com");
    let from_clone = fx2.x509_self_signed("x509-clone", spec2);
    assert_eq!(
        _warm.cert_der(),
        from_clone.cert_der(),
        "cloned factory must share the cache"
    );
}
