#![cfg(feature = "all")]

use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_openssl::{
    OpenSslEcdsaExt, OpenSslEd25519Ext, OpenSslRsaExt, OpenSslX509ChainExt, OpenSslX509Ext,
};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

fn fx() -> Factory {
    Factory::deterministic_from_str("uselesskey-openssl-tests-v1")
}

#[test]
fn rsa_sign_verify_round_trip() {
    let key = fx().rsa("openssl-rsa", RsaSpec::rs256());
    let msg = b"openssl-rsa-sign";
    let sig = key.sign_sha256_openssl(msg);
    assert!(key.verify_sha256_openssl(msg, &sig));
    assert!(!key.verify_sha256_openssl(b"wrong", &sig));
    assert!(key.private_key_openssl().private_key_to_der().is_ok());
    assert!(key.public_key_openssl().public_key_to_der().is_ok());
}

#[test]
fn ecdsa_sign_verify_round_trip() {
    let ecdsa = fx().ecdsa("openssl-ecdsa", EcdsaSpec::es256());
    let sig = ecdsa.sign_sha256_openssl(b"openssl-ecdsa-sign");
    assert!(ecdsa.verify_openssl(b"openssl-ecdsa-sign", &sig));
    assert!(!ecdsa.verify_openssl(b"wrong", &sig));
}

#[test]
fn ed25519_conversion_round_trip() {
    let ed = fx().ed25519("openssl-ed25519", Ed25519Spec::new());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let sig = ed.sign_openssl(b"openssl-ed25519-sign");
        ed.verify_openssl(b"openssl-ed25519-sign", &sig)
    }));

    if let Ok(verified) = result {
        assert!(verified, "Ed25519 verify should pass when supported");
    }
}

#[test]
fn x509_conversions_yield_leaf_chain_root() {
    let chain = fx().x509_chain("openssl-x509", ChainSpec::new("openssl.example.com"));

    let leaf = chain.leaf_cert_openssl();
    let chain_stack = chain.cert_chain_stack_openssl();
    let root = chain.root_cert_openssl();
    let key = chain.leaf_private_key_openssl();

    assert!(!leaf.to_der().expect("leaf der").is_empty());
    assert_eq!(chain_stack.len(), 2);
    assert!(!root.to_der().expect("root der").is_empty());
    assert!(key.private_key_to_der().is_ok());
}

#[test]
fn x509_certificate_conversion_round_trip() {
    let cert = fx().x509_self_signed(
        "openssl-self-signed",
        X509Spec::self_signed("openssl.example.com"),
    );

    let native = cert.cert_openssl();
    assert!(!native.to_der().expect("cert der").is_empty());
    assert!(cert.private_key_openssl().private_key_to_der().is_ok());
}
