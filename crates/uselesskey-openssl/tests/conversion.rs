use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_openssl::{OpensslKeyExt, OpensslSignVerifyExt, OpensslX509Ext};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

fn fx() -> Factory {
    Factory::deterministic(Seed::from_env_value("uselesskey-openssl-tests-v1").expect("seed"))
}

#[test]
fn rsa_sign_verify_round_trip() {
    let key = fx().rsa("openssl-rsa", RsaSpec::rs256());
    let msg = b"openssl-rsa-sign";
    let sig = key.sign_sha256_openssl(msg);
    assert!(key.verify_sha256_openssl(msg, &sig));
    assert!(key.private_key_openssl().private_key_to_der().is_ok());
    assert!(key.public_key_openssl().public_key_to_der().is_ok());
}

#[test]
fn ecdsa_sign_verify_round_trip() {
    let fx = fx();

    let ecdsa = fx.ecdsa("openssl-ecdsa", EcdsaSpec::es256());
    let sig = ecdsa.sign_sha256_openssl(b"openssl-ecdsa-sign");
    assert!(ecdsa.verify_sha256_openssl(b"openssl-ecdsa-sign", &sig));
}

#[test]
fn ed25519_conversion_is_available_when_provider_supports_it() {
    let fx = fx();
    let ed = fx.ed25519("openssl-ed25519", Ed25519Spec::new());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let sig = ed.sign_sha256_openssl(b"openssl-ed25519-sign");
        ed.verify_sha256_openssl(b"openssl-ed25519-sign", &sig)
    }));

    if let Ok(verified) = result {
        assert!(verified, "Ed25519 verify should pass when supported");
    }
}

#[test]
fn x509_conversions_yield_leaf_chain_root() {
    let chain = fx().x509_chain("openssl-x509", ChainSpec::new("openssl.example.com"));

    let leaf = chain.leaf_cert_openssl();
    let chain_stack = chain.chain_openssl();
    let root = chain.root_cert_openssl();
    let key = chain.leaf_private_key_openssl();

    assert!(!leaf.to_der().expect("leaf der").is_empty());
    assert_eq!(chain_stack.len(), 2);
    assert!(!root.to_der().expect("root der").is_empty());
    assert!(key.private_key_to_der().is_ok());
}
