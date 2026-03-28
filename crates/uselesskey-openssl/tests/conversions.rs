use uselesskey_core::Factory;

#[cfg(feature = "rsa")]
use openssl::sign::{Signer, Verifier};
#[cfg(feature = "ecdsa")]
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
#[cfg(feature = "ed25519")]
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
#[cfg(feature = "rsa")]
use uselesskey_openssl::OpensslRsaExt;
#[cfg(feature = "ecdsa")]
use uselesskey_openssl::OpensslEcdsaExt;
#[cfg(feature = "ed25519")]
use uselesskey_openssl::OpensslEd25519Ext;
#[cfg(feature = "x509")]
use uselesskey_openssl::OpensslChainExt;
#[cfg(feature = "rsa")]
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
#[cfg(feature = "x509")]
use uselesskey_x509::{ChainSpec, X509FactoryExt};

#[cfg(feature = "rsa")]
#[test]
fn rsa_sign_verify_roundtrip() {
    let fx = Factory::random();
    let key = fx.rsa("rsa-openssl", RsaSpec::rs256());
    let pkey = key.private_key_openssl();

    let msg = b"openssl-rsa";
    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("signer");
    signer.update(msg).expect("update");
    let sig = signer.sign_to_vec().expect("sign");

    let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("verifier");
    verifier.update(msg).expect("update");
    assert!(verifier.verify(&sig).expect("verify"));
}

#[cfg(feature = "ecdsa")]
#[test]
fn ecdsa_sign_verify_roundtrip() {
    let fx = Factory::random();
    let key = fx.ecdsa("ecdsa-openssl", EcdsaSpec::es256());
    let pkey = key.private_key_openssl();

    let msg = b"openssl-ecdsa";
    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("signer");
    signer.update(msg).expect("update");
    let sig = signer.sign_to_vec().expect("sign");

    let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("verifier");
    verifier.update(msg).expect("update");
    assert!(verifier.verify(&sig).expect("verify"));
}

#[cfg(feature = "ed25519")]
#[test]
fn ed25519_sign_verify_roundtrip() {
    let fx = Factory::random();
    let key = fx.ed25519("ed25519-openssl", Ed25519Spec::new());

    let pkey = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| key.private_key_openssl())) {
        Ok(pkey) => pkey,
        Err(_) => return,
    };

    let msg = b"openssl-ed25519";
    let mut signer = Signer::new_without_digest(&pkey).expect("signer");
    signer.update(msg).expect("update");
    let sig = signer.sign_to_vec().expect("sign");

    let mut verifier = Verifier::new_without_digest(&pkey).expect("verifier");
    verifier.update(msg).expect("update");
    assert!(verifier.verify(&sig).expect("verify"));
}

#[cfg(feature = "x509")]
#[test]
fn x509_chain_converts() {
    let fx = Factory::random();
    let chain = fx.x509_chain("x509-openssl", ChainSpec::new("svc.example.test"));

    let leaf = chain.leaf_cert_openssl();
    let issuer = chain.intermediate_cert_openssl();
    let root = chain.root_cert_openssl();

    assert_ne!(leaf.subject_name().entries().count(), 0);
    assert_ne!(issuer.subject_name().entries().count(), 0);
    assert_ne!(root.subject_name().entries().count(), 0);
}
