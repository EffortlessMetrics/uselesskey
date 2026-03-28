#![cfg(feature = "openssl-interop")]

use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_openssl::{OpenSslEcdsaExt, OpenSslRsaExt};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_rustcrypto::RustCryptoRsaExt;
use uselesskey_webpki::WebPkiChainExt;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

#[test]
fn rsa_openssl_sign_rustcrypto_verify() {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let kp = Factory::random().rsa("interop-openssl-rsa", RsaSpec::rs256());
    let sig = kp.sign_sha256_openssl(b"interop-message");

    let public = kp.rsa_public_key();
    let verifier = VerifyingKey::<rsa::sha2::Sha256>::new(public);
    let parsed = Signature::try_from(sig.as_slice()).expect("parse PKCS1v15 signature");
    verifier
        .verify(b"interop-message", &parsed)
        .expect("rustcrypto verifies openssl RSA signature");
}

#[test]
fn ecdsa_openssl_round_trip() {
    let kp = Factory::random().ecdsa("interop-openssl-ecdsa", EcdsaSpec::es256());
    let sig = kp.sign_sha256_openssl(b"interop-message");
    assert!(kp.verify_openssl(b"interop-message", &sig));
}

#[test]
fn webpki_verifies_good_and_rejects_bad_hostname() {
    let chain = Factory::random().x509_chain("interop-webpki", ChainSpec::new("svc.example.com"));

    chain
        .verify_leaf_for_server_name_webpki("svc.example.com")
        .expect("good chain verifies");
    assert!(chain.verify_leaf_rejected_webpki("wrong.example.com"));
}
