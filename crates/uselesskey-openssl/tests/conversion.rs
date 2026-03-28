use openssl::hash::MessageDigest;
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_openssl::{OpensslEcdsaExt, OpensslEd25519Ext, OpensslRsaExt, OpensslX509Ext};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

#[test]
fn rsa_roundtrip_and_sign_verify() {
    let fx = Factory::random();
    let kp = fx.rsa("openssl-rsa", RsaSpec::rs256());
    let msg = b"openssl-rsa-sign-verify";

    let sig = uselesskey_openssl::openssl_sign(&kp.openssl_private_key(), MessageDigest::sha256(), msg)
        .expect("rsa sign");

    let ok = uselesskey_openssl::openssl_verify(
        &kp.openssl_public_key(),
        MessageDigest::sha256(),
        msg,
        &sig,
    )
    .expect("rsa verify");

    assert!(ok);
}

#[test]
fn ecdsa_and_ed25519_private_keys_parse() {
    let fx = Factory::random();

    let ecdsa = fx.ecdsa("openssl-ecdsa", EcdsaSpec::es256());
    assert!(ecdsa.openssl_private_key().bits() > 0);

    let ed = fx.ed25519("openssl-ed25519", Ed25519Spec::new());
    assert!(ed.openssl_private_key().bits() > 0);
}

#[test]
fn x509_chain_builds_connector_and_acceptor() {
    let fx = Factory::random();
    let chain = fx.x509_chain("openssl-chain", ChainSpec::new("svc.example.test"));

    let acceptor = chain.openssl_server_acceptor().expect("server acceptor");
    let connector = chain.openssl_client_connector().expect("client connector");

    let _ = acceptor.context();
    let _ = connector.configure().expect("configure connector");
}
