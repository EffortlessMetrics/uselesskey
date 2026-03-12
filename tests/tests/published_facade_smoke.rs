#![cfg(feature = "determinism")]

use uselesskey::{
    ChainSpec, Factory, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt,
};

fn fx() -> Factory {
    Factory::deterministic_from_str("published-facade-smoke-v1")
}

#[test]
fn published_facade_smoke_reads_like_a_consumer_test() {
    let fx = fx();

    let rsa = fx.rsa("svc-signing", RsaSpec::rs256());
    let token = fx.token("svc-api", TokenSpec::api_key());
    let chain = fx.x509_chain("svc-tls", ChainSpec::new("svc.example.com"));

    assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(rsa.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    assert!(token.value().starts_with("uk_test_"));
    assert!(chain.chain_pem().contains("BEGIN CERTIFICATE"));
    assert!(
        chain
            .leaf_private_key_pkcs8_pem()
            .contains("BEGIN PRIVATE KEY")
    );
}

#[test]
fn published_facade_determinism_survives_fixture_order() {
    let fx_a = fx();
    let token_a = fx_a.token("svc-api", TokenSpec::bearer());
    let rsa_a = fx_a.rsa("svc-signing", RsaSpec::rs256());

    let fx_b = fx();
    let rsa_b = fx_b.rsa("svc-signing", RsaSpec::rs256());
    let token_b = fx_b.token("svc-api", TokenSpec::bearer());

    assert_eq!(token_a.value(), token_b.value());
    assert_eq!(rsa_a.kid(), rsa_b.kid());
    assert_eq!(rsa_a.public_key_spki_der(), rsa_b.public_key_spki_der());
}
