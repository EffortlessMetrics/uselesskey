use uselesskey::{ChainSpec, Factory, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt};

fn main() {
    let fx = Factory::deterministic_from_str("facade-minimal-canary");

    let rsa = fx.rsa("issuer", RsaSpec::rs256());
    let token = fx.token("svc-api", TokenSpec::api_key());
    let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));

    assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(token.value().starts_with("uk_test_"));
    assert!(chain.chain_pem().contains("BEGIN CERTIFICATE"));
}
