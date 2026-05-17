use uselesskey::{ChainSpec, Factory, X509FactoryExt};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};

#[test]
fn tls_chain_fixtures_build_rustls_configs_from_a_clean_project() {
    let fx = Factory::deterministic_from_str("external-tls-chain-validation");
    let chain = fx.x509_chain(
        "service",
        ChainSpec::new("valid.tls.uselesskey.test"),
    );

    assert!(chain.chain_pem().contains("BEGIN CERTIFICATE"));
    assert!(chain.root_cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(chain.leaf_private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));

    let server = chain.server_config_rustls();
    let client = chain.client_config_rustls();

    assert!(server.alpn_protocols.is_empty());
    assert!(client.alpn_protocols.is_empty());
}
