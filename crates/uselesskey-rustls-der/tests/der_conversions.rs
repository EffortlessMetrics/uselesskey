use uselesskey_core::{Factory, Seed};
use uselesskey_rustls_der::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};

fn fx() -> Factory {
    Factory::deterministic(Seed::from_env_value("uselesskey-rustls-der-tests").unwrap())
}

#[cfg(feature = "x509")]
#[test]
fn x509_chain_conversions_match_source_der() {
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    let chain = fx().x509_chain("chain", ChainSpec::new("test.example.com"));
    let key = chain.private_key_der_rustls();
    let cert = chain.certificate_der_rustls();
    let cert_chain = chain.chain_der_rustls();

    assert_eq!(key.secret_der(), chain.leaf_private_key_pkcs8_der());
    assert_eq!(cert.as_ref(), chain.leaf_cert_der());
    assert_eq!(cert_chain[0].as_ref(), chain.leaf_cert_der());
    assert_eq!(cert_chain[1].as_ref(), chain.intermediate_cert_der());
    assert_eq!(
        chain.root_certificate_der_rustls().as_ref(),
        chain.root_cert_der()
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_private_key_der_matches_source() {
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    let keypair = fx().rsa("rsa", RsaSpec::rs256());
    let key = keypair.private_key_der_rustls();
    assert_eq!(key.secret_der(), keypair.private_key_pkcs8_der());
}
