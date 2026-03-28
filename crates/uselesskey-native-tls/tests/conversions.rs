use uselesskey_core::Factory;
use uselesskey_native_tls::NativeTlsX509Ext;
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

#[test]
fn chain_builds_identity_and_connector() {
    let fx = Factory::random();
    let chain = fx.x509_chain("native-chain", ChainSpec::new("native.example.test"));

    let _id = chain.identity_native_tls_pkcs8();
    let _root = chain.root_certificate_native_tls();
    let _connector = chain.connector_native_tls();
}

#[test]
fn self_signed_builds_identity_and_connector() {
    let fx = Factory::random();
    let cert = fx.x509_self_signed("native-self", X509Spec::self_signed("self.example.test"));

    let _id = cert.identity_native_tls_pkcs8();
    let _root = cert.root_certificate_native_tls();
    let _connector = cert.connector_native_tls();
}
