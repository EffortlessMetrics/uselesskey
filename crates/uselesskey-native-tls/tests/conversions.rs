use uselesskey_core::Factory;
use uselesskey_native_tls::{NativeTlsX509ChainExt, NativeTlsX509Ext};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

fn fx() -> Factory {
    Factory::deterministic_from_str("uselesskey-native-tls-tests-v1")
}

#[test]
fn self_signed_native_tls_conversions() {
    let cert = fx().x509_self_signed(
        "native-tls-cert",
        X509Spec::self_signed("native-tls.example.com"),
    );
    let _identity = cert.identity_native_tls();
    let _cert = cert.certificate_native_tls();
    let _builder = cert.connector_builder_native_tls();
}

#[test]
fn chain_native_tls_conversions() {
    let chain = fx().x509_chain("native-tls-chain", ChainSpec::new("native-tls.example.com"));
    let _identity = chain.leaf_identity_native_tls();
    let _root = chain.root_certificate_native_tls();
    let _builder = chain.connector_builder_native_tls();
}
