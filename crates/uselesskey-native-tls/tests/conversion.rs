use uselesskey_core::Factory;
use uselesskey_native_tls::NativeTlsX509Ext;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

#[test]
fn chain_converts_to_identity_and_connector() {
    let fx = Factory::random();
    let chain = fx.x509_chain("native-tls-chain", ChainSpec::new("svc.example.test"));

    let _identity = chain.native_tls_identity_pkcs8();
    let _root = chain.native_tls_root_certificate();

    let _connector = chain.native_tls_connector();
}
