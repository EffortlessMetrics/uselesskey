use uselesskey_core::{Factory, Seed};
use uselesskey_native_tls::NativeTlsIdentityExt;
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

fn fx() -> Factory {
    Factory::deterministic(Seed::from_env_value("uselesskey-native-tls-tests-v1").expect("seed"))
}

#[test]
fn self_signed_identity_and_connector_inputs_build() {
    let cert = fx().x509_self_signed("native-tls-self", X509Spec::self_signed("localhost"));

    let _identity = cert.identity_native_tls();
    let _root = cert.trust_certificate_native_tls();
    let _connector = cert.connector_native_tls();
}

#[test]
fn chain_identity_and_connector_inputs_build() {
    let chain = fx().x509_chain("native-tls-chain", ChainSpec::new("native.example.com"));

    let _identity = chain.identity_native_tls();
    let _root = chain.trust_certificate_native_tls();
    let _connector = chain.connector_native_tls();
}
