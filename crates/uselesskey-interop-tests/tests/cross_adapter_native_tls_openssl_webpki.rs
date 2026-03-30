#![cfg(feature = "openssl-interop")]

use rustls_pki_types::UnixTime;
use uselesskey_core::Factory;
use uselesskey_native_tls::NativeTlsX509ChainExt;
use uselesskey_openssl::{OpenSslRsaExt, OpenSslX509ChainExt};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_webpki::WebPkiChainExt;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

fn fx() -> Factory {
    Factory::deterministic_from_str("uselesskey-interop-native-tests-v1")
}

#[test]
fn x509_chain_round_trips_across_openssl_native_tls_and_webpki() {
    let chain = fx().x509_chain(
        "interop-native-chain",
        ChainSpec::new("interop-native.example.com"),
    );

    let openssl_chain = chain.cert_chain_stack_openssl();
    assert_eq!(openssl_chain.len(), 2);
    assert!(!chain.root_cert_openssl().to_der().expect("der").is_empty());

    let _identity = chain.leaf_identity_native_tls();
    let _builder = chain.connector_builder_native_tls();

    let _now = UnixTime::now();
    chain
        .verify_leaf_for_server_name_webpki("interop-native.example.com")
        .expect("webpki verification should pass");
}

#[test]
fn rsa_sign_verify_with_openssl_stays_usable_beside_tls_adapters() {
    let key = fx().rsa("interop-native-rsa", RsaSpec::rs256());

    let msg = b"interop openssl sign verify";
    let sig = key.sign_sha256_openssl(msg);
    assert!(key.verify_sha256_openssl(msg, &sig));
}
