#![cfg(feature = "cross-tls")]

use rustls_pki_types::UnixTime;
use uselesskey_core::{Factory, Seed};
use uselesskey_native_tls::NativeTlsIdentityExt;
use uselesskey_openssl::{OpensslSignVerifyExt, OpensslX509Ext};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_webpki::WebPkiX509Ext;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

fn fx() -> Factory {
    Factory::deterministic(Seed::from_env_value("uselesskey-interop-native-tests-v1").expect("seed"))
}

#[test]
fn x509_chain_round_trips_across_openssl_native_tls_and_webpki() {
    let chain = fx().x509_chain("interop-native-chain", ChainSpec::new("interop-native.example.com"));

    let openssl_chain = chain.chain_openssl();
    assert_eq!(openssl_chain.len(), 2);
    assert!(!chain.root_cert_openssl().to_der().expect("der").is_empty());

    let _identity = chain.identity_native_tls();
    let _connector = chain.connector_native_tls();

    let now = UnixTime::now();
    chain
        .verify_server_cert_webpki("interop-native.example.com", now)
        .expect("webpki verification should pass");
}

#[test]
fn rsa_sign_verify_with_openssl_stays_usable_beside_tls_adapters() {
    let fx = fx();
    let key = fx.rsa("interop-native-rsa", RsaSpec::rs256());

    let msg = b"interop openssl sign verify";
    let sig = key.sign_sha256_openssl(msg);
    assert!(key.verify_sha256_openssl(msg, &sig));
}
