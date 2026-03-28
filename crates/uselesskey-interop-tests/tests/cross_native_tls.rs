#![cfg(feature = "cross-native-tls")]

use rustls_pki_types::UnixTime;
use uselesskey_core::Factory;
use uselesskey_native_tls::NativeTlsX509Ext;
use uselesskey_openssl::OpensslX509Ext;
use uselesskey_webpki::WebPkiX509Ext;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

#[test]
fn x509_chain_is_usable_across_native_tls_openssl_and_webpki() {
    let fx = Factory::random();
    let chain = fx.x509_chain("cross-native-tls", ChainSpec::new("svc.example.test"));

    let _identity = chain.native_tls_identity_pkcs8();
    let _connector = chain.native_tls_connector();

    let _acceptor = chain.openssl_server_acceptor().expect("openssl acceptor");
    let _client = chain
        .openssl_client_connector()
        .expect("openssl client connector");

    chain
        .verify_tls_server_cert_webpki("svc.example.test", UnixTime::now())
        .expect("webpki verify");
}
