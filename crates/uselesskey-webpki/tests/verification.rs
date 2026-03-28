use rustls_pki_types::UnixTime;
use uselesskey_core::{Factory, Seed};
use uselesskey_webpki::WebPkiX509Ext;
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

fn fx() -> Factory {
    Factory::deterministic(Seed::from_env_value("uselesskey-webpki-tests-v1").expect("seed"))
}

#[test]
fn self_signed_verification_passes_for_matching_dns_name() {
    let cert = fx().x509_self_signed(
        "webpki-self",
        X509Spec::self_signed("localhost").with_sans(vec!["localhost".into()]),
    );
    let now = UnixTime::now();

    cert.verify_server_cert_webpki("localhost", now)
        .expect("self-signed cert verifies as own trust anchor");
}

#[test]
fn chain_verification_passes_and_wrong_name_fails() {
    let chain = fx().x509_chain("webpki-chain", ChainSpec::new("webpki.example.com"));
    let now = UnixTime::now();

    chain
        .verify_server_cert_webpki("webpki.example.com", now)
        .expect("chain verifies with root trust anchor");

    assert!(
        chain
            .verify_server_cert_webpki("wrong.example.com", now)
            .is_err(),
        "mismatched dns name should fail verification"
    );
}
