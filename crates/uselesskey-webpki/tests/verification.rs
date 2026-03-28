use rustls_pki_types::UnixTime;
use std::time::{Duration, SystemTime};
use uselesskey_core::Factory;
use uselesskey_webpki::WebPkiX509Ext;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

fn now_unix() -> UnixTime {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    UnixTime::since_unix_epoch(dur)
}

#[test]
fn valid_chain_verifies_for_expected_host() {
    let fx = Factory::random();
    let chain = fx.x509_chain("webpki-valid", ChainSpec::new("svc.example.test"));

    chain
        .verify_tls_server_cert_webpki("svc.example.test", now_unix())
        .expect("expected chain to verify");
}

#[test]
fn wrong_host_fails_verification() {
    let fx = Factory::random();
    let chain = fx.x509_chain("webpki-negative", ChainSpec::new("svc.example.test"));

    chain
        .verify_tls_server_cert_webpki("different.example.test", now_unix())
        .expect_err("host mismatch should fail");
}
