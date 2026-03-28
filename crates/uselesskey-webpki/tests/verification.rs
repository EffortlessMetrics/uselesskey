use uselesskey_core::Factory;
use uselesskey_webpki::verify_server_cert;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

#[test]
fn verifies_valid_chain_for_matching_hostname() {
    let fx = Factory::random();
    let chain = fx.x509_chain("webpki-ok", ChainSpec::new("webpki.example.test"));

    verify_server_cert(&chain, "webpki.example.test").expect("expected valid chain");
}

#[test]
fn rejects_wrong_hostname() {
    let fx = Factory::random();
    let chain = fx.x509_chain("webpki-bad-host", ChainSpec::new("right.example.test"));

    assert!(verify_server_cert(&chain, "wrong.example.test").is_err());
}
