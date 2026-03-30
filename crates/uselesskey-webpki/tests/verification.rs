use uselesskey_core::Factory;
use uselesskey_webpki::WebPkiChainExt;
use uselesskey_x509::{ChainSpec, X509FactoryExt};

fn fx() -> Factory {
    Factory::deterministic_from_str("uselesskey-webpki-tests-v1")
}

#[test]
fn webpki_verifies_good_chain() {
    let chain = fx().x509_chain("webpki-good", ChainSpec::new("webpki.example.com"));
    chain
        .verify_leaf_for_server_name_webpki("webpki.example.com")
        .expect("webpki should verify a valid chain");
}

#[test]
fn webpki_rejects_hostname_mismatch() {
    let chain = fx().x509_chain("webpki-bad-host", ChainSpec::new("webpki.example.com"));
    assert!(chain.verify_leaf_rejected_webpki("wrong.example.com"));
}
