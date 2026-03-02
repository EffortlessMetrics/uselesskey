#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, Seed,
    X509FactoryExt, X509Spec,
};
use uselesskey_rustls::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};

#[derive(Arbitrary, Debug)]
enum Scenario {
    EcdsaKey,
    Ed25519Key,
    SelfSignedCert,
    Chain,
}

#[derive(Arbitrary, Debug)]
struct Input {
    seed: [u8; 32],
    label: String,
    scenario: Scenario,
}

fuzz_target!(|input: Input| {
    if input.label.len() > 256 {
        return;
    }

    let fx = Factory::deterministic(Seed::new(input.seed));

    match input.scenario {
        Scenario::EcdsaKey => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es256());
            let der = kp.private_key_der_rustls();
            assert!(!der.secret_der().is_empty());
        }
        Scenario::Ed25519Key => {
            let kp = fx.ed25519(&input.label, Ed25519Spec::new());
            let der = kp.private_key_der_rustls();
            assert!(!der.secret_der().is_empty());
        }
        Scenario::SelfSignedCert => {
            let cert = fx.x509_self_signed(&input.label, X509Spec::self_signed("fuzz.test"));
            let cert_der = cert.certificate_der_rustls();
            assert!(!cert_der.as_ref().is_empty());
            let key_der = cert.private_key_der_rustls();
            assert!(!key_der.secret_der().is_empty());
        }
        Scenario::Chain => {
            let chain = fx.x509_chain(&input.label, ChainSpec::new("fuzz.test"));
            let chain_certs = chain.chain_der_rustls();
            assert_eq!(chain_certs.len(), 2);
            let root = chain.root_certificate_der_rustls();
            assert!(!root.as_ref().is_empty());
            let key_der = chain.private_key_der_rustls();
            assert!(!key_der.secret_der().is_empty());
        }
    }
});
