#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{ChainSpec, Factory, Seed, X509FactoryExt};

#[derive(Arbitrary, Debug)]
struct Input {
    seed: [u8; 32],
    label: String,
    domain: String,
    san_count: u8,
}

fuzz_target!(|input: Input| {
    if input.domain.is_empty() || input.domain.len() > 128 {
        return;
    }
    if input.label.len() > 128 {
        return;
    }

    let fx = Factory::deterministic(Seed::new(input.seed));

    let mut spec = ChainSpec::new(&input.domain);

    // Add a bounded number of SANs derived from the domain
    let san_count = (input.san_count % 8) as usize;
    if san_count > 0 {
        let sans: Vec<String> = (0..san_count)
            .map(|i| format!("san{i}.{}", input.domain))
            .collect();
        spec = spec.with_sans(sans);
    }

    let chain = fx.x509_chain(&input.label, spec);

    // Leaf cert PEM envelope
    let leaf_pem = chain.leaf_cert_pem();
    assert!(leaf_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(leaf_pem.contains("-----END CERTIFICATE-----"));

    // Intermediate cert present
    assert!(!chain.intermediate_cert_der().is_empty());

    // Root cert present
    let root_pem = chain.root_cert_pem();
    assert!(root_pem.starts_with("-----BEGIN CERTIFICATE-----"));

    // Chain PEM has exactly 2 certs (leaf + intermediate)
    let chain_pem = chain.chain_pem();
    assert_eq!(chain_pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);

    // Private key present
    assert!(!chain.leaf_private_key_pkcs8_der().is_empty());

    // Determinism check
    let chain2 = fx.x509_chain(&input.label, ChainSpec::new(&input.domain));
    assert_eq!(chain.leaf_cert_pem(), chain2.leaf_cert_pem());
});
