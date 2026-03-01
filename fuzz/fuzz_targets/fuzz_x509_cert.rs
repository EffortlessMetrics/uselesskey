#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{Factory, Seed, X509FactoryExt, X509Spec};

#[derive(Arbitrary, Debug)]
struct X509Input {
    seed: [u8; 32],
    label: String,
    subject_cn: String,
}

fuzz_target!(|input: X509Input| {
    // Skip empty subject CN — X509Spec requires a non-empty CN.
    if input.subject_cn.is_empty() {
        return;
    }

    // Limit subject CN length to avoid excessive allocation in cert generation.
    if input.subject_cn.len() > 256 {
        return;
    }

    // Limit label length similarly.
    if input.label.len() > 256 {
        return;
    }

    let fx = Factory::deterministic(Seed::new(input.seed));
    let spec = X509Spec::self_signed(&input.subject_cn);
    let cert = fx.x509_self_signed(&input.label, spec);

    // Certificate PEM must have correct envelope
    let cert_pem = cert.cert_pem();
    assert!(
        cert_pem.starts_with("-----BEGIN CERTIFICATE-----"),
        "bad cert PEM header"
    );
    assert!(
        cert_pem.contains("-----END CERTIFICATE-----"),
        "bad cert PEM footer"
    );

    // Private key PEM must have correct envelope
    let key_pem = cert.private_key_pkcs8_pem();
    assert!(
        key_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "bad key PEM header"
    );
    assert!(
        key_pem.contains("-----END PRIVATE KEY-----"),
        "bad key PEM footer"
    );

    // DER bytes must be non-empty
    assert!(!cert.cert_der().is_empty());
    assert!(!cert.private_key_pkcs8_der().is_empty());

    // Determinism: same inputs = same output
    let cert2 = fx.x509_self_signed(&input.label, X509Spec::self_signed(&input.subject_cn));
    assert_eq!(cert.cert_pem(), cert2.cert_pem());
});
