#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{Ed25519FactoryExt, Ed25519Spec, Factory, Seed};

#[derive(Arbitrary, Debug)]
struct Ed25519Input {
    seed: [u8; 32],
    label: String,
}

fuzz_target!(|input: Ed25519Input| {
    let fx = Factory::deterministic(Seed::new(input.seed));
    let kp = fx.ed25519(&input.label, Ed25519Spec::new());

    // Private key PEM envelope
    let priv_pem = kp.private_key_pkcs8_pem();
    assert!(
        priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "bad private PEM header"
    );
    assert!(
        priv_pem.contains("-----END PRIVATE KEY-----"),
        "bad private PEM footer"
    );

    // Public key PEM envelope
    let pub_pem = kp.public_key_spki_pem();
    assert!(
        pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
        "bad public PEM header"
    );
    assert!(
        pub_pem.contains("-----END PUBLIC KEY-----"),
        "bad public PEM footer"
    );

    // DER bytes must be non-empty
    assert!(!kp.private_key_pkcs8_der().is_empty());
    assert!(!kp.public_key_spki_der().is_empty());

    // Determinism: same factory + label = same output
    let kp2 = fx.ed25519(&input.label, Ed25519Spec::new());
    assert_eq!(kp.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
    assert_eq!(kp.public_key_spki_der(), kp2.public_key_spki_der());

    // Mismatched key must differ
    let mismatch = kp.mismatched_public_key_spki_der();
    assert!(!mismatch.is_empty());
    assert_ne!(mismatch, kp.public_key_spki_der());

    // Ed25519 PEM should be parseable by ed25519-dalek
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let parsed = ed25519_dalek::SigningKey::from_pkcs8_pem(priv_pem);
    assert!(parsed.is_ok(), "generated Ed25519 PEM must be valid");
});
