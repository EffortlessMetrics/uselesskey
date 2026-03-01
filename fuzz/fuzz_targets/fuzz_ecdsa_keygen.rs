#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Factory, Seed};

#[derive(Arbitrary, Debug)]
struct EcdsaInput {
    seed: [u8; 32],
    label: String,
    use_es384: bool,
}

fuzz_target!(|input: EcdsaInput| {
    let fx = Factory::deterministic(Seed::new(input.seed));
    let spec = if input.use_es384 {
        EcdsaSpec::es384()
    } else {
        EcdsaSpec::es256()
    };

    let kp = fx.ecdsa(&input.label, spec);

    // Private key PEM must have correct envelope
    let priv_pem = kp.private_key_pkcs8_pem();
    assert!(
        priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "bad private PEM header"
    );
    assert!(
        priv_pem.contains("-----END PRIVATE KEY-----"),
        "bad private PEM footer"
    );

    // Public key PEM must have correct envelope
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

    // Determinism: same factory + label + spec = same output
    let kp2 = fx.ecdsa(&input.label, spec);
    assert_eq!(kp.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
    assert_eq!(kp.public_key_spki_der(), kp2.public_key_spki_der());

    // Mismatched key must differ from the real public key
    let mismatch = kp.mismatched_public_key_spki_der();
    assert!(!mismatch.is_empty());
    assert_ne!(mismatch, kp.public_key_spki_der());
});
