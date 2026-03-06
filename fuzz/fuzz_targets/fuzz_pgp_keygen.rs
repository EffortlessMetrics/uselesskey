#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{Factory, PgpFactoryExt, PgpSpec, Seed};

#[derive(Arbitrary, Debug)]
struct PgpInput {
    seed: [u8; 32],
    label: String,
    /// 0 = Ed25519, 1+ = RSA-2048 (skip RSA-3072 to keep fuzz fast)
    spec_choice: u8,
}

fuzz_target!(|input: PgpInput| {
    if input.label.len() > 256 {
        return;
    }

    let fx = Factory::deterministic(Seed::new(input.seed));
    let spec = if input.spec_choice == 0 {
        PgpSpec::ed25519()
    } else {
        PgpSpec::rsa_2048()
    };

    let kp = fx.pgp(&input.label, spec);

    // Armored outputs must have correct envelopes
    assert!(
        kp.private_key_armored().contains("BEGIN PGP PRIVATE KEY BLOCK"),
        "bad private armor header"
    );
    assert!(
        kp.public_key_armored().contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "bad public armor header"
    );

    // Fingerprint must be non-empty
    assert!(!kp.fingerprint().is_empty(), "fingerprint must be non-empty");

    // Binary outputs must be non-empty
    assert!(!kp.private_key_binary().is_empty());
    assert!(!kp.public_key_binary().is_empty());

    // Determinism: same factory + label + spec = same output
    let kp2 = fx.pgp(&input.label, spec);
    assert_eq!(kp.private_key_armored(), kp2.private_key_armored());
    assert_eq!(kp.public_key_binary(), kp2.public_key_binary());
    assert_eq!(kp.fingerprint(), kp2.fingerprint());

    // Mismatched key must differ from real key
    let mismatch = kp.mismatched_public_key_binary();
    assert!(!mismatch.is_empty());
    assert_ne!(mismatch.as_slice(), kp.public_key_binary());
});
