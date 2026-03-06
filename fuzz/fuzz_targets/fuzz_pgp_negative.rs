#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::negative::CorruptPem;
use uselesskey::{Factory, PgpFactoryExt, PgpSpec, Seed};

#[derive(Arbitrary, Debug)]
struct PgpNegativeInput {
    seed: [u8; 32],
    label: String,
    /// 0 = BadHeader, 1 = BadFooter, 2 = BadBase64, 3 = ExtraBlankLine, 4+ = Truncate
    corruption_idx: u8,
    truncate_len: usize,
    variant: String,
}

fuzz_target!(|input: PgpNegativeInput| {
    if input.label.len() > 256 {
        return;
    }

    let fx = Factory::deterministic(Seed::new(input.seed));
    // Use Ed25519 for speed (RSA keygen is slow)
    let kp = fx.pgp(&input.label, PgpSpec::ed25519());

    let corruption = match input.corruption_idx % 5 {
        0 => CorruptPem::BadHeader,
        1 => CorruptPem::BadFooter,
        2 => CorruptPem::BadBase64,
        3 => CorruptPem::ExtraBlankLine,
        _ => CorruptPem::Truncate {
            bytes: input.truncate_len % 128,
        },
    };

    // Corrupt armored output must not panic
    let bad = kp.private_key_armored_corrupt(corruption);
    assert!(!bad.is_empty());

    // Deterministic corruption must be stable
    if !input.variant.is_empty() && input.variant.len() <= 64 {
        let det_a = kp.private_key_armored_corrupt_deterministic(&input.variant);
        let det_b = kp.private_key_armored_corrupt_deterministic(&input.variant);
        assert_eq!(det_a, det_b);
        assert!(!det_a.is_empty());
    }

    // Binary truncation must not panic and must respect bounds
    let trunc = kp.private_key_binary_truncated(input.truncate_len % 256);
    assert!(trunc.len() <= kp.private_key_binary().len());

    // Binary deterministic corruption must not panic
    if !input.variant.is_empty() && input.variant.len() <= 64 {
        let det_a = kp.private_key_binary_corrupt_deterministic(&input.variant);
        let det_b = kp.private_key_binary_corrupt_deterministic(&input.variant);
        assert_eq!(det_a, det_b);
        assert_eq!(det_a.len(), kp.private_key_binary().len());
    }
});
