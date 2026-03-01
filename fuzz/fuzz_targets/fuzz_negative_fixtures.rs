#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::negative::CorruptPem;
use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, Seed};

#[derive(Arbitrary, Debug)]
struct NegativeInput {
    seed: [u8; 32],
    label: String,
    /// 0 = BadHeader, 1 = BadFooter, 2 = BadBase64, 3 = ExtraBlankLine, 4+ = Truncate
    corruption_idx: u8,
    truncate_len: usize,
    /// 0 = ECDSA ES256, 1 = ECDSA ES384, 2 = Ed25519
    key_type: u8,
    /// Variant string for deterministic corruption
    variant: String,
}

fuzz_target!(|input: NegativeInput| {
    let fx = Factory::deterministic(Seed::new(input.seed));

    let corruption = match input.corruption_idx % 5 {
        0 => CorruptPem::BadHeader,
        1 => CorruptPem::BadFooter,
        2 => CorruptPem::BadBase64,
        3 => CorruptPem::ExtraBlankLine,
        _ => CorruptPem::Truncate {
            bytes: input.truncate_len % 128,
        },
    };

    match input.key_type % 3 {
        0 => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es256());

            // Corrupt PEM must not panic
            let bad = kp.private_key_pkcs8_pem_corrupt(corruption);
            assert!(!bad.is_empty());

            // Deterministic corruption must not panic
            if !input.variant.is_empty() && input.variant.len() <= 64 {
                let det = kp.private_key_pkcs8_pem_corrupt_deterministic(&input.variant);
                assert!(!det.is_empty());
                // Same variant = same output
                let det2 = kp.private_key_pkcs8_pem_corrupt_deterministic(&input.variant);
                assert_eq!(det, det2);
            }

            // Truncated DER must not panic and must respect bounds
            let trunc = kp.private_key_pkcs8_der_truncated(input.truncate_len % 256);
            assert!(trunc.len() <= kp.private_key_pkcs8_der().len());

            // DER deterministic corruption must not panic
            if !input.variant.is_empty() && input.variant.len() <= 64 {
                let _ = kp.private_key_pkcs8_der_corrupt_deterministic(&input.variant);
            }
        }
        1 => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es384());
            let bad = kp.private_key_pkcs8_pem_corrupt(corruption);
            assert!(!bad.is_empty());
            let trunc = kp.private_key_pkcs8_der_truncated(input.truncate_len % 256);
            assert!(trunc.len() <= kp.private_key_pkcs8_der().len());
        }
        _ => {
            let kp = fx.ed25519(&input.label, Ed25519Spec::new());

            let bad = kp.private_key_pkcs8_pem_corrupt(corruption);
            assert!(!bad.is_empty());

            if !input.variant.is_empty() && input.variant.len() <= 64 {
                let det = kp.private_key_pkcs8_pem_corrupt_deterministic(&input.variant);
                assert!(!det.is_empty());
                let det2 = kp.private_key_pkcs8_pem_corrupt_deterministic(&input.variant);
                assert_eq!(det, det2);
            }

            let trunc = kp.private_key_pkcs8_der_truncated(input.truncate_len % 256);
            assert!(trunc.len() <= kp.private_key_pkcs8_der().len());
        }
    }
});
