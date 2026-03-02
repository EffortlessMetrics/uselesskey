#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

#[derive(Arbitrary, Debug)]
struct NegativePemInput {
    body: Vec<u8>,
    variant: String,
    corruption_idx: u8,
    truncate_bytes: usize,
    /// Tag for the PEM envelope (selects among common PEM types).
    tag_idx: u8,
}

const PEM_TAGS: &[(&str, &str)] = &[
    ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
    ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
    ("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"),
    ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"),
    ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
];

fuzz_target!(|input: NegativePemInput| {
    // Cap sizes.
    if input.body.len() > 2048 || input.variant.len() > 256 {
        return;
    }

    let (header, footer) = PEM_TAGS[input.tag_idx as usize % PEM_TAGS.len()];
    let body_text = String::from_utf8_lossy(&input.body);
    let pem = format!("{header}\n{body_text}\n{footer}");

    let corruption = match input.corruption_idx % 5 {
        0 => CorruptPem::BadHeader,
        1 => CorruptPem::BadFooter,
        2 => CorruptPem::BadBase64,
        3 => CorruptPem::ExtraBlankLine,
        _ => CorruptPem::Truncate {
            bytes: input.truncate_bytes % 512,
        },
    };

    // Single corruption must not panic.
    let corrupted = corrupt_pem(&pem, corruption.clone());
    let _ = corrupted.len();

    // Deterministic corruption must be stable.
    if !input.variant.is_empty() {
        let det1 = corrupt_pem_deterministic(&pem, &input.variant);
        let det2 = corrupt_pem_deterministic(&pem, &input.variant);
        assert_eq!(det1, det2, "deterministic corruption must be stable");
    }

    // Double-corruption: corrupt the already-corrupted output.
    let double = corrupt_pem(&corrupted, corruption);
    let _ = double.len();

    // Exercise all corruption variants on the same PEM.
    for variant in &[
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::ExtraBlankLine,
        CorruptPem::Truncate { bytes: 1 },
    ] {
        let _ = corrupt_pem(&pem, variant.clone());
    }
});
