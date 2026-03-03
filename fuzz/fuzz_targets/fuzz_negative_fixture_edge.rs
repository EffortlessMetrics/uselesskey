#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::negative::{corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic};
use uselesskey::negative::{flip_byte, truncate_der, CorruptPem};

#[derive(Arbitrary, Debug)]
struct NegativeEdgeInput {
    pem_body: Vec<u8>,
    der_body: Vec<u8>,
    variant: String,
    truncate_len: usize,
    flip_offset: usize,
}

fuzz_target!(|input: NegativeEdgeInput| {
    // Cap sizes.
    if input.pem_body.len() > 4096
        || input.der_body.len() > 4096
        || input.variant.len() > 256
    {
        return;
    }

    // --- PEM corruption: edge cases ---
    let pem_text = String::from_utf8_lossy(&input.pem_body);

    // Empty PEM must not panic.
    let _ = corrupt_pem("", CorruptPem::BadHeader);
    let _ = corrupt_pem("", CorruptPem::BadFooter);
    let _ = corrupt_pem("", CorruptPem::BadBase64);
    let _ = corrupt_pem("", CorruptPem::ExtraBlankLine);
    let _ = corrupt_pem("", CorruptPem::Truncate { bytes: 0 });

    // Single-char PEM.
    let _ = corrupt_pem("X", CorruptPem::BadHeader);
    let _ = corrupt_pem("X", CorruptPem::Truncate { bytes: 0 });
    let _ = corrupt_pem("X", CorruptPem::Truncate { bytes: 1 });

    // Fuzz-supplied PEM with all corruption variants.
    for variant in &[
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::ExtraBlankLine,
        CorruptPem::Truncate { bytes: input.truncate_len % 512 },
    ] {
        let result = corrupt_pem(&pem_text, *variant);
        let _ = result.len();
    }

    // Deterministic PEM corruption must be stable.
    if !input.variant.is_empty() {
        let d1 = corrupt_pem_deterministic(&pem_text, &input.variant);
        let d2 = corrupt_pem_deterministic(&pem_text, &input.variant);
        assert_eq!(d1, d2, "deterministic PEM corruption must be stable");

        // Empty PEM with deterministic corruption.
        let e1 = corrupt_pem_deterministic("", &input.variant);
        let e2 = corrupt_pem_deterministic("", &input.variant);
        assert_eq!(e1, e2);
    }

    // --- DER corruption: edge cases ---

    // Empty DER must not panic.
    let _ = truncate_der(&[], 0);
    let _ = truncate_der(&[], 100);
    let _ = flip_byte(&[], 0);
    let _ = flip_byte(&[], usize::MAX);

    // Single-byte DER.
    let _ = truncate_der(&[0x42], 0);
    let _ = truncate_der(&[0x42], 1);
    let _ = flip_byte(&[0x42], 0);

    // Fuzz-supplied DER.
    let truncated = truncate_der(&input.der_body, input.truncate_len);
    assert!(truncated.len() <= input.der_body.len());

    let flipped = flip_byte(&input.der_body, input.flip_offset);
    assert_eq!(flipped.len(), input.der_body.len());

    // Deterministic DER corruption.
    if !input.variant.is_empty() && !input.der_body.is_empty() {
        let c1 = corrupt_der_deterministic(&input.der_body, &input.variant);
        let c2 = corrupt_der_deterministic(&input.der_body, &input.variant);
        assert_eq!(c1, c2, "deterministic DER corruption must be stable");
    }

    // Boundary: truncate at 0, at len, at MAX.
    let _ = truncate_der(&input.der_body, 0);
    let _ = truncate_der(&input.der_body, input.der_body.len());
    let _ = truncate_der(&input.der_body, usize::MAX);

    // Boundary: flip at 0, at len-1, at MAX.
    let _ = flip_byte(&input.der_body, 0);
    if !input.der_body.is_empty() {
        let _ = flip_byte(&input.der_body, input.der_body.len() - 1);
    }
    let _ = flip_byte(&input.der_body, usize::MAX);
});
