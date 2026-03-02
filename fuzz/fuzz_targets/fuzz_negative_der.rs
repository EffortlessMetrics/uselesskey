#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::negative::{corrupt_der_deterministic, flip_byte, truncate_der};

#[derive(Arbitrary, Debug)]
struct NegativeDerInput {
    der: Vec<u8>,
    truncate_len: usize,
    flip_offset: usize,
    variant: String,
}

fuzz_target!(|input: NegativeDerInput| {
    // Cap sizes to avoid excessive allocations.
    if input.der.len() > 4096 || input.variant.len() > 256 {
        return;
    }

    // Truncation must not panic and must respect bounds.
    let truncated = truncate_der(&input.der, input.truncate_len);
    assert!(truncated.len() <= input.der.len());
    if input.truncate_len < input.der.len() {
        assert_eq!(truncated.len(), input.truncate_len);
    }

    // Flip byte must not panic.
    let flipped = flip_byte(&input.der, input.flip_offset);
    assert_eq!(flipped.len(), input.der.len());
    if input.flip_offset < input.der.len() {
        // Exactly one byte differs.
        let diffs = flipped
            .iter()
            .zip(input.der.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(diffs, 1);
    }

    // Deterministic corruption must be stable.
    if !input.variant.is_empty() && !input.der.is_empty() {
        let out1 = corrupt_der_deterministic(&input.der, &input.variant);
        let out2 = corrupt_der_deterministic(&input.der, &input.variant);
        assert_eq!(out1, out2, "deterministic DER corruption must be stable");
        // Corrupted output must differ from original (for non-trivial input).
        if input.der.len() > 1 {
            assert_ne!(out1, input.der, "corrupted DER must differ from original");
        }
    }

    // Truncate at boundary values.
    let _ = truncate_der(&input.der, 0);
    let _ = truncate_der(&input.der, input.der.len());
    let _ = truncate_der(&input.der, usize::MAX);

    // Flip at boundary values.
    let _ = flip_byte(&input.der, 0);
    if !input.der.is_empty() {
        let _ = flip_byte(&input.der, input.der.len() - 1);
    }
    let _ = flip_byte(&input.der, usize::MAX);
});
