use uselesskey_core_negative_der::{corrupt_der_deterministic, flip_byte, truncate_der};

// ---------------------------------------------------------------------------
// truncate_der
// ---------------------------------------------------------------------------

#[test]
fn truncate_returns_prefix_of_requested_length() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0xAA];
    let out = truncate_der(&der, 3);
    assert_eq!(out, &der[..3]);
}

#[test]
fn truncate_to_zero_returns_empty() {
    let der = vec![0x30, 0x82];
    assert!(truncate_der(&der, 0).is_empty());
}

#[test]
fn truncate_at_exact_length_returns_copy() {
    let der = vec![0x30, 0x82, 0x01];
    assert_eq!(truncate_der(&der, 3), der);
}

#[test]
fn truncate_beyond_length_returns_full_copy() {
    let der = vec![0x30, 0x82];
    assert_eq!(truncate_der(&der, 100), der);
}

#[test]
fn truncate_empty_input() {
    let empty: &[u8] = &[];
    assert!(truncate_der(empty, 0).is_empty());
    assert!(truncate_der(empty, 5).is_empty());
}

#[test]
fn truncate_single_byte_to_zero() {
    assert!(truncate_der(&[0xFF], 0).is_empty());
}

#[test]
fn truncate_single_byte_to_one() {
    assert_eq!(truncate_der(&[0xFF], 1), vec![0xFF]);
}

// ---------------------------------------------------------------------------
// flip_byte
// ---------------------------------------------------------------------------

#[test]
fn flip_byte_xors_exactly_one_position() {
    let der = vec![0x00, 0x10, 0x20, 0x30];
    let out = flip_byte(&der, 2);
    assert_eq!(out[2], 0x21); // 0x20 ^ 0x01
    assert_eq!(out[0], 0x00);
    assert_eq!(out[1], 0x10);
    assert_eq!(out[3], 0x30);
}

#[test]
fn flip_byte_is_involutory() {
    let der = vec![0xAB, 0xCD, 0xEF];
    let flipped = flip_byte(&der, 1);
    let restored = flip_byte(&flipped, 1);
    assert_eq!(restored, der);
}

#[test]
fn flip_byte_out_of_bounds_returns_copy() {
    let der = vec![0x30, 0x82];
    assert_eq!(flip_byte(&der, 2), der);
    assert_eq!(flip_byte(&der, 100), der);
}

#[test]
fn flip_byte_empty_returns_empty() {
    let empty: &[u8] = &[];
    assert!(flip_byte(empty, 0).is_empty());
}

#[test]
fn flip_byte_single_byte() {
    assert_eq!(flip_byte(&[0x00], 0), vec![0x01]);
    assert_eq!(flip_byte(&[0x01], 0), vec![0x00]);
    assert_eq!(flip_byte(&[0xFF], 0), vec![0xFE]);
}

// ---------------------------------------------------------------------------
// corrupt_der_deterministic
// ---------------------------------------------------------------------------

#[test]
fn deterministic_corruption_is_repeatable() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let a = corrupt_der_deterministic(&der, "repeat-test");
    let b = corrupt_der_deterministic(&der, "repeat-test");
    assert_eq!(a, b);
}

#[test]
fn different_variants_produce_different_output() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let a = corrupt_der_deterministic(&der, "variant-alpha");
    let b = corrupt_der_deterministic(&der, "variant-beta");
    // With high probability these differ; both differ from original.
    assert_ne!(a, der);
    assert_ne!(b, der);
    assert_ne!(a, b);
}

#[test]
fn different_inputs_same_variant_produce_different_output() {
    // Use large inputs so truncation still leaves distinct content.
    let d1: Vec<u8> = (0..128).collect();
    let d2: Vec<u8> = (128..=255).chain(0..2).collect();
    let a = corrupt_der_deterministic(&d1, "shared-variant");
    let b = corrupt_der_deterministic(&d2, "shared-variant");
    assert_ne!(a, b);
}

#[test]
fn corrupt_empty_input() {
    let empty: &[u8] = &[];
    // Should not panic on empty input.
    let out = corrupt_der_deterministic(empty, "empty-test");
    assert!(out.is_empty());
}

#[test]
fn corrupt_single_byte_input() {
    let single = vec![0x42];
    // Should not panic; result may be empty (truncation to 0) or flipped.
    let out = corrupt_der_deterministic(&single, "single-byte-test");
    assert!(out.len() <= 1);
}

#[test]
fn corrupt_output_always_differs_from_original() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    // Try many variant strings — every corruption must differ from the original.
    for i in 0..50 {
        let variant = format!("diff-check-{i}");
        let out = corrupt_der_deterministic(&der, &variant);
        assert_ne!(out, der, "variant {variant} produced unchanged output");
    }
}

#[test]
fn corrupt_output_never_longer_than_input() {
    let der: Vec<u8> = (0..64).collect();
    for i in 0..30 {
        let variant = format!("len-check-{i}");
        let out = corrupt_der_deterministic(&der, &variant);
        assert!(
            out.len() <= der.len(),
            "output longer than input for variant {variant}"
        );
    }
}

// ---------------------------------------------------------------------------
// proptest: randomized property checks
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn truncate_never_exceeds_requested_len(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            len in 0usize..512,
        ) {
            let out = truncate_der(&data, len);
            prop_assert!(out.len() <= data.len());
            prop_assert!(out.len() <= len);
        }

        #[test]
        fn flip_preserves_length_when_in_bounds(
            data in proptest::collection::vec(any::<u8>(), 1..256),
            offset in 0usize..256,
        ) {
            let out = flip_byte(&data, offset);
            prop_assert_eq!(out.len(), data.len());
        }

        #[test]
        fn corrupt_deterministic_is_pure(
            data in proptest::collection::vec(any::<u8>(), 1..128),
            variant in "[a-z]{1,16}",
        ) {
            let a = corrupt_der_deterministic(&data, &variant);
            let b = corrupt_der_deterministic(&data, &variant);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn corrupt_never_grows(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            variant in "[a-z]{1,16}",
        ) {
            let out = corrupt_der_deterministic(&data, &variant);
            prop_assert!(out.len() <= data.len());
        }
    }
}
