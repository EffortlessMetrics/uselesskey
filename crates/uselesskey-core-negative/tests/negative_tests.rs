use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// ---------------------------------------------------------------------------
// Sample data
// ---------------------------------------------------------------------------

const SAMPLE_DER: &[u8] = &[0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0xAA, 0xBB];

const SAMPLE_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIBogIBAAJBALRiMLKQk/Al7mPaPNE4IeA9TwJw5JSTkU9wOLkM0DpjCEZAbPjX\n\
qZuJ3QXt4XUJcDOy1JJVDwYL1HRqn8pMuTECAwEAAQ==\n\
-----END RSA PRIVATE KEY-----\n";

// ===========================================================================
// 1. truncate_der tests
// ===========================================================================

#[test]
fn truncate_der_reduces_length() {
    let out = truncate_der(SAMPLE_DER, 4);
    assert_eq!(out.len(), 4);
    assert!(out.len() < SAMPLE_DER.len());
}

#[test]
fn truncate_der_preserves_prefix() {
    let out = truncate_der(SAMPLE_DER, 5);
    assert_eq!(&out[..], &SAMPLE_DER[..5]);
}

#[test]
fn truncate_der_to_zero() {
    let out = truncate_der(SAMPLE_DER, 0);
    assert!(out.is_empty());
}

#[test]
fn truncate_der_to_full_length() {
    let out = truncate_der(SAMPLE_DER, SAMPLE_DER.len());
    assert_eq!(out, SAMPLE_DER);
}

#[test]
fn truncate_der_beyond_length_returns_copy() {
    let out = truncate_der(SAMPLE_DER, SAMPLE_DER.len() + 100);
    assert_eq!(out, SAMPLE_DER);
}

#[test]
fn truncate_der_empty_input() {
    let out = truncate_der(&[], 5);
    assert!(out.is_empty());
}

// ===========================================================================
// 2. flip_byte tests
// ===========================================================================

#[test]
fn flip_byte_changes_target() {
    let out = flip_byte(SAMPLE_DER, 2);
    assert_ne!(out[2], SAMPLE_DER[2]);
}

#[test]
fn flip_byte_preserves_others() {
    let out = flip_byte(SAMPLE_DER, 3);
    for (i, (&orig, &flipped)) in SAMPLE_DER.iter().zip(out.iter()).enumerate() {
        if i != 3 {
            assert_eq!(orig, flipped, "byte at index {i} should be unchanged");
        }
    }
}

#[test]
fn flip_byte_at_zero() {
    let out = flip_byte(SAMPLE_DER, 0);
    assert_eq!(out[0], SAMPLE_DER[0] ^ 0x01);
    assert_eq!(&out[1..], &SAMPLE_DER[1..]);
}

#[test]
fn flip_byte_at_end() {
    let last = SAMPLE_DER.len() - 1;
    let out = flip_byte(SAMPLE_DER, last);
    assert_eq!(out[last], SAMPLE_DER[last] ^ 0x01);
    assert_eq!(&out[..last], &SAMPLE_DER[..last]);
}

#[test]
fn flip_byte_out_of_bounds_returns_copy() {
    let out = flip_byte(SAMPLE_DER, SAMPLE_DER.len() + 10);
    assert_eq!(out, SAMPLE_DER);
}

#[test]
fn flip_byte_empty_input() {
    let out = flip_byte(&[], 0);
    assert!(out.is_empty());
}

// ===========================================================================
// 3. corrupt_der_deterministic tests
// ===========================================================================

#[test]
fn corrupt_deterministic_same_variant_same_output() {
    let a = corrupt_der_deterministic(SAMPLE_DER, "corrupt:alpha");
    let b = corrupt_der_deterministic(SAMPLE_DER, "corrupt:alpha");
    assert_eq!(a, b);
}

#[test]
fn corrupt_deterministic_different_variants_differ() {
    let a = corrupt_der_deterministic(SAMPLE_DER, "corrupt:alpha");
    let b = corrupt_der_deterministic(SAMPLE_DER, "corrupt:beta");
    assert_ne!(a, b);
}

#[test]
fn corrupt_deterministic_always_mutates() {
    let out = corrupt_der_deterministic(SAMPLE_DER, "corrupt:mutate-check");
    assert_ne!(out.as_slice(), SAMPLE_DER);
}

#[test]
fn corrupt_deterministic_single_byte_input() {
    let der = vec![0xFF];
    let out = corrupt_der_deterministic(&der, "corrupt:single");
    // Must either truncate to empty or flip the byte
    assert!(out.is_empty() || (out.len() == 1 && out[0] != 0xFF));
}

#[test]
fn corrupt_deterministic_covers_multiple_arms() {
    // Run many variants to exercise all three internal arms (truncate, flip, flip+truncate)
    use std::collections::HashSet;
    let mut lengths: HashSet<usize> = HashSet::new();
    for i in 0..50 {
        let v = format!("arm-probe-{i}");
        let out = corrupt_der_deterministic(SAMPLE_DER, &v);
        lengths.insert(out.len());
    }
    // With 50 variants we should hit at least 2 distinct output lengths
    assert!(
        lengths.len() >= 2,
        "expected diverse output lengths, got {lengths:?}"
    );
}

// ===========================================================================
// 4. Re-export tests
// ===========================================================================

#[test]
fn corrupt_pem_reexported() {
    // Verify CorruptPem enum and corrupt_pem fn are accessible through the crate
    let _variant = CorruptPem::BadHeader;
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    assert_ne!(out, SAMPLE_PEM);
}

#[test]
fn corrupt_pem_deterministic_reexported() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "reexport-check");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "reexport-check");
    assert_eq!(a, b);
    assert_ne!(a, SAMPLE_PEM);
}

#[test]
fn corrupt_pem_all_variants_accessible() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 10 },
        CorruptPem::ExtraBlankLine,
    ];
    for v in &variants {
        let out = corrupt_pem(SAMPLE_PEM, *v);
        assert_ne!(out, SAMPLE_PEM, "variant {v:?} should corrupt the PEM");
    }
}

// ===========================================================================
// 5. Property tests (proptest)
// ===========================================================================

mod proptests {
    use proptest::prelude::*;
    use uselesskey_core_negative::{flip_byte, truncate_der};

    proptest! {
        #[test]
        fn truncate_never_exceeds_input(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            len in 0usize..512,
        ) {
            let out = truncate_der(&data, len);
            prop_assert!(out.len() <= data.len());
        }

        #[test]
        fn flip_byte_round_trips(
            data in proptest::collection::vec(any::<u8>(), 1..256),
            offset in 0usize..256,
        ) {
            let clamped = offset % data.len();
            let once = flip_byte(&data, clamped);
            let twice = flip_byte(&once, clamped);
            prop_assert_eq!(twice, data, "XOR flip should round-trip");
        }

        #[test]
        fn truncate_preserves_prefix(
            data in proptest::collection::vec(any::<u8>(), 1..256),
            len in 0usize..256,
        ) {
            let out = truncate_der(&data, len);
            let effective = len.min(data.len());
            prop_assert_eq!(&out[..], &data[..effective]);
        }

        #[test]
        fn flip_byte_changes_exactly_one_byte(
            data in proptest::collection::vec(any::<u8>(), 1..256),
            offset in 0usize..256,
        ) {
            let clamped = offset % data.len();
            let out = flip_byte(&data, clamped);
            let diff_count = out.iter().zip(data.iter()).filter(|(a, b)| a != b).count();
            prop_assert_eq!(diff_count, 1);
        }
    }
}
