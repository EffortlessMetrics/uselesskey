use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn kid_is_deterministic(input in any::<Vec<u8>>()) {
        let a = kid_from_bytes(&input);
        let b = kid_from_bytes(&input);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn kid_is_valid_base64url(input in any::<Vec<u8>>()) {
        let kid = kid_from_bytes(&input);
        let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes());
        prop_assert!(decoded.is_ok(), "kid should be valid base64url");
    }

    #[test]
    fn kid_default_decodes_to_expected_length(input in any::<Vec<u8>>()) {
        let kid = kid_from_bytes(&input);
        let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes()).unwrap();
        prop_assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);
    }

    #[test]
    fn kid_custom_prefix_decodes_to_requested_length(
        input in any::<Vec<u8>>(),
        prefix_bytes in 1usize..=32,
    ) {
        let kid = kid_from_bytes_with_prefix(&input, prefix_bytes);
        let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes()).unwrap();
        prop_assert_eq!(decoded.len(), prefix_bytes);
    }

    #[test]
    fn different_inputs_produce_different_kids(
        a in proptest::collection::vec(any::<u8>(), 1..64),
        b in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(a != b);
        let kid_a = kid_from_bytes(&a);
        let kid_b = kid_from_bytes(&b);
        prop_assert_ne!(kid_a, kid_b);
    }

    #[test]
    fn kid_contains_only_url_safe_chars(input in any::<Vec<u8>>()) {
        let kid = kid_from_bytes(&input);
        for ch in kid.chars() {
            prop_assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "unexpected char in kid: {:?}",
                ch
            );
        }
    }

    /// Flipping any single bit in the input should change the KID.
    #[test]
    fn single_bit_flip_changes_kid(
        input in proptest::collection::vec(any::<u8>(), 1..64),
        bit_index in 0usize..512,
    ) {
        let byte_idx = bit_index / 8;
        let bit_pos = bit_index % 8;
        prop_assume!(byte_idx < input.len());

        let mut flipped = input.clone();
        flipped[byte_idx] ^= 1 << bit_pos;

        let kid_orig = kid_from_bytes(&input);
        let kid_flip = kid_from_bytes(&flipped);
        prop_assert_ne!(kid_orig, kid_flip, "bit flip at byte {} bit {} should change KID", byte_idx, bit_pos);
    }

    /// Appending a byte to the input should change the KID.
    #[test]
    fn appending_byte_changes_kid(
        input in proptest::collection::vec(any::<u8>(), 0..64),
        extra in any::<u8>(),
    ) {
        let mut extended = input.clone();
        extended.push(extra);

        let kid_orig = kid_from_bytes(&input);
        let kid_ext = kid_from_bytes(&extended);
        prop_assert_ne!(kid_orig, kid_ext, "appending a byte should change KID");
    }

    /// KID string length is always exactly 16 chars for default prefix (12 bytes).
    #[test]
    fn kid_string_length_is_always_16(input in any::<Vec<u8>>()) {
        let kid = kid_from_bytes(&input);
        prop_assert_eq!(kid.len(), 16, "default KID should always be 16 chars");
    }

    /// KID never contains base64 padding characters.
    #[test]
    fn kid_never_contains_padding(
        input in any::<Vec<u8>>(),
        prefix_bytes in 1usize..=32,
    ) {
        let kid = kid_from_bytes_with_prefix(&input, prefix_bytes);
        prop_assert!(!kid.contains('='), "KID should never have padding");
    }
}
