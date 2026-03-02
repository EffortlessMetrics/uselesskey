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
}
