use proptest::prelude::*;
use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// kid_from_bytes is deterministic for any input.
    #[test]
    fn kid_deterministic(data in any::<Vec<u8>>()) {
        prop_assert_eq!(kid_from_bytes(&data), kid_from_bytes(&data));
    }

    /// kid_from_bytes always produces valid base64url (no padding).
    #[test]
    fn kid_is_valid_base64url(data in any::<Vec<u8>>()) {
        let kid = kid_from_bytes(&data);
        prop_assert!(
            kid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "kid contains invalid base64url characters: {kid}"
        );
    }

    /// kid_from_bytes output decodes to DEFAULT_KID_PREFIX_BYTES bytes.
    #[test]
    fn kid_default_length(data in any::<Vec<u8>>()) {
        let kid = kid_from_bytes(&data);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(kid.as_bytes())
            .expect("kid should be valid base64url");
        prop_assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);
    }

    /// Different inputs produce different kids (collision resistance).
    #[test]
    fn kid_different_inputs_differ(a in any::<Vec<u8>>(), b in any::<Vec<u8>>()) {
        prop_assume!(a != b);
        prop_assert_ne!(kid_from_bytes(&a), kid_from_bytes(&b));
    }

    /// kid_from_bytes_with_prefix respects the prefix_bytes parameter.
    #[test]
    fn kid_with_prefix_respects_length(
        data in any::<Vec<u8>>(),
        prefix in 1u8..=32u8,
    ) {
        let kid = kid_from_bytes_with_prefix(&data, prefix as usize);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(kid.as_bytes())
            .expect("kid should be valid base64url");
        prop_assert_eq!(decoded.len(), prefix as usize);
    }
}

use base64::Engine as _;
