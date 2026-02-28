use proptest::prelude::*;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Same input bytes always produce the same kid.
    #[test]
    fn deterministic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let a = kid_from_bytes(&bytes);
        let b = kid_from_bytes(&bytes);
        prop_assert_eq!(&a, &b);
    }

    /// Different inputs produce different kids (with high probability).
    #[test]
    fn different_inputs_different_kids(
        bytes1 in prop::collection::vec(any::<u8>(), 1..256),
        bytes2 in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(bytes1 != bytes2);
        let kid1 = kid_from_bytes(&bytes1);
        let kid2 = kid_from_bytes(&bytes2);
        prop_assert_ne!(kid1, kid2);
    }

    /// kid output is valid base64url (no padding).
    #[test]
    fn kid_is_valid_base64url(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let kid = kid_from_bytes(&bytes);
        let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes());
        prop_assert!(decoded.is_ok(), "kid should be valid base64url, got error: {:?}", decoded.err());
    }

    /// Default kid decodes to exactly DEFAULT_KID_PREFIX_BYTES bytes.
    #[test]
    fn kid_length_is_consistent(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let kid = kid_from_bytes(&bytes);
        let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes()).expect("valid base64url");
        prop_assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);
    }

    /// Custom prefix length is respected for all valid prefix sizes.
    #[test]
    fn custom_prefix_length_respected(
        bytes in prop::collection::vec(any::<u8>(), 1..128),
        prefix in 1usize..=32,
    ) {
        let kid = kid_from_bytes_with_prefix(&bytes, prefix);
        let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes()).expect("valid base64url");
        prop_assert_eq!(decoded.len(), prefix);
    }
}
