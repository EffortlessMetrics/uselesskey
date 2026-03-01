use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

fn is_valid_base64url(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[test]
fn empty_input_produces_valid_kid() {
    let kid = kid_from_bytes(b"");
    assert!(!kid.is_empty());
    assert!(is_valid_base64url(&kid));
    URL_SAFE_NO_PAD
        .decode(kid.as_bytes())
        .expect("kid should be valid base64url");
}

#[test]
fn large_input_produces_valid_kid() {
    let input = vec![0xABu8; 1024 * 1024];
    let kid = kid_from_bytes(&input);
    assert!(is_valid_base64url(&kid));
    let decoded = URL_SAFE_NO_PAD
        .decode(kid.as_bytes())
        .expect("kid should be valid base64url");
    assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);
}

#[test]
fn collision_resistance_1000_keys() {
    let kids: Vec<String> = (0u32..1000)
        .map(|i| kid_from_bytes(&i.to_le_bytes()))
        .collect();
    let unique: HashSet<&String> = kids.iter().collect();
    assert_eq!(unique.len(), 1000, "all 1000 kids should be unique");
}

#[test]
fn output_is_valid_base64url() {
    let inputs: &[&[u8]] = &[b"alpha", b"beta", b"gamma", b"\x00\xff\x80", b""];
    for input in inputs {
        let kid = kid_from_bytes(input);
        assert!(
            is_valid_base64url(&kid),
            "kid for input {input:?} contained invalid base64url characters: {kid}"
        );
    }
}

#[test]
fn prefix_length_boundary_values() {
    for prefix_bytes in [1, 16, 32] {
        let kid = kid_from_bytes_with_prefix(b"boundary-test", prefix_bytes);
        assert!(is_valid_base64url(&kid));
        let decoded = URL_SAFE_NO_PAD
            .decode(kid.as_bytes())
            .expect("kid should be valid base64url");
        assert_eq!(
            decoded.len(),
            prefix_bytes,
            "decoded length should match prefix_bytes={prefix_bytes}"
        );
    }
}

#[test]
fn determinism_across_calls() {
    let input = b"determinism-check-input";
    let first = kid_from_bytes(input);
    let second = kid_from_bytes(input);
    assert_eq!(first, second, "same input must always produce the same kid");
}

proptest! {
    #[test]
    fn proptest_arbitrary_inputs(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        let kid = kid_from_bytes(&input);
        prop_assert!(!kid.is_empty(), "kid must not be empty");
        prop_assert!(
            is_valid_base64url(&kid),
            "kid contained invalid base64url characters: {}", kid
        );
    }
}
