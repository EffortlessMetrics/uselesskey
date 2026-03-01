//! Integration tests for `uselesskey-core-kid`.

use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

#[test]
fn kid_from_same_bytes_is_deterministic() {
    let input = b"deterministic-test-key-material";
    let a = kid_from_bytes(input);
    let b = kid_from_bytes(input);
    assert_eq!(a, b, "same input must produce the same kid");
}

#[test]
fn kid_from_different_bytes_is_different() {
    let a = kid_from_bytes(b"key-alpha");
    let b = kid_from_bytes(b"key-beta");
    assert_ne!(a, b, "different inputs must produce different kids");
}

#[test]
fn kid_with_prefix_is_deterministic() {
    let input = b"prefix-determinism-check";
    for prefix in [1, 8, 16, 32] {
        let a = kid_from_bytes_with_prefix(input, prefix);
        let b = kid_from_bytes_with_prefix(input, prefix);
        assert_eq!(a, b, "with_prefix({prefix}) must be deterministic");
    }
}

// ---------------------------------------------------------------------------
// Format tests
// ---------------------------------------------------------------------------

/// Output must only contain base64url-safe characters (no padding).
#[test]
fn kid_is_base64url_encoded() {
    let kid = kid_from_bytes(b"format-check");
    assert!(
        kid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "kid must only contain base64url chars, got: {kid}",
    );
}

/// Default prefix (12 bytes) → 16 base64url characters.
#[test]
fn kid_default_length() {
    let kid = kid_from_bytes(b"length-check");
    // 12 bytes encodes to exactly 16 base64 characters (no padding).
    let expected_len = (DEFAULT_KID_PREFIX_BYTES * 4 + 2) / 3;
    assert_eq!(
        kid.len(),
        expected_len,
        "default kid length should be {expected_len}",
    );
}

/// Custom prefix_bytes produces the correct base64url length.
#[test]
fn kid_custom_prefix_length() {
    for prefix in [1, 2, 3, 6, 8, 12, 16, 24, 32] {
        let kid = kid_from_bytes_with_prefix(b"prefix-length-check", prefix);
        let expected_len = (prefix * 4 + 2) / 3;
        assert_eq!(
            kid.len(),
            expected_len,
            "prefix_bytes={prefix} should yield {expected_len} chars",
        );
    }
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn kid_from_empty_bytes() {
    let kid = kid_from_bytes(b"");
    assert!(!kid.is_empty(), "empty input should still produce a kid");
}

#[test]
#[should_panic(expected = "prefix_bytes must be in 1..=32")]
fn kid_prefix_zero_bytes() {
    let _ = kid_from_bytes_with_prefix(b"zero-prefix", 0);
}

/// Maximum prefix (32 = blake3::OUT_LEN) should work without panic.
#[test]
fn kid_prefix_large() {
    let kid = kid_from_bytes_with_prefix(b"large-prefix", 32);
    let expected_len = (32 * 4 + 2) / 3;
    assert_eq!(kid.len(), expected_len);
}

#[test]
#[should_panic(expected = "prefix_bytes must be in 1..=32")]
fn kid_prefix_exceeds_blake3_output() {
    let _ = kid_from_bytes_with_prefix(b"too-large", 33);
}

// ---------------------------------------------------------------------------
// Property tests (proptest)
// ---------------------------------------------------------------------------

proptest::proptest! {
    #[test]
    fn kid_always_base64url(input in proptest::collection::vec(proptest::num::u8::ANY, 0..256)) {
        let kid = kid_from_bytes(&input);
        proptest::prop_assert!(
            kid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "non-base64url char in kid: {}", kid,
        );
    }

    #[test]
    fn kid_deterministic_for_all_inputs(input in proptest::collection::vec(proptest::num::u8::ANY, 0..256)) {
        let a = kid_from_bytes(&input);
        let b = kid_from_bytes(&input);
        proptest::prop_assert_eq!(a, b);
    }

    #[test]
    fn kid_different_inputs_usually_different(
        a in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
        b in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
    ) {
        // Only assert difference when inputs themselves differ.
        proptest::prop_assume!(a != b);
        let kid_a = kid_from_bytes(&a);
        let kid_b = kid_from_bytes(&b);
        // 96-bit hash prefix: collision probability ≈ 2^-96 per pair.
        proptest::prop_assert_ne!(kid_a, kid_b);
    }
}
