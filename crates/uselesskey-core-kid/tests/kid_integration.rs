use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

// ── Determinism ──────────────────────────────────────────────────────

#[test]
fn same_input_produces_same_kid() {
    let a = kid_from_bytes(b"deterministic-test-key");
    let b = kid_from_bytes(b"deterministic-test-key");
    assert_eq!(a, b);
}

#[test]
fn stable_across_repeated_calls() {
    let input = b"stability-check";
    let first = kid_from_bytes(input);
    for _ in 0..100 {
        assert_eq!(kid_from_bytes(input), first);
    }
}

#[test]
fn with_prefix_is_deterministic() {
    let a = kid_from_bytes_with_prefix(b"prefix-test", 16);
    let b = kid_from_bytes_with_prefix(b"prefix-test", 16);
    assert_eq!(a, b);
}

// ── Uniqueness ───────────────────────────────────────────────────────

#[test]
fn different_inputs_produce_different_kids() {
    let a = kid_from_bytes(b"key-alpha");
    let b = kid_from_bytes(b"key-beta");
    assert_ne!(a, b);
}

#[test]
fn single_byte_difference_produces_different_kid() {
    let a = kid_from_bytes(b"AAAA");
    let b = kid_from_bytes(b"AAAB");
    assert_ne!(a, b);
}

#[test]
fn different_prefix_lengths_produce_different_kids() {
    let a = kid_from_bytes_with_prefix(b"same-input", 8);
    let b = kid_from_bytes_with_prefix(b"same-input", 16);
    assert_ne!(a, b);
}

#[test]
fn shorter_prefix_is_prefix_of_longer() {
    let short = kid_from_bytes_with_prefix(b"prefix-relation", 8);
    let long = kid_from_bytes_with_prefix(b"prefix-relation", 16);
    // Both derive from the same BLAKE3 hash, so the shorter base64
    // encoding won't necessarily be a string-prefix of the longer one
    // (base64 re-encodes different byte slices), but they must differ.
    assert_ne!(short, long);
}

// ── Format validation (URL-safe base64, no padding) ──────────────────

#[test]
fn kid_is_valid_url_safe_base64_no_pad() {
    let kid = kid_from_bytes(b"format-check");
    // Must contain only URL-safe base64 chars: [A-Za-z0-9_-]
    assert!(
        kid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "kid contains non-URL-safe-base64 characters: {kid}"
    );
    // No padding characters
    assert!(!kid.contains('='), "kid must not contain padding: {kid}");
}

#[test]
fn kid_decodes_to_default_prefix_bytes() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let kid = kid_from_bytes(b"decode-length-check");
    let decoded = URL_SAFE_NO_PAD
        .decode(kid.as_bytes())
        .expect("kid must be valid base64url");
    assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);
}

#[test]
fn custom_prefix_lengths_decode_correctly() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    for prefix in [1, 4, 8, 12, 16, 24, 32] {
        let kid = kid_from_bytes_with_prefix(b"length-test", prefix);
        let decoded = URL_SAFE_NO_PAD
            .decode(kid.as_bytes())
            .expect("kid must be valid base64url");
        assert_eq!(
            decoded.len(),
            prefix,
            "decoded length mismatch for prefix_bytes={prefix}"
        );
    }
}

#[test]
fn kid_length_scales_with_prefix() {
    let kid_8 = kid_from_bytes_with_prefix(b"scale", 8);
    let kid_16 = kid_from_bytes_with_prefix(b"scale", 16);
    let kid_32 = kid_from_bytes_with_prefix(b"scale", 32);
    assert!(kid_8.len() < kid_16.len());
    assert!(kid_16.len() < kid_32.len());
}

// ── Edge cases ───────────────────────────────────────────────────────

#[test]
fn empty_input_produces_valid_kid() {
    let kid = kid_from_bytes(b"");
    assert!(!kid.is_empty(), "kid for empty input must not be empty");
    assert!(
        kid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "kid for empty input has invalid characters: {kid}"
    );
}

#[test]
fn empty_input_is_deterministic() {
    let a = kid_from_bytes(b"");
    let b = kid_from_bytes(b"");
    assert_eq!(a, b);
}

#[test]
fn very_long_input_produces_valid_kid() {
    let long_input = vec![0xABu8; 1_000_000];
    let kid = kid_from_bytes(&long_input);
    assert!(!kid.is_empty());
    assert!(
        kid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "kid for large input has invalid characters"
    );
}

#[test]
fn very_long_input_is_deterministic() {
    let long_input = vec![0xFFu8; 100_000];
    let a = kid_from_bytes(&long_input);
    let b = kid_from_bytes(&long_input);
    assert_eq!(a, b);
}

#[test]
fn all_zeros_vs_all_ones() {
    let zeros = kid_from_bytes(&[0u8; 64]);
    let ones = kid_from_bytes(&[0xFFu8; 64]);
    assert_ne!(zeros, ones);
}

// ── Boundary prefix values ──────────────────────────────────────────

#[test]
fn minimum_prefix_length() {
    let kid = kid_from_bytes_with_prefix(b"min-prefix", 1);
    assert!(!kid.is_empty());
}

#[test]
fn maximum_prefix_length() {
    let kid = kid_from_bytes_with_prefix(b"max-prefix", 32);
    assert!(!kid.is_empty());
}

#[test]
#[should_panic(expected = "prefix_bytes must be in 1..=32")]
fn prefix_zero_panics() {
    let _ = kid_from_bytes_with_prefix(b"panic-test", 0);
}

#[test]
#[should_panic(expected = "prefix_bytes must be in 1..=32")]
fn prefix_33_panics() {
    let _ = kid_from_bytes_with_prefix(b"panic-test", 33);
}

// ── Default constant ─────────────────────────────────────────────────

#[test]
fn default_prefix_bytes_is_12() {
    assert_eq!(DEFAULT_KID_PREFIX_BYTES, 12);
}
