//! Mutant-killing tests for KID generation.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

#[test]
fn default_prefix_is_12() {
    assert_eq!(DEFAULT_KID_PREFIX_BYTES, 12);
}

#[test]
fn kid_from_bytes_produces_16_char_base64url() {
    // 12 bytes base64url-encoded = ceil(12 * 4 / 3) = 16 chars (no padding)
    let kid = kid_from_bytes(b"test-key-material");
    assert_eq!(kid.len(), 16);
}

#[test]
fn kid_from_bytes_with_prefix_1_produces_short_kid() {
    let kid = kid_from_bytes_with_prefix(b"test", 1);
    // 1 byte = ceil(1 * 4/3) = 2 chars base64url
    let decoded = URL_SAFE_NO_PAD.decode(&kid).unwrap();
    assert_eq!(decoded.len(), 1);
}

#[test]
fn kid_from_bytes_with_prefix_32_produces_longest_kid() {
    let kid = kid_from_bytes_with_prefix(b"test", 32);
    let decoded = URL_SAFE_NO_PAD.decode(&kid).unwrap();
    assert_eq!(decoded.len(), 32);
}

#[test]
#[should_panic(expected = "prefix_bytes must be in 1..=32")]
fn kid_prefix_33_panics() {
    let _ = kid_from_bytes_with_prefix(b"test", 33);
}

#[test]
fn kid_uses_blake3_hash() {
    let input = b"my-public-key-bytes";
    let kid = kid_from_bytes(input);

    // Manually compute expected
    let digest = blake3::hash(input);
    let expected = URL_SAFE_NO_PAD.encode(&digest.as_bytes()[..DEFAULT_KID_PREFIX_BYTES]);
    assert_eq!(kid, expected);
}

#[test]
fn kid_different_inputs_produce_different_kids() {
    let a = kid_from_bytes(b"key-material-a");
    let b = kid_from_bytes(b"key-material-b");
    let c = kid_from_bytes(b"key-material-c");
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

#[test]
fn kid_is_url_safe() {
    let kid = kid_from_bytes(b"test-key");
    assert!(
        kid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    );
}
