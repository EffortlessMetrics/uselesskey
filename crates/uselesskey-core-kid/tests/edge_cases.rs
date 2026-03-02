//! Edge-case and boundary tests for KID generation.

use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

// ── Empty input ─────────────────────────────────────────────────────

#[test]
fn kid_from_empty_bytes() {
    let kid = kid_from_bytes(b"");
    assert!(!kid.is_empty(), "KID from empty bytes should be non-empty");
}

#[test]
fn kid_from_empty_bytes_is_deterministic() {
    let k1 = kid_from_bytes(b"");
    let k2 = kid_from_bytes(b"");
    assert_eq!(k1, k2);
}

// ── Boundary prefix_bytes ───────────────────────────────────────────

#[test]
fn kid_with_prefix_bytes_1() {
    let kid = kid_from_bytes_with_prefix(b"test", 1);
    // 1 byte = 8 bits, base64url encodes to ~2 chars
    assert!(!kid.is_empty());
    assert!(kid.len() <= 4, "1-byte prefix should produce short kid");
}

#[test]
fn kid_with_prefix_bytes_32() {
    let kid = kid_from_bytes_with_prefix(b"test", 32);
    // 32 bytes = full BLAKE3 output, base64url encodes to 43 chars
    assert!(
        kid.len() >= 40,
        "32-byte prefix should produce ~43 char kid"
    );
}

#[test]
#[should_panic]
fn kid_with_prefix_bytes_0_panics() {
    kid_from_bytes_with_prefix(b"test", 0);
}

#[test]
#[should_panic]
fn kid_with_prefix_bytes_33_panics() {
    kid_from_bytes_with_prefix(b"test", 33);
}

// ── Default prefix ──────────────────────────────────────────────────

#[test]
fn default_prefix_bytes_is_12() {
    assert_eq!(DEFAULT_KID_PREFIX_BYTES, 12);
}

#[test]
fn kid_from_bytes_uses_default_prefix() {
    let k1 = kid_from_bytes(b"hello");
    let k2 = kid_from_bytes_with_prefix(b"hello", DEFAULT_KID_PREFIX_BYTES);
    assert_eq!(k1, k2);
}

// ── Determinism ─────────────────────────────────────────────────────

#[test]
fn different_inputs_produce_different_kids() {
    let k1 = kid_from_bytes(b"key-a");
    let k2 = kid_from_bytes(b"key-b");
    assert_ne!(k1, k2);
}

#[test]
fn single_bit_difference_produces_different_kid() {
    let k1 = kid_from_bytes(&[0x00]);
    let k2 = kid_from_bytes(&[0x01]);
    assert_ne!(k1, k2);
}

// ── Large input ─────────────────────────────────────────────────────

#[test]
fn kid_from_large_input() {
    let large = vec![0xAB; 100_000];
    let kid = kid_from_bytes(&large);
    assert!(!kid.is_empty());
}

// ── Base64url format ────────────────────────────────────────────────

#[test]
fn kid_contains_only_base64url_chars() {
    let kid = kid_from_bytes(b"test key material");
    for ch in kid.chars() {
        assert!(
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
            "KID contains non-base64url char: {ch:?}"
        );
    }
}

#[test]
fn kid_has_no_padding() {
    // base64url without padding should never contain '='
    let kid = kid_from_bytes(b"test");
    assert!(!kid.contains('='), "KID should not contain padding");
}

// ── Unicode inputs ──────────────────────────────────────────────────

#[test]
fn kid_from_unicode_bytes() {
    let kid = kid_from_bytes("héllo wörld".as_bytes());
    assert!(!kid.is_empty());
    assert!(
        kid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "KID from unicode should still be base64url"
    );
}

#[test]
fn kid_from_unicode_is_deterministic() {
    let input = "日本語テスト🔑".as_bytes();
    let k1 = kid_from_bytes(input);
    let k2 = kid_from_bytes(input);
    assert_eq!(k1, k2);
}

#[test]
fn kid_from_emoji_bytes() {
    let kid = kid_from_bytes("🔐🔑🗝️".as_bytes());
    assert!(!kid.is_empty());
}

#[test]
fn kid_different_unicode_inputs_differ() {
    let k1 = kid_from_bytes("café".as_bytes());
    let k2 = kid_from_bytes("cafe".as_bytes());
    assert_ne!(k1, k2, "unicode vs ascii should differ");
}

#[test]
fn kid_from_nul_bytes() {
    let kid = kid_from_bytes(&[0x00, 0x00, 0x00]);
    assert!(!kid.is_empty());
}

// ── All-same-byte patterns ──────────────────────────────────────────

#[test]
fn kid_from_all_zeros_vs_all_ones() {
    let k1 = kid_from_bytes(&[0x00; 32]);
    let k2 = kid_from_bytes(&[0xFF; 32]);
    assert_ne!(k1, k2);
}

// ── Prefix length affects output ────────────────────────────────────

#[test]
fn different_prefix_lengths_produce_different_kid_lengths() {
    let short = kid_from_bytes_with_prefix(b"key", 4);
    let long = kid_from_bytes_with_prefix(b"key", 16);
    assert!(short.len() < long.len());
}

#[test]
fn kid_from_bytes_equals_default_prefix() {
    let k1 = kid_from_bytes(b"test-key-material");
    let k2 = kid_from_bytes_with_prefix(b"test-key-material", DEFAULT_KID_PREFIX_BYTES);
    assert_eq!(k1, k2);
}
