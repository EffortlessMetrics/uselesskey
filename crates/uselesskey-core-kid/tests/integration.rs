use rstest::rstest;
use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

// ── determinism ──────────────────────────────────────────────────────

#[test]
fn kid_is_deterministic_from_same_spki_bytes() {
    let spki = b"mock-spki-public-key-bytes";
    assert_eq!(kid_from_bytes(spki), kid_from_bytes(spki));
}

#[rstest]
#[case(b"key-a" as &[u8])]
#[case(b"key-b")]
#[case(b"")]
#[case(&[0u8; 256])]
fn kid_is_stable_across_calls(#[case] input: &[u8]) {
    let first = kid_from_bytes(input);
    let second = kid_from_bytes(input);
    assert_eq!(first, second);
}

// ── different inputs produce different KIDs ──────────────────────────

#[test]
fn different_spki_bytes_produce_different_kids() {
    let kid_a = kid_from_bytes(b"public-key-a");
    let kid_b = kid_from_bytes(b"public-key-b");
    assert_ne!(kid_a, kid_b);
}

#[test]
fn single_bit_difference_produces_different_kid() {
    let a = [0u8; 32];
    let mut b = [0u8; 32];
    b[0] = 1;
    assert_ne!(kid_from_bytes(&a), kid_from_bytes(&b));

    let mut c = [0u8; 32];
    c[31] = 0xFF;
    let mut d = [0u8; 32];
    d[31] = 0xFE;
    assert_ne!(kid_from_bytes(&c), kid_from_bytes(&d));
}

// ── KID format (base64url, correct length) ───────────────────────────

#[test]
fn kid_is_valid_base64url_no_padding() {
    let kid = kid_from_bytes(b"test-key-material");

    // base64url charset: A-Z, a-z, 0-9, -, _
    for ch in kid.chars() {
        assert!(
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
            "unexpected character '{ch}' in KID"
        );
    }

    // No padding characters
    assert!(!kid.contains('='));
}

#[test]
fn default_kid_decodes_to_expected_byte_count() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let kid = kid_from_bytes(b"test-key");
    let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes()).unwrap();
    assert_eq!(decoded.len(), DEFAULT_KID_PREFIX_BYTES);
}

#[test]
fn default_kid_has_expected_string_length() {
    let kid = kid_from_bytes(b"test-key");
    // 12 bytes → ceil(12 * 4/3) = 16 base64 characters (no padding needed since 12 is divisible by 3)
    assert_eq!(kid.len(), 16);
}

// ── custom prefix lengths ────────────────────────────────────────────

#[rstest]
#[case(1)]
#[case(4)]
#[case(12)]
#[case(16)]
#[case(32)]
fn custom_prefix_produces_correct_decoded_length(#[case] prefix_bytes: usize) {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let kid = kid_from_bytes_with_prefix(b"test-key", prefix_bytes);
    let decoded = URL_SAFE_NO_PAD.decode(kid.as_bytes()).unwrap();
    assert_eq!(decoded.len(), prefix_bytes);
}

#[test]
#[should_panic(expected = "prefix_bytes must be in 1..=32")]
fn prefix_zero_panics() {
    let _ = kid_from_bytes_with_prefix(b"test", 0);
}

#[test]
#[should_panic(expected = "prefix_bytes must be in 1..=32")]
fn prefix_too_large_panics() {
    let _ = kid_from_bytes_with_prefix(b"test", 33);
}

// ── no key material leakage ──────────────────────────────────────────

#[test]
fn kid_does_not_contain_raw_input() {
    let input = b"my-secret-public-key-bytes-1234567890";
    let kid = kid_from_bytes(input);

    // KID should be a short hash, not contain the raw input
    let input_str = String::from_utf8_lossy(input);
    assert!(!kid.contains(&*input_str));
    assert!(kid.len() < input.len());
}
