//! Integration tests for core hash helpers — edge cases and boundary conditions.

use uselesskey_core_hash::{Hash, Hasher, hash32, write_len_prefixed};

// ── hash32 edge cases ────────────────────────────────────────────────

#[test]
fn hash32_empty_input_is_deterministic() {
    let a = hash32(b"");
    let b = hash32(b"");
    assert_eq!(a, b);
}

#[test]
fn hash32_single_byte_differs_from_empty() {
    assert_ne!(hash32(b""), hash32(b"\0"));
}

#[test]
fn hash32_returns_32_byte_digest() {
    let h = hash32(b"test");
    assert_eq!(h.as_bytes().len(), 32);
}

// ── write_len_prefixed boundary hashing ──────────────────────────────

#[test]
fn different_tuple_boundaries_produce_different_hashes() {
    // ("ab", "c") != ("a", "bc") due to length prefixes
    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"ab");
    write_len_prefixed(&mut h1, b"c");

    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, b"a");
    write_len_prefixed(&mut h2, b"bc");

    assert_ne!(h1.finalize(), h2.finalize());
}

#[test]
fn empty_field_is_distinguishable() {
    // ("", "abc") != ("abc",) != ("abc", "")
    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"");
    write_len_prefixed(&mut h1, b"abc");

    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, b"abc");

    let mut h3 = Hasher::new();
    write_len_prefixed(&mut h3, b"abc");
    write_len_prefixed(&mut h3, b"");

    assert_ne!(h1.finalize(), h2.finalize());
    assert_ne!(h2.finalize(), h3.finalize());
    assert_ne!(h1.finalize(), h3.finalize());
}

#[test]
fn single_bit_difference_propagates() {
    let a = [0u8; 64];
    let mut b = [0u8; 64];
    b[63] = 1;

    assert_ne!(hash32(&a), hash32(&b));
}

// ── re-exported types are usable ─────────────────────────────────────

#[test]
fn hasher_reexport_can_finalize() {
    let mut h = Hasher::new();
    h.update(b"test");
    let result: Hash = h.finalize();
    assert_eq!(result, hash32(b"test"));
}

#[test]
fn hash_display_is_hex() {
    let h = hash32(b"test");
    let s = format!("{h}");
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(s.len(), 64); // 32 bytes = 64 hex chars
}

// ── multi-field determinism ──────────────────────────────────────────

#[test]
fn multi_field_hash_is_deterministic() {
    let compute = || {
        let mut h = Hasher::new();
        write_len_prefixed(&mut h, b"domain");
        write_len_prefixed(&mut h, b"label");
        write_len_prefixed(&mut h, b"spec-bytes");
        h.finalize()
    };

    assert_eq!(compute(), compute());
}

#[test]
fn field_order_matters() {
    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"alpha");
    write_len_prefixed(&mut h1, b"beta");

    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, b"beta");
    write_len_prefixed(&mut h2, b"alpha");

    assert_ne!(h1.finalize(), h2.finalize());
}

// ── Additional boundary tests ───────────────────────────────────────

#[test]
fn hash32_single_zero_byte_is_valid() {
    let h = hash32(&[0x00]);
    assert_eq!(h.as_bytes().len(), 32);
    assert_ne!(h, hash32(b""), "\\0 differs from empty");
}

#[test]
fn write_len_prefixed_single_byte_values_differ() {
    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, &[0x00]);

    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, &[0x01]);

    assert_ne!(h1.finalize(), h2.finalize());
}

#[test]
fn hash32_large_input() {
    let data = vec![0xAB; 100_000];
    let h = hash32(&data);
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn write_len_prefixed_three_empty_fields_differs_from_two() {
    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, b"");
    write_len_prefixed(&mut h2, b"");

    let mut h3 = Hasher::new();
    write_len_prefixed(&mut h3, b"");
    write_len_prefixed(&mut h3, b"");
    write_len_prefixed(&mut h3, b"");

    assert_ne!(h2.finalize(), h3.finalize());
}
