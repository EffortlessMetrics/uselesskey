//! Mutant-killing tests for the hash module.

use blake3::Hasher;
use uselesskey_core_hash::{hash32, write_len_prefixed};

#[test]
fn hash32_empty_input() {
    let h = hash32(b"");
    assert_eq!(h, blake3::hash(b""));
}

#[test]
fn hash32_single_byte_input() {
    let h = hash32(b"x");
    assert_eq!(h, blake3::hash(b"x"));
}

#[test]
fn write_len_prefixed_empty_data() {
    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"");

    let mut h2 = Hasher::new();
    h2.update(&0u32.to_be_bytes());
    h2.update(b"");

    assert_eq!(h1.finalize(), h2.finalize());
}

#[test]
fn write_len_prefixed_uses_4_byte_big_endian_length() {
    let data = b"hello";
    let mut h = Hasher::new();
    write_len_prefixed(&mut h, data);

    let mut expected = Hasher::new();
    expected.update(&5u32.to_be_bytes());
    expected.update(data);
    assert_eq!(h.finalize(), expected.finalize());
}

#[test]
fn write_len_prefixed_different_data_different_hashes() {
    let mut a = Hasher::new();
    write_len_prefixed(&mut a, b"abc");

    let mut b = Hasher::new();
    write_len_prefixed(&mut b, b"abd");

    assert_ne!(a.finalize(), b.finalize());
}

#[test]
fn boundary_ambiguity_prevented_by_length_prefix() {
    // "a" + "bc" vs "ab" + "c" should differ
    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"a");
    write_len_prefixed(&mut h1, b"bc");

    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, b"ab");
    write_len_prefixed(&mut h2, b"c");

    assert_ne!(h1.finalize(), h2.finalize());
}

#[test]
fn write_len_prefixed_length_byte_order_matters() {
    // Verify it's big-endian: length 256 = [0, 0, 1, 0] in BE
    let data = vec![0u8; 256];
    let mut h = Hasher::new();
    write_len_prefixed(&mut h, &data);

    let mut expected = Hasher::new();
    expected.update(&256u32.to_be_bytes());
    expected.update(&data);
    assert_eq!(h.finalize(), expected.finalize());
}
