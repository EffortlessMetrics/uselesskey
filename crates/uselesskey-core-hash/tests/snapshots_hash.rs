//! Insta snapshot tests for uselesskey-core-hash.
//!
//! Snapshot hash output sizes and determinism properties.
//! No actual hash values are captured — only metadata.

use serde::Serialize;
use uselesskey_core_hash::{Hasher, hash32, write_len_prefixed};

#[derive(Serialize)]
struct HashOutputShape {
    input_description: &'static str,
    digest_byte_len: usize,
    hex_len: usize,
}

#[test]
fn snapshot_hash32_output_sizes() {
    let inputs: Vec<(&str, &[u8])> = vec![
        ("empty", b""),
        ("single_byte", b"\x00"),
        ("short_string", b"hello"),
        ("fixture_label", b"deterministic-fixture-hash"),
    ];

    let results: Vec<HashOutputShape> = inputs
        .into_iter()
        .map(|(desc, data)| {
            let h = hash32(data);
            HashOutputShape {
                input_description: desc,
                digest_byte_len: h.as_bytes().len(),
                hex_len: h.to_hex().len(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("hash_output_sizes", results);
}

#[test]
fn snapshot_hash32_determinism() {
    #[derive(Serialize)]
    struct HashDeterminism {
        input_description: &'static str,
        same_input_matches: bool,
        different_inputs_differ: bool,
    }

    let a1 = hash32(b"test-key-material");
    let a2 = hash32(b"test-key-material");
    let b = hash32(b"different-material");

    let result = HashDeterminism {
        input_description: "test-key-material",
        same_input_matches: a1 == a2,
        different_inputs_differ: a1 != b,
    };

    insta::assert_yaml_snapshot!("hash_determinism", result);
}

#[test]
fn snapshot_write_len_prefixed_boundary_separation() {
    #[derive(Serialize)]
    struct BoundarySeparation {
        split_a: &'static str,
        split_b: &'static str,
        digests_differ: bool,
    }

    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"a");
    write_len_prefixed(&mut h1, b"bc");

    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, b"ab");
    write_len_prefixed(&mut h2, b"c");

    let result = BoundarySeparation {
        split_a: "[a] + [bc]",
        split_b: "[ab] + [c]",
        digests_differ: h1.finalize() != h2.finalize(),
    };

    insta::assert_yaml_snapshot!("hash_boundary_separation", result);
}

#[test]
fn snapshot_hasher_reexport() {
    #[derive(Serialize)]
    struct HasherMeta {
        new_hasher_digest_len: usize,
        update_then_finalize_len: usize,
    }

    let empty = Hasher::new().finalize();
    let mut h = Hasher::new();
    h.update(b"data");
    let with_data = h.finalize();

    let result = HasherMeta {
        new_hasher_digest_len: empty.as_bytes().len(),
        update_then_finalize_len: with_data.as_bytes().len(),
    };

    insta::assert_yaml_snapshot!("hash_hasher_reexport", result);
}
