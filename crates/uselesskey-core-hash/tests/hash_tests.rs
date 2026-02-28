use blake3::Hasher;
use proptest::prelude::*;
use uselesskey_core_hash::{hash32, write_len_prefixed};

// ---------------------------------------------------------------------------
// 1. Determinism: same inputs always produce same output
// ---------------------------------------------------------------------------

#[test]
fn hash32_deterministic() {
    let data = b"same-input-twice";
    assert_eq!(hash32(data), hash32(data));
}

#[test]
fn write_len_prefixed_deterministic() {
    let build = || {
        let mut h = Hasher::new();
        write_len_prefixed(&mut h, b"domain");
        write_len_prefixed(&mut h, b"label");
        h.finalize()
    };
    assert_eq!(build(), build());
}

#[test]
fn keyed_hasher_deterministic() {
    let seed = [0xABu8; 32];
    let build = || {
        let mut h = Hasher::new_keyed(&seed);
        write_len_prefixed(&mut h, b"domain");
        write_len_prefixed(&mut h, b"label");
        h.finalize()
    };
    assert_eq!(build(), build());
}

// ---------------------------------------------------------------------------
// 2. Different seeds produce different outputs
// ---------------------------------------------------------------------------

#[test]
fn different_seeds_produce_different_outputs() {
    let seed_a = [0x01u8; 32];
    let seed_b = [0x02u8; 32];

    let derive = |seed: &[u8; 32]| {
        let mut h = Hasher::new_keyed(seed);
        write_len_prefixed(&mut h, b"domain");
        write_len_prefixed(&mut h, b"label");
        h.finalize()
    };

    assert_ne!(derive(&seed_a), derive(&seed_b));
}

// ---------------------------------------------------------------------------
// 3. Different domain strings produce different outputs
// ---------------------------------------------------------------------------

#[test]
fn different_domains_produce_different_outputs() {
    let seed = [0xCCu8; 32];

    let derive = |domain: &[u8]| {
        let mut h = Hasher::new_keyed(&seed);
        write_len_prefixed(&mut h, domain);
        write_len_prefixed(&mut h, b"label");
        h.finalize()
    };

    assert_ne!(derive(b"domain-a"), derive(b"domain-b"));
}

// ---------------------------------------------------------------------------
// 4. Different labels produce different outputs
// ---------------------------------------------------------------------------

#[test]
fn different_labels_produce_different_outputs() {
    let seed = [0xCCu8; 32];

    let derive = |label: &[u8]| {
        let mut h = Hasher::new_keyed(&seed);
        write_len_prefixed(&mut h, b"domain");
        write_len_prefixed(&mut h, label);
        h.finalize()
    };

    assert_ne!(derive(b"label-a"), derive(b"label-b"));
}

// ---------------------------------------------------------------------------
// 5. Output is 32 bytes
// ---------------------------------------------------------------------------

#[test]
fn hash32_output_is_32_bytes() {
    let digest = hash32(b"any-data");
    assert_eq!(digest.as_bytes().len(), 32);
}

#[test]
fn keyed_derivation_output_is_32_bytes() {
    let seed = [0x00u8; 32];
    let mut h = Hasher::new_keyed(&seed);
    write_len_prefixed(&mut h, b"domain");
    write_len_prefixed(&mut h, b"label");
    let digest = h.finalize();
    assert_eq!(digest.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// 6. Known test vector stability
// ---------------------------------------------------------------------------

#[test]
fn hash32_known_vector() {
    // Pin the digest so any accidental algorithm change is caught.
    let digest = hash32(b"uselesskey-stability-vector");
    let hex = digest.to_hex();
    assert_eq!(
        hex.as_str(),
        "d3036b403cffb224ed4f2c218a0ba98f00d15f2548f615f3a51034e7196661c0",
        "hash32 known-vector changed — derivation stability broken"
    );
}

#[test]
fn keyed_derivation_known_vector() {
    let seed = [0x42u8; 32];
    let mut h = Hasher::new_keyed(&seed);
    write_len_prefixed(&mut h, b"test-domain");
    write_len_prefixed(&mut h, b"test-label");
    let digest = h.finalize();
    let hex = digest.to_hex();
    assert_eq!(
        hex.as_str(),
        "e6883aa69bb5a2bd036820302f2fda03d9d1403108073992e4039f22bb44ac7c",
        "keyed derivation known-vector changed — derivation stability broken"
    );
}

// ---------------------------------------------------------------------------
// 7. Empty string inputs are handled
// ---------------------------------------------------------------------------

#[test]
fn hash32_empty_input() {
    // Must not panic; result equals blake3::hash of empty slice.
    let digest = hash32(b"");
    assert_eq!(digest, blake3::hash(b""));
}

#[test]
fn write_len_prefixed_empty_input() {
    let mut h = Hasher::new();
    write_len_prefixed(&mut h, b"");
    let digest = h.finalize();

    // Length prefix is 0u32 big-endian followed by zero payload bytes.
    let mut expected = Hasher::new();
    expected.update(&0u32.to_be_bytes());
    assert_eq!(digest, expected.finalize());
}

#[test]
fn keyed_derivation_with_empty_domain_and_label() {
    let seed = [0xFFu8; 32];
    let mut h = Hasher::new_keyed(&seed);
    write_len_prefixed(&mut h, b"");
    write_len_prefixed(&mut h, b"");
    // Must not panic and must still return 32 bytes.
    assert_eq!(h.finalize().as_bytes().len(), 32);
}

#[test]
fn empty_vs_nonempty_differ() {
    let mut a = Hasher::new();
    write_len_prefixed(&mut a, b"");

    let mut b = Hasher::new();
    write_len_prefixed(&mut b, b"x");

    assert_ne!(a.finalize(), b.finalize());
}

// ---------------------------------------------------------------------------
// Property-based tests (proptest)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn prop_output_always_32_bytes(seed in any::<[u8; 32]>(), input in any::<Vec<u8>>()) {
        let mut h = Hasher::new_keyed(&seed);
        write_len_prefixed(&mut h, &input);
        prop_assert_eq!(h.finalize().as_bytes().len(), 32);
    }

    #[test]
    fn prop_hash32_always_32_bytes(data in any::<Vec<u8>>()) {
        prop_assert_eq!(hash32(&data).as_bytes().len(), 32);
    }

    #[test]
    fn prop_single_bit_flip_changes_output(seed in any::<[u8; 32]>(), bit_pos in 0usize..256) {
        let mut flipped = seed;
        flipped[bit_pos / 8] ^= 1 << (bit_pos % 8);

        let derive = |s: &[u8; 32]| {
            let mut h = Hasher::new_keyed(s);
            write_len_prefixed(&mut h, b"collision-test");
            h.finalize()
        };

        prop_assert_ne!(derive(&seed), derive(&flipped));
    }
}
