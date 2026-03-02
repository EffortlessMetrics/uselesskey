#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Length-prefixed hashing helpers for deterministic fixture derivation.
//!
//! Wraps BLAKE3 to provide collision-resistant, deterministic digests used
//! throughout the `uselesskey` workspace for seed derivation and artifact identity.

pub use blake3::{Hash, Hasher};

/// Compute a BLAKE3 digest over input bytes.
pub fn hash32(bytes: &[u8]) -> Hash {
    blake3::hash(bytes)
}

/// Write a length-prefixed byte slice into a BLAKE3 hasher.
///
/// This preserves tuple boundaries when multiple fields are concatenated.
pub fn write_len_prefixed(hasher: &mut Hasher, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(&len.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::{hash32, write_len_prefixed};
    use blake3::Hasher;
    use proptest::prelude::*;

    #[test]
    fn hash32_matches_blake3_hash() {
        let data = b"deterministic-fixture-hash";
        assert_eq!(hash32(data), blake3::hash(data));
    }

    #[test]
    fn write_len_prefixed_uses_big_endian_length() {
        let data = b"abc";
        let expected_len = 3u32.to_be_bytes();

        let mut hasher = Hasher::new();
        hasher.update(&expected_len);
        hasher.update(data);
        let expected = hasher.finalize();

        let mut hasher2 = Hasher::new();
        write_len_prefixed(&mut hasher2, data);
        let actual = hasher2.finalize();

        assert_eq!(actual, expected);
    }

    #[test]
    fn len_prefix_changes_on_boundary_change() {
        let mut a_left = Hasher::new();
        write_len_prefixed(&mut a_left, b"a");
        write_len_prefixed(&mut a_left, b"bc");

        let mut b_left = Hasher::new();
        write_len_prefixed(&mut b_left, b"ab");
        write_len_prefixed(&mut b_left, b"c");

        assert_ne!(a_left.finalize(), b_left.finalize());
    }

    #[test]
    fn hash32_empty_input() {
        let h = hash32(b"");
        assert_eq!(h, blake3::hash(b""));
    }

    #[test]
    fn write_len_prefixed_empty_data() {
        let mut hasher = Hasher::new();
        write_len_prefixed(&mut hasher, b"");
        let actual = hasher.finalize();

        let mut expected_hasher = Hasher::new();
        expected_hasher.update(&0u32.to_be_bytes());
        assert_eq!(actual, expected_hasher.finalize());
    }

    #[test]
    fn hash32_different_inputs_differ() {
        assert_ne!(hash32(b"alpha"), hash32(b"beta"));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        #[test]
        fn hash32_is_deterministic_for_random_inputs(data in any::<Vec<u8>>()) {
            let first = hash32(&data);
            let second = hash32(&data);
            assert_eq!(first, second);
        }

        #[test]
        fn write_len_prefixed_matches_direct_length_encoding(data in any::<Vec<u8>>()) {
            let expected_len = (u32::try_from(data.len()).unwrap_or(u32::MAX)).to_be_bytes();

            let mut direct = Hasher::new();
            direct.update(&expected_len);
            direct.update(&data);
            let expected = direct.finalize();

            let mut prefixed = Hasher::new();
            write_len_prefixed(&mut prefixed, &data);
            let actual = prefixed.finalize();

            assert_eq!(actual, expected);
        }
    }
}
