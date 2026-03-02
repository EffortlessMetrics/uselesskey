use proptest::prelude::*;
use uselesskey_core_hash::{Hasher, hash32, write_len_prefixed};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn hash32_deterministic(data in any::<Vec<u8>>()) {
        prop_assert_eq!(hash32(&data), hash32(&data));
    }

    #[test]
    fn hash32_different_inputs_differ(
        a in proptest::collection::vec(any::<u8>(), 1..64),
        b in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(a != b);
        prop_assert_ne!(hash32(&a), hash32(&b));
    }

    #[test]
    fn write_len_prefixed_matches_manual(data in any::<Vec<u8>>()) {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);

        let mut manual = Hasher::new();
        manual.update(&len.to_be_bytes());
        manual.update(&data);

        let mut prefixed = Hasher::new();
        write_len_prefixed(&mut prefixed, &data);

        prop_assert_eq!(manual.finalize(), prefixed.finalize());
    }

    #[test]
    fn len_prefix_prevents_boundary_confusion(
        left in proptest::collection::vec(any::<u8>(), 1..32),
        right in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(left.len() > 1 || right.len() > 1);

        // Split at a different boundary
        let combined: Vec<u8> = left.iter().chain(right.iter()).copied().collect();
        let split_at = if left.len() > 1 { left.len() - 1 } else { left.len() + 1 };
        prop_assume!(split_at < combined.len());
        let (alt_left, alt_right) = combined.split_at(split_at);
        prop_assume!(alt_left != left.as_slice() || alt_right != right.as_slice());

        let mut original = Hasher::new();
        write_len_prefixed(&mut original, &left);
        write_len_prefixed(&mut original, &right);

        let mut alternate = Hasher::new();
        write_len_prefixed(&mut alternate, alt_left);
        write_len_prefixed(&mut alternate, alt_right);

        prop_assert_ne!(original.finalize(), alternate.finalize());
    }

    #[test]
    fn hash32_output_is_32_bytes(data in any::<Vec<u8>>()) {
        prop_assert_eq!(hash32(&data).as_bytes().len(), 32);
    }
}
