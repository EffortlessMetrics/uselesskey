use proptest::prelude::*;
use uselesskey_core_hash::{Hasher, hash32, write_len_prefixed};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// hash32 is deterministic for any input.
    #[test]
    fn hash32_deterministic(data in any::<Vec<u8>>()) {
        prop_assert_eq!(hash32(&data), hash32(&data));
    }

    /// Different inputs produce different hashes (collision resistance).
    #[test]
    fn hash32_different_inputs_differ(a in any::<Vec<u8>>(), b in any::<Vec<u8>>()) {
        prop_assume!(a != b);
        prop_assert_ne!(hash32(&a), hash32(&b));
    }

    /// write_len_prefixed preserves tuple boundaries: [a][b] != [a+b].
    #[test]
    fn len_prefix_separates_fields(
        a in prop::collection::vec(any::<u8>(), 1..32),
        b in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        let mut combined = a.clone();
        combined.extend_from_slice(&b);

        let mut h_two = Hasher::new();
        write_len_prefixed(&mut h_two, &a);
        write_len_prefixed(&mut h_two, &b);

        let mut h_one = Hasher::new();
        write_len_prefixed(&mut h_one, &combined);

        prop_assert_ne!(h_two.finalize(), h_one.finalize());
    }

    /// write_len_prefixed is deterministic.
    #[test]
    fn write_len_prefixed_deterministic(data in any::<Vec<u8>>()) {
        let mut h1 = Hasher::new();
        write_len_prefixed(&mut h1, &data);

        let mut h2 = Hasher::new();
        write_len_prefixed(&mut h2, &data);

        prop_assert_eq!(h1.finalize(), h2.finalize());
    }
}
