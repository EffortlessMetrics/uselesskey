use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_base62::{BASE62_ALPHABET, random_base62};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn output_length_matches_requested(seed in any::<[u8; 32]>(), len in 0usize..256) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let out = random_base62(&mut rng, len);
        prop_assert_eq!(out.len(), len);
    }

    #[test]
    fn output_contains_only_base62_chars(seed in any::<[u8; 32]>(), len in 1usize..256) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let out = random_base62(&mut rng, len);
        for b in out.bytes() {
            prop_assert!(
                BASE62_ALPHABET.contains(&b),
                "byte {} is not in BASE62_ALPHABET",
                b
            );
        }
    }

    #[test]
    fn deterministic_for_same_seed(seed in any::<[u8; 32]>(), len in 1usize..128) {
        let a = random_base62(&mut ChaCha20Rng::from_seed(seed), len);
        let b = random_base62(&mut ChaCha20Rng::from_seed(seed), len);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_output(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed_a != seed_b);
        let a = random_base62(&mut ChaCha20Rng::from_seed(seed_a), 64);
        let b = random_base62(&mut ChaCha20Rng::from_seed(seed_b), 64);
        prop_assert_ne!(a, b);
    }

    #[test]
    fn zero_length_produces_empty_string(seed in any::<[u8; 32]>()) {
        let out = random_base62(&mut ChaCha20Rng::from_seed(seed), 0);
        prop_assert!(out.is_empty());
    }
}
