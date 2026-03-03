use proptest::prelude::*;
use uselesskey_core_hmac_spec::HmacSpec;

fn arb_hmac_spec() -> impl Strategy<Value = HmacSpec> {
    prop_oneof![
        Just(HmacSpec::Hs256),
        Just(HmacSpec::Hs384),
        Just(HmacSpec::Hs512),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn byte_len_matches_alg(spec in arb_hmac_spec()) {
        let expected = match spec.alg_name() {
            "HS256" => 32,
            "HS384" => 48,
            "HS512" => 64,
            other => panic!("unexpected alg: {other}"),
        };
        prop_assert_eq!(spec.byte_len(), expected);
    }

    #[test]
    fn alg_name_starts_with_hs(spec in arb_hmac_spec()) {
        prop_assert!(spec.alg_name().starts_with("HS"));
    }

    #[test]
    fn stable_bytes_length_is_four(spec in arb_hmac_spec()) {
        prop_assert_eq!(spec.stable_bytes().len(), 4);
    }

    #[test]
    fn stable_bytes_are_nonzero(spec in arb_hmac_spec()) {
        prop_assert_ne!(spec.stable_bytes(), [0, 0, 0, 0]);
    }

    #[test]
    fn clone_preserves_equality(spec in arb_hmac_spec()) {
        #[allow(clippy::clone_on_copy)]
        let cloned = spec.clone();
        prop_assert_eq!(spec, cloned);
        prop_assert_eq!(spec.alg_name(), cloned.alg_name());
        prop_assert_eq!(spec.byte_len(), cloned.byte_len());
        prop_assert_eq!(spec.stable_bytes(), cloned.stable_bytes());
    }

    #[test]
    fn all_pairs_have_distinct_stable_bytes(
        a in arb_hmac_spec(),
        b in arb_hmac_spec(),
    ) {
        if a != b {
            prop_assert_ne!(a.stable_bytes(), b.stable_bytes());
            prop_assert_ne!(a.alg_name(), b.alg_name());
            prop_assert_ne!(a.byte_len(), b.byte_len());
        }
    }

    #[test]
    fn byte_len_is_power_of_sixteen(spec in arb_hmac_spec()) {
        prop_assert_eq!(spec.byte_len() % 16, 0);
    }
}
