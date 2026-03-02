use proptest::prelude::*;
use uselesskey_core_seed::Seed;

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn seed_roundtrip_bytes(bytes in any::<[u8; 32]>()) {
        let seed = Seed::new(bytes);
        prop_assert_eq!(*seed.bytes(), bytes);
    }

    #[test]
    fn seed_debug_never_leaks_bytes(bytes in any::<[u8; 32]>()) {
        let seed = Seed::new(bytes);
        let debug = format!("{:?}", seed);
        prop_assert_eq!(debug, "Seed(**redacted**)");
    }

    #[test]
    fn seed_from_hex_is_deterministic(bytes in any::<[u8; 32]>()) {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let a = Seed::from_env_value(&hex).unwrap();
        let b = Seed::from_env_value(&hex).unwrap();
        prop_assert_eq!(a.bytes(), b.bytes());
    }

    #[test]
    fn seed_from_hex_with_0x_prefix(bytes in any::<[u8; 32]>()) {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let without = Seed::from_env_value(&hex).unwrap();
        let with = Seed::from_env_value(&format!("0x{hex}")).unwrap();
        prop_assert_eq!(without.bytes(), with.bytes());
    }

    #[test]
    fn seed_from_string_is_deterministic(s in "[a-zA-Z0-9_]{1,63}") {
        let a = Seed::from_env_value(&s).unwrap();
        let b = Seed::from_env_value(&s).unwrap();
        prop_assert_eq!(a.bytes(), b.bytes());
    }

    #[test]
    fn seed_from_different_strings_differ(
        s1 in "[a-zA-Z]{1,32}",
        s2 in "[a-zA-Z]{1,32}",
    ) {
        prop_assume!(s1 != s2);
        let a = Seed::from_env_value(&s1).unwrap();
        let b = Seed::from_env_value(&s2).unwrap();
        prop_assert_ne!(a.bytes(), b.bytes());
    }

    #[test]
    fn seed_from_hex_case_insensitive(bytes in any::<[u8; 32]>()) {
        let lower: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let upper: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
        let a = Seed::from_env_value(&lower).unwrap();
        let b = Seed::from_env_value(&upper).unwrap();
        prop_assert_eq!(a.bytes(), b.bytes());
    }

    #[test]
    fn seed_from_hex_trims_whitespace(bytes in any::<[u8; 32]>()) {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let padded = format!("  {hex}  ");
        let a = Seed::from_env_value(&hex).unwrap();
        let b = Seed::from_env_value(&padded).unwrap();
        prop_assert_eq!(a.bytes(), b.bytes());
    }
}
