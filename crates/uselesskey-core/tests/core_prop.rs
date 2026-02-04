use proptest::prelude::*;

use uselesskey_core::negative::{corrupt_pem, truncate_der, CorruptPem};
use uselesskey_core::{ArtifactId, DerivationVersion, Factory, Seed};

fn spec_bytes(bits: u32, e: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&bits.to_be_bytes());
    v.extend_from_slice(&e.to_be_bytes());
    v
}

/// Helper to derive a seed directly using the crate's internal derivation.
fn derive_seed_for_test(master: &Seed, domain: &'static str, label: &str, variant: &str) -> Seed {
    let _id = ArtifactId::new(domain, label, &[0u8; 8], variant, DerivationVersion::V1);
    // Use the factory to observe the derived seed indirectly via determinism.
    let fx = Factory::deterministic(*master);
    let val = fx.get_or_init(domain, label, &[0u8; 8], variant, |rng| {
        use rand_core::RngCore;
        let mut out = [0u8; 32];
        rng.fill_bytes(&mut out);
        out
    });
    Seed::new(*val)
}

#[test]
fn deterministic_is_order_independent_for_cache_keys() {
    let seed = Seed::new([42u8; 32]);
    let fx = Factory::deterministic(seed);

    // Two different artifact keys.
    let a = fx.get_or_init("domain:a", "label", &spec_bytes(1, 2), "good", |_rng| {
        123u32
    });
    let b = fx.get_or_init("domain:b", "label", &spec_bytes(3, 4), "good", |_rng| {
        456u32
    });

    // Clear cache and request in reverse order; values should match.
    fx.clear_cache();
    let b2 = fx.get_or_init("domain:b", "label", &spec_bytes(3, 4), "good", |_rng| {
        456u32
    });
    let a2 = fx.get_or_init("domain:a", "label", &spec_bytes(1, 2), "good", |_rng| {
        123u32
    });

    assert_eq!(*a, *a2);
    assert_eq!(*b, *b2);
}

proptest! {
    #[test]
    fn deterministic_factory_returns_same_value_for_same_id(seed_bytes in any::<[u8;32]>(), label in "[-_a-zA-Z0-9]{1,32}") {
        let fx = Factory::deterministic(Seed::new(seed_bytes));
        let spec = spec_bytes(2048, 65537);

        let v1 = fx.get_or_init("domain:test", &label, &spec, "good", |_rng| 7u32);
        let v2 = fx.get_or_init("domain:test", &label, &spec, "good", |_rng| 7u32);

        prop_assert_eq!(*v1, *v2);
    }

    // =========================================================================
    // Seed::from_env_value() tests
    // =========================================================================

    /// Seed::from_env_value() handles arbitrary strings without panicking.
    /// It returns Ok for most strings (hashing them), but may return Err
    /// for 64-byte strings that look like hex but contain invalid hex chars.
    #[test]
    fn seed_from_env_value_handles_arbitrary_strings(s in ".*") {
        // Should never panic. May return Ok or Err depending on input.
        let _result = Seed::from_env_value(&s);
        // If we got here without panicking, the test passes.
    }

    /// Seed::from_env_value() returns Ok for ASCII strings that are not 64 bytes.
    /// (64-byte strings may be parsed as hex which can fail if invalid hex chars.)
    #[test]
    fn seed_from_env_value_non_64_byte_ascii_strings_always_ok(s in "[a-zA-Z0-9!@#$%^&*()]{0,63}|[a-zA-Z0-9!@#$%^&*()]{65,200}") {
        let trimmed = s.trim();
        let after_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        // Only test if not 64 bytes after processing.
        prop_assume!(after_prefix.len() != 64);

        let result = Seed::from_env_value(&s);
        prop_assert!(result.is_ok(), "Non-64-byte strings should always be Ok, got: {:?}", result);
    }

    /// Seed::from_env_value() with valid 64-char hex produces valid seeds.
    #[test]
    fn seed_from_env_value_valid_hex_produces_valid_seeds(hex_bytes in any::<[u8; 32]>()) {
        // Convert bytes to hex string.
        let hex: String = hex_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        prop_assert_eq!(hex.len(), 64);

        let result = Seed::from_env_value(&hex);
        prop_assert!(result.is_ok());

        let seed = result.unwrap();
        prop_assert_eq!(seed.bytes(), &hex_bytes);
    }

    /// Seed::from_env_value() with 0x prefix also works.
    #[test]
    fn seed_from_env_value_valid_hex_with_prefix(hex_bytes in any::<[u8; 32]>()) {
        let hex: String = format!("0x{}", hex_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());

        let result = Seed::from_env_value(&hex);
        prop_assert!(result.is_ok());

        let seed = result.unwrap();
        prop_assert_eq!(seed.bytes(), &hex_bytes);
    }

    // =========================================================================
    // Derivation uniqueness tests
    // =========================================================================

    /// Different seeds produce different derived seeds for the same artifact ID.
    #[test]
    fn different_seeds_produce_different_derived_seeds(
        seed1 in any::<[u8; 32]>(),
        seed2 in any::<[u8; 32]>()
    ) {
        prop_assume!(seed1 != seed2);

        let master1 = Seed::new(seed1);
        let master2 = Seed::new(seed2);

        let derived1 = derive_seed_for_test(&master1, "domain:test", "label", "variant");
        let derived2 = derive_seed_for_test(&master2, "domain:test", "label", "variant");

        prop_assert_ne!(derived1.bytes(), derived2.bytes());
    }

    /// Same seed + different labels produce different derived seeds.
    #[test]
    fn different_labels_produce_different_derived_seeds(
        seed in any::<[u8; 32]>(),
        label1 in "[a-zA-Z0-9]{1,16}",
        label2 in "[a-zA-Z0-9]{1,16}"
    ) {
        prop_assume!(label1 != label2);

        let master = Seed::new(seed);

        let derived1 = derive_seed_for_test(&master, "domain:test", &label1, "variant");
        let derived2 = derive_seed_for_test(&master, "domain:test", &label2, "variant");

        prop_assert_ne!(derived1.bytes(), derived2.bytes());
    }

    /// Same seed + different variants produce different derived seeds.
    #[test]
    fn different_variants_produce_different_derived_seeds(
        seed in any::<[u8; 32]>(),
        variant1 in "[a-zA-Z0-9]{1,16}",
        variant2 in "[a-zA-Z0-9]{1,16}"
    ) {
        prop_assume!(variant1 != variant2);

        let master = Seed::new(seed);

        let derived1 = derive_seed_for_test(&master, "domain:test", "label", &variant1);
        let derived2 = derive_seed_for_test(&master, "domain:test", "label", &variant2);

        prop_assert_ne!(derived1.bytes(), derived2.bytes());
    }

    // =========================================================================
    // truncate_der() tests
    // =========================================================================

    /// truncate_der() with length >= original returns original.
    #[test]
    fn truncate_der_with_length_gte_original_returns_original(
        der in prop::collection::vec(any::<u8>(), 1..256),
        extra in 0usize..100
    ) {
        let len = der.len() + extra;
        let result = truncate_der(&der, len);
        prop_assert_eq!(result, der);
    }

    /// truncate_der() with length < original returns truncated version.
    #[test]
    fn truncate_der_with_length_lt_original_returns_truncated(
        der in prop::collection::vec(any::<u8>(), 2..256),
        divisor in 1usize..10
    ) {
        let len = der.len() / divisor.max(1);
        prop_assume!(len < der.len());

        let result = truncate_der(&der, len);
        prop_assert_eq!(result.len(), len);
        prop_assert_eq!(result, &der[..len]);
    }

    // =========================================================================
    // corrupt_pem() tests
    // =========================================================================

    /// All CorruptPem variants produce outputs that differ from input.
    #[test]
    fn corrupt_pem_all_variants_differ_from_input(
        body in "[A-Za-z0-9+/]{64,256}"
    ) {
        // Build a minimal valid PEM structure.
        let pem = format!("-----BEGIN TEST KEY-----\n{body}\n-----END TEST KEY-----");

        let variants = [
            CorruptPem::BadHeader,
            CorruptPem::BadFooter,
            CorruptPem::BadBase64,
            CorruptPem::Truncate { bytes: pem.len() / 2 },
            CorruptPem::ExtraBlankLine,
        ];

        for variant in variants {
            let corrupted = corrupt_pem(&pem, variant);
            prop_assert_ne!(
                corrupted, pem.clone(),
                "CorruptPem::{:?} should produce output different from input",
                variant
            );
        }
    }
}
