use proptest::prelude::*;

use uselesskey_core_hash::hash32;
use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

#[test]
fn deterministic_output_is_stable_for_same_variant() {
    let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
    let first = corrupt_pem_deterministic(pem, "integration:variant-1");
    let second = corrupt_pem_deterministic(pem, "integration:variant-1");
    assert_eq!(first, second);
}

#[test]
fn deterministic_variants_produce_at_least_two_shapes_for_fixture() {
    let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
    let one = corrupt_pem_deterministic(pem, &find_variant_for_arm(0));
    let two = corrupt_pem_deterministic(pem, &find_variant_for_arm(1));
    assert_ne!(one, two);
}

#[test]
fn bad_base64_inserts_marker() {
    let out = corrupt_pem("HEADER\nPAYLOAD\nFOOTER\n", CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

fn find_variant_for_arm(target: u8) -> String {
    for i in 0u64.. {
        let candidate = format!("integration-{i}");
        let hash = hash32(candidate.as_bytes());
        let bytes = hash.as_bytes();
        if bytes[0] % 5 == target {
            return candidate;
        }
    }
    unreachable!()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn truncate_length_is_capped(
        pem in "[ -~]{0,512}",
        len in 0usize..1024,
    ) {
        let truncated = corrupt_pem(&pem, CorruptPem::Truncate { bytes: len });
        assert!(truncated.chars().count() <= pem.chars().count());
        assert_eq!(truncated.chars().count(), len.min(pem.chars().count()));
    }

    #[test]
    fn deterministic_corruption_is_reproducible(
        pem in "[ -~]{0,256}",
        variant in "[A-Za-z0-9-]{1,32}",
    ) {
        let a = corrupt_pem_deterministic(&pem, &variant);
        let b = corrupt_pem_deterministic(&pem, &variant);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn extra_blank_line_includes_double_newline(
        pem in "[A-Z]{1,16}\\n[A-Z]{1,16}\\n[A-Z]{1,16}"
    ) {
        let out = corrupt_pem(&pem, CorruptPem::ExtraBlankLine);
        assert!(out.contains("\n\n"));
    }
}
