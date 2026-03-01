use proptest::prelude::*;
use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

fn valid_pem() -> &'static str {
    "-----BEGIN TEST KEY-----\nABCDEFGH\n-----END TEST KEY-----\n"
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// corrupt_pem_deterministic is stable for the same variant.
    #[test]
    fn deterministic_corruption_is_stable(variant in ".*") {
        let a = corrupt_pem_deterministic(valid_pem(), &variant);
        let b = corrupt_pem_deterministic(valid_pem(), &variant);
        prop_assert_eq!(a, b);
    }

    /// corrupt_pem_deterministic always produces output different from input.
    #[test]
    fn deterministic_corruption_changes_output(variant in "[a-z]{1,16}") {
        let result = corrupt_pem_deterministic(valid_pem(), &variant);
        prop_assert_ne!(result, valid_pem());
    }

    /// BadHeader corruption always replaces the first line.
    #[test]
    fn bad_header_replaces_first_line(
        body in "[A-Za-z0-9+/=]{4,32}",
    ) {
        let pem = format!("-----BEGIN TEST-----\n{body}\n-----END TEST-----\n");
        let corrupted = corrupt_pem(&pem, CorruptPem::BadHeader);
        prop_assert!(corrupted.starts_with("-----BEGIN CORRUPTED KEY-----\n"));
        prop_assert!(corrupted.contains(&body));
    }

    /// BadFooter corruption always replaces the last line.
    #[test]
    fn bad_footer_replaces_last_line(
        body in "[A-Za-z0-9+/=]{4,32}",
    ) {
        let pem = format!("-----BEGIN TEST-----\n{body}\n-----END TEST-----\n");
        let corrupted = corrupt_pem(&pem, CorruptPem::BadFooter);
        prop_assert!(corrupted.contains("-----END CORRUPTED KEY-----\n"));
        prop_assert!(corrupted.contains(&body));
    }

    /// BadBase64 corruption injects invalid base64 into the PEM.
    #[test]
    fn bad_base64_injects_invalid_data(
        body in "[A-Za-z0-9+/=]{4,32}",
    ) {
        let pem = format!("-----BEGIN TEST-----\n{body}\n-----END TEST-----\n");
        let corrupted = corrupt_pem(&pem, CorruptPem::BadBase64);
        prop_assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
    }

    /// Truncate corruption produces output no longer than the requested byte count.
    #[test]
    fn truncate_respects_limit(bytes in 0usize..=128) {
        let corrupted = corrupt_pem(valid_pem(), CorruptPem::Truncate { bytes });
        prop_assert!(corrupted.len() <= bytes);
    }

    /// corrupt_pem never panics on any CorruptPem variant and valid PEM input.
    #[test]
    fn corrupt_pem_never_panics_on_valid_pem(
        body in "[A-Za-z0-9+/=]{4,32}",
        strategy in 0u8..5,
    ) {
        let pem = format!("-----BEGIN TEST-----\n{body}\n-----END TEST-----\n");
        let how = match strategy {
            0 => CorruptPem::BadHeader,
            1 => CorruptPem::BadFooter,
            2 => CorruptPem::BadBase64,
            3 => CorruptPem::ExtraBlankLine,
            _ => CorruptPem::Truncate { bytes: 10 },
        };
        let _ = corrupt_pem(&pem, how);
    }
}
