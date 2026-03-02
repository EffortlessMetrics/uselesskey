use proptest::prelude::*;
use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

const SAMPLE_PEM: &str =
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH\n-----END RSA PRIVATE KEY-----\n";

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn bad_header_always_corrupts_header(input in "[A-Z ]{3,20}") {
        let pem = format!("-----BEGIN {input}-----\nDATA=\n-----END {input}-----\n");
        let out = corrupt_pem(&pem, CorruptPem::BadHeader);
        prop_assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----"));
        let expected_start = format!("-----BEGIN {input}-----");
        prop_assert!(!out.starts_with(&expected_start));
    }

    #[test]
    fn bad_footer_always_corrupts_footer(input in "[A-Z ]{3,20}") {
        let pem = format!("-----BEGIN {input}-----\nDATA=\n-----END {input}-----\n");
        let out = corrupt_pem(&pem, CorruptPem::BadFooter);
        prop_assert!(out.contains("-----END CORRUPTED KEY-----"));
        let expected_end = format!("-----END {input}-----\n");
        prop_assert!(!out.ends_with(&expected_end));
    }

    #[test]
    fn bad_base64_injects_invalid_data(input in "[A-Z ]{3,20}") {
        let pem = format!("-----BEGIN {input}-----\nDATA=\n-----END {input}-----\n");
        let out = corrupt_pem(&pem, CorruptPem::BadBase64);
        prop_assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn truncate_produces_exact_length(bytes in 0usize..50) {
        let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes });
        prop_assert_eq!(out.chars().count(), bytes.min(SAMPLE_PEM.chars().count()));
    }

    #[test]
    fn extra_blank_line_adds_empty_line(input in "[A-Z ]{3,20}") {
        let pem = format!("-----BEGIN {input}-----\nDATA=\n-----END {input}-----\n");
        let out = corrupt_pem(&pem, CorruptPem::ExtraBlankLine);
        let lines: Vec<&str> = out.lines().collect();
        let orig_lines: Vec<&str> = pem.lines().collect();
        prop_assert!(lines.len() > orig_lines.len());
        prop_assert!(lines.contains(&""));
    }

    #[test]
    fn deterministic_corruption_is_stable(variant in "[a-z0-9:_-]{1,32}") {
        let a = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        let b = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn corrupt_output_differs_from_original(variant in "[a-z0-9:_-]{1,32}") {
        let out = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        prop_assert_ne!(out, SAMPLE_PEM);
    }
}
