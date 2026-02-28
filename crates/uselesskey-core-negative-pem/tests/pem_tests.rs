use std::collections::HashSet;

use proptest::prelude::*;

use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

// ---------------------------------------------------------------------------
// Sample PEM fixtures for different key types
// ---------------------------------------------------------------------------

const RSA_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRw+2v/RvjDtmRMb0pezFDBt/BnkS8P3xnGE8rfRg8z9YvTG6V
YGk0NJ6pU8E+yjSHIgF7txvqP3SLTXjOBfkCAwEAAQJAAdLrsBEt0Jv+e7rkNIz5
N5JRCGEvKq1KyGxhG3rJSE0O+70fYnAswJjHEEqXRiyM2w5A6MdbJNkzk+GPfT1L
AQIhAODc+K3t3FH0WY7V0NGXH/BAfUlm5PIQ7QS6bOyc9nChAiEA0Mc2YUGSfR7d
I00l0V8aGZBjlH9PDTR4eCbQrPJaNakCIQCDW9g4Bkp/EH+wBfPOjcB1YaGW8JUp
FcB2CvqPVcfPYQIgSnj3/v+CPbPCcXH20M3hx2KFKjDm1nNbXg3Fj0PuHFkCIBi4
kBR1iKJnqndz2D8FwBjHHK0sTfBLdMq3mCVqNKMP
-----END RSA PRIVATE KEY-----
";

const EC_PEM: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIODo0NJUV4IMbtLAfsRubMb3VaUHlHMD3xO5SG2p6pBcoAcGBSuBBAAi
oWQDYgAE6JUASYK8VPDyYAUhL6rz9T+1YdO0K+2Ubjm3HqxL8eERqnoeyUxNIXLO
pJWcPmLaQ0BxDzBf1g9BbkohKcHdXns9Kd2JWi5KiC7tJMPGKkJyGZHmFSwVifCa
B7wui4U1
-----END EC PRIVATE KEY-----
";

const ED25519_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHKQGnRPF9Lp2VqwkJFd+xeKNA9kABe2VkJFn4p2Xg5
-----END PRIVATE KEY-----
";

const CERTIFICATE_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh1nBPMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC0cPtr/0b4w7ZkTG9KXsxQ
wbfwZ5EvD98ZxhPK30YPM/WL0xulWBpNDSeqVPBPso0hyIBe7cb6j90i014zwQX5
AgMBAAGjUzBRMB0GA1UdDgQWBBQN1GqF/XUqo8NArFaYLwn2BoN2EjAfBgNVHSME
GDAWgBQN1GqF/XUqo8NArFaYLwn2BoN2EjAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAm4qEv3H8MxRG1Oh+Cv8iRLn5FY4BMQO9MYNIVng0ns2K3gPR
AcnvKINs0iTRGP+1R2f9EylGWOa6VR8f7V2bdQ==
-----END CERTIFICATE-----
";

// ---------------------------------------------------------------------------
// 1. Each CorruptPem variant produces output that differs from the input
// ---------------------------------------------------------------------------

#[test]
fn bad_header_produces_different_output() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    assert_ne!(out, RSA_PEM);
}

#[test]
fn bad_footer_produces_different_output() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    assert_ne!(out, RSA_PEM);
}

#[test]
fn bad_base64_produces_different_output() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadBase64);
    assert_ne!(out, RSA_PEM);
}

#[test]
fn truncate_produces_different_output() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: 20 });
    assert_ne!(out, RSA_PEM);
}

#[test]
fn extra_blank_line_produces_different_output() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::ExtraBlankLine);
    assert_ne!(out, RSA_PEM);
}

// ---------------------------------------------------------------------------
// 2. Corrupt PEM is deterministic (same input → same corrupt output)
// ---------------------------------------------------------------------------

#[test]
fn bad_header_is_deterministic() {
    let a = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    let b = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    assert_eq!(a, b);
}

#[test]
fn bad_footer_is_deterministic() {
    let a = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    let b = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    assert_eq!(a, b);
}

#[test]
fn bad_base64_is_deterministic() {
    let a = corrupt_pem(RSA_PEM, CorruptPem::BadBase64);
    let b = corrupt_pem(RSA_PEM, CorruptPem::BadBase64);
    assert_eq!(a, b);
}

#[test]
fn truncate_is_deterministic() {
    let a = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: 30 });
    let b = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: 30 });
    assert_eq!(a, b);
}

#[test]
fn extra_blank_line_is_deterministic() {
    let a = corrupt_pem(RSA_PEM, CorruptPem::ExtraBlankLine);
    let b = corrupt_pem(RSA_PEM, CorruptPem::ExtraBlankLine);
    assert_eq!(a, b);
}

#[test]
fn deterministic_corruption_stable_across_calls() {
    let a = corrupt_pem_deterministic(RSA_PEM, "test-variant-42");
    let b = corrupt_pem_deterministic(RSA_PEM, "test-variant-42");
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 3. Each variant produces a DIFFERENT corruption (distinct from each other)
// ---------------------------------------------------------------------------

#[test]
fn all_variants_produce_distinct_outputs() {
    let variants = [
        corrupt_pem(RSA_PEM, CorruptPem::BadHeader),
        corrupt_pem(RSA_PEM, CorruptPem::BadFooter),
        corrupt_pem(RSA_PEM, CorruptPem::BadBase64),
        corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: 20 }),
        corrupt_pem(RSA_PEM, CorruptPem::ExtraBlankLine),
    ];
    let unique: HashSet<&String> = variants.iter().collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "Expected all 5 corruption variants to produce distinct output"
    );
}

#[test]
fn bad_header_and_bad_footer_differ() {
    let header = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    let footer = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    assert_ne!(header, footer);
}

#[test]
fn bad_base64_and_extra_blank_line_differ() {
    let base64 = corrupt_pem(RSA_PEM, CorruptPem::BadBase64);
    let blank = corrupt_pem(RSA_PEM, CorruptPem::ExtraBlankLine);
    assert_ne!(base64, blank);
}

// ---------------------------------------------------------------------------
// 4. Corrupted output still looks PEM-shaped where applicable
// ---------------------------------------------------------------------------

#[test]
fn bad_header_keeps_end_marker() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    assert!(
        out.contains("-----END RSA PRIVATE KEY-----"),
        "BadHeader should preserve the footer"
    );
}

#[test]
fn bad_header_has_begin_marker() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    assert!(
        out.contains("-----BEGIN CORRUPTED KEY-----"),
        "BadHeader should inject a BEGIN marker"
    );
}

#[test]
fn bad_footer_keeps_begin_marker() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    assert!(
        out.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "BadFooter should preserve the header"
    );
}

#[test]
fn bad_footer_has_end_marker() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    assert!(
        out.contains("-----END CORRUPTED KEY-----"),
        "BadFooter should inject an END marker"
    );
}

#[test]
fn bad_base64_preserves_begin_and_end_markers() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadBase64);
    assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(out.contains("-----END RSA PRIVATE KEY-----"));
}

#[test]
fn extra_blank_line_preserves_begin_and_end_markers() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::ExtraBlankLine);
    assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(out.contains("-----END RSA PRIVATE KEY-----"));
}

// ---------------------------------------------------------------------------
// 5. Truncation actually truncates
// ---------------------------------------------------------------------------

#[test]
fn truncation_shortens_output() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: 10 });
    assert_eq!(out.chars().count(), 10);
    assert!(out.len() < RSA_PEM.len());
}

#[test]
fn truncation_to_zero_gives_empty_string() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: 0 });
    assert!(out.is_empty());
}

#[test]
fn truncation_to_full_length_preserves_all_chars() {
    let full_len = RSA_PEM.chars().count();
    let out = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: full_len });
    assert_eq!(out.chars().count(), full_len);
}

#[test]
fn truncation_beyond_length_returns_full_input() {
    let full_len = RSA_PEM.chars().count();
    let out = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: full_len + 100 });
    assert_eq!(out.chars().count(), full_len);
}

#[test]
fn truncation_removes_end_marker() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::Truncate { bytes: 30 });
    assert!(
        !out.contains("-----END"),
        "Truncated output at 30 chars should not contain the END marker"
    );
}

// ---------------------------------------------------------------------------
// 6. Base64 corruption actually corrupts the base64 content
// ---------------------------------------------------------------------------

#[test]
fn bad_base64_injects_invalid_base64_marker() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadBase64);
    assert!(
        out.contains("THIS_IS_NOT_BASE64!!!"),
        "BadBase64 should inject a non-base64 line"
    );
}

#[test]
fn bad_base64_line_is_between_header_and_body() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadBase64);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0], "-----BEGIN RSA PRIVATE KEY-----",
        "First line should still be the header"
    );
    assert_eq!(
        lines[1], "THIS_IS_NOT_BASE64!!!",
        "Second line should be the injected bad base64"
    );
}

#[test]
fn bad_base64_on_short_input_appends_marker() {
    let short = "AB";
    let out = corrupt_pem(short, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

// ---------------------------------------------------------------------------
// 7. Header mangling corrupts the header
// ---------------------------------------------------------------------------

#[test]
fn bad_header_removes_original_header() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    assert!(
        !out.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "BadHeader should remove the original header"
    );
}

#[test]
fn bad_header_replaces_with_corrupted_key() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    let first_line = out.lines().next().unwrap();
    assert_eq!(first_line, "-----BEGIN CORRUPTED KEY-----");
}

#[test]
fn bad_header_preserves_body_lines() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadHeader);
    // The body base64 content should still be present
    assert!(out.contains("MIIBogIBAAJBALRw"));
}

#[test]
fn bad_footer_removes_original_footer() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    assert!(
        !out.contains("-----END RSA PRIVATE KEY-----"),
        "BadFooter should remove the original footer"
    );
}

#[test]
fn bad_footer_replaces_with_corrupted_key() {
    let out = corrupt_pem(RSA_PEM, CorruptPem::BadFooter);
    let last_non_empty = out.lines().last().unwrap();
    assert_eq!(last_non_empty, "-----END CORRUPTED KEY-----");
}

// ---------------------------------------------------------------------------
// 8. Works on various PEM types (RSA, EC, Ed25519, Certificate)
// ---------------------------------------------------------------------------

#[test]
fn bad_header_works_on_ec_pem() {
    let out = corrupt_pem(EC_PEM, CorruptPem::BadHeader);
    assert!(out.contains("-----BEGIN CORRUPTED KEY-----"));
    assert!(!out.contains("-----BEGIN EC PRIVATE KEY-----"));
}

#[test]
fn bad_footer_works_on_ec_pem() {
    let out = corrupt_pem(EC_PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(!out.contains("-----END EC PRIVATE KEY-----"));
}

#[test]
fn bad_base64_works_on_ec_pem() {
    let out = corrupt_pem(EC_PEM, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    assert!(out.contains("-----BEGIN EC PRIVATE KEY-----"));
}

#[test]
fn bad_header_works_on_ed25519_pem() {
    let out = corrupt_pem(ED25519_PEM, CorruptPem::BadHeader);
    assert!(out.contains("-----BEGIN CORRUPTED KEY-----"));
    assert!(!out.contains("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn bad_footer_works_on_ed25519_pem() {
    let out = corrupt_pem(ED25519_PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(!out.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn truncate_works_on_ed25519_pem() {
    let out = corrupt_pem(ED25519_PEM, CorruptPem::Truncate { bytes: 15 });
    assert_eq!(out.chars().count(), 15);
}

#[test]
fn bad_header_works_on_certificate_pem() {
    let out = corrupt_pem(CERTIFICATE_PEM, CorruptPem::BadHeader);
    assert!(out.contains("-----BEGIN CORRUPTED KEY-----"));
    assert!(!out.contains("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn bad_footer_works_on_certificate_pem() {
    let out = corrupt_pem(CERTIFICATE_PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(!out.contains("-----END CERTIFICATE-----"));
}

#[test]
fn extra_blank_line_works_on_ec_pem() {
    let out = corrupt_pem(EC_PEM, CorruptPem::ExtraBlankLine);
    assert!(out.contains("\n\n"));
    assert!(out.contains("-----BEGIN EC PRIVATE KEY-----"));
}

#[test]
fn all_variants_produce_corrupted_output_for_each_pem_type() {
    let pems = [RSA_PEM, EC_PEM, ED25519_PEM, CERTIFICATE_PEM];
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 20 },
        CorruptPem::ExtraBlankLine,
    ];
    for pem in pems {
        for variant in &variants {
            let out = corrupt_pem(pem, *variant);
            assert_ne!(out, pem, "Corruption should change the PEM");
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic corruption across key types
// ---------------------------------------------------------------------------

#[test]
fn deterministic_corruption_works_on_ec() {
    let a = corrupt_pem_deterministic(EC_PEM, "ec-variant");
    let b = corrupt_pem_deterministic(EC_PEM, "ec-variant");
    assert_eq!(a, b);
    assert_ne!(a, EC_PEM);
}

#[test]
fn deterministic_corruption_works_on_ed25519() {
    let a = corrupt_pem_deterministic(ED25519_PEM, "ed-variant");
    let b = corrupt_pem_deterministic(ED25519_PEM, "ed-variant");
    assert_eq!(a, b);
    assert_ne!(a, ED25519_PEM);
}

#[test]
fn deterministic_corruption_works_on_certificate() {
    let a = corrupt_pem_deterministic(CERTIFICATE_PEM, "cert-variant");
    let b = corrupt_pem_deterministic(CERTIFICATE_PEM, "cert-variant");
    assert_eq!(a, b);
    assert_ne!(a, CERTIFICATE_PEM);
}

#[test]
fn deterministic_different_variants_produce_different_output() {
    let outputs: HashSet<String> = (0..20)
        .map(|i| corrupt_pem_deterministic(RSA_PEM, &format!("distinct-{i}")))
        .collect();
    assert!(
        outputs.len() >= 2,
        "At least 2 distinct outputs expected from 20 variants"
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_input_bad_header() {
    let out = corrupt_pem("", CorruptPem::BadHeader);
    assert!(out.contains("-----BEGIN CORRUPTED KEY-----"));
}

#[test]
fn empty_input_bad_footer() {
    let out = corrupt_pem("", CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
}

#[test]
fn empty_input_truncate() {
    let out = corrupt_pem("", CorruptPem::Truncate { bytes: 10 });
    assert!(out.is_empty());
}

#[test]
fn single_line_pem_bad_base64() {
    let out = corrupt_pem("single-line", CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn single_line_pem_extra_blank_line() {
    let out = corrupt_pem("single-line", CorruptPem::ExtraBlankLine);
    assert!(out.contains("\n\n"));
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn any_pem_bad_header_differs_from_input(
        pem in "-----BEGIN [A-Z ]{3,20}-----\n[A-Za-z0-9+/=\n]{10,100}\n-----END [A-Z ]{3,20}-----\n"
    ) {
        let out = corrupt_pem(&pem, CorruptPem::BadHeader);
        prop_assert_ne!(out, pem);
    }

    #[test]
    fn any_pem_bad_footer_differs_from_input(
        pem in "-----BEGIN [A-Z ]{3,20}-----\n[A-Za-z0-9+/=\n]{10,100}\n-----END [A-Z ]{3,20}-----\n"
    ) {
        let out = corrupt_pem(&pem, CorruptPem::BadFooter);
        prop_assert_ne!(out, pem);
    }

    #[test]
    fn any_pem_bad_base64_differs_from_input(
        pem in "-----BEGIN [A-Z ]{3,20}-----\n[A-Za-z0-9+/=\n]{10,100}\n-----END [A-Z ]{3,20}-----\n"
    ) {
        let out = corrupt_pem(&pem, CorruptPem::BadBase64);
        prop_assert_ne!(out, pem);
    }

    #[test]
    fn any_pem_extra_blank_line_differs_from_input(
        pem in "-----BEGIN [A-Z ]{3,20}-----\n[A-Za-z0-9+/=\n]{10,100}\n-----END [A-Z ]{3,20}-----\n"
    ) {
        let out = corrupt_pem(&pem, CorruptPem::ExtraBlankLine);
        prop_assert_ne!(out, pem);
    }

    #[test]
    fn corruption_is_deterministic_for_any_input(
        pem in "[ -~]{1,256}",
        variant in "[a-z0-9]{1,16}",
    ) {
        let a = corrupt_pem_deterministic(&pem, &variant);
        let b = corrupt_pem_deterministic(&pem, &variant);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn truncation_never_exceeds_original_length(
        pem in "[ -~]{0,512}",
        bytes in 0usize..1024,
    ) {
        let out = corrupt_pem(&pem, CorruptPem::Truncate { bytes });
        prop_assert!(out.chars().count() <= pem.chars().count());
    }

    #[test]
    fn bad_base64_always_injects_marker(
        pem in "[A-Z]{1,16}\n[A-Z]{1,16}\n[A-Z]{1,16}\n"
    ) {
        let out = corrupt_pem(&pem, CorruptPem::BadBase64);
        prop_assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn extra_blank_line_always_has_double_newline(
        pem in "[A-Z]{1,16}\n[A-Z]{1,16}\n[A-Z]{1,16}\n"
    ) {
        let out = corrupt_pem(&pem, CorruptPem::ExtraBlankLine);
        prop_assert!(out.contains("\n\n"));
    }
}
