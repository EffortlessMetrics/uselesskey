use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// ---------------------------------------------------------------------------
// Sample PEM for testing
// ---------------------------------------------------------------------------

const SAMPLE_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIBogIBAAJBALRiMLKQk/Al7mPaPNE4IeA9TwJw5JSTkU9wOLkM0DpjCEZAbPjX\n\
qZuJ3QXt4XUJcDOy1JJVDwYL1HRqn8pMuTECAwEAAQ==\n\
-----END RSA PRIVATE KEY-----\n";

// ---------------------------------------------------------------------------
// 1. CorruptPem variants
// ---------------------------------------------------------------------------

#[test]
fn corrupt_pem_bad_header_replaces_begin_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----\n"));
    assert!(!out.contains("BEGIN RSA PRIVATE KEY"));
    // Body and footer survive
    assert!(out.contains("END RSA PRIVATE KEY"));
}

#[test]
fn corrupt_pem_bad_footer_replaces_end_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----\n"));
    assert!(!out.contains("END RSA PRIVATE KEY"));
    // Header survives
    assert!(out.contains("BEGIN RSA PRIVATE KEY"));
}

#[test]
fn corrupt_pem_bad_base64_inserts_garbage_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn corrupt_pem_truncate_limits_length() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 15 });
    assert_eq!(out.chars().count(), 15);
    assert!(out.len() < SAMPLE_PEM.len());
}

#[test]
fn corrupt_pem_extra_blank_line_injects_empty_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::ExtraBlankLine);
    // The blank line appears right after the header
    assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----\n\n"));
}

// ---------------------------------------------------------------------------
// 2. DER truncation
// ---------------------------------------------------------------------------

#[test]
fn truncate_der_shortens_to_requested_length() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
    let out = truncate_der(&der, 3);
    assert_eq!(out, vec![0x30, 0x82, 0x01]);
}

#[test]
fn truncate_der_returns_full_copy_when_len_exceeds_input() {
    let der = vec![0x30, 0x82];
    let out = truncate_der(&der, 100);
    assert_eq!(out, der);
}

#[test]
fn truncate_der_returns_full_copy_when_len_equals_input() {
    let der = vec![0x30, 0x82];
    let out = truncate_der(&der, 2);
    assert_eq!(out, der);
}

#[test]
fn truncate_der_to_zero_yields_empty() {
    let der = vec![0x30, 0x82, 0x01];
    let out = truncate_der(&der, 0);
    assert!(out.is_empty());
}

// ---------------------------------------------------------------------------
// 3. flip_byte
// ---------------------------------------------------------------------------

#[test]
fn flip_byte_xors_target_offset() {
    let der = vec![0x30, 0x82, 0x01, 0x22];
    let out = flip_byte(&der, 2);
    assert_eq!(out[2], 0x00); // 0x01 ^ 0x01 = 0x00
    // Other bytes unchanged
    assert_eq!(out[0], 0x30);
    assert_eq!(out[1], 0x82);
    assert_eq!(out[3], 0x22);
}

#[test]
fn flip_byte_out_of_bounds_returns_original() {
    let der = vec![0x30, 0x82];
    let out = flip_byte(&der, 10);
    assert_eq!(out, der);
}

// ---------------------------------------------------------------------------
// 4. corrupt_der_deterministic
// ---------------------------------------------------------------------------

#[test]
fn corrupt_der_deterministic_is_stable_across_calls() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0xAA, 0xBB];
    let a = corrupt_der_deterministic(&der, "corrupt:test-stable");
    let b = corrupt_der_deterministic(&der, "corrupt:test-stable");
    assert_eq!(a, b);
}

#[test]
fn corrupt_der_deterministic_differs_for_different_variants() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0xAA, 0xBB];
    let a = corrupt_der_deterministic(&der, "corrupt:alpha");
    let b = corrupt_der_deterministic(&der, "corrupt:beta");
    // Different variants should (almost certainly) produce different outputs
    assert_ne!(a, b);
}

#[test]
fn corrupt_der_deterministic_always_mutates() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
    let out = corrupt_der_deterministic(&der, "corrupt:mutates");
    assert_ne!(out, der, "Deterministic corruption should alter the input");
}

// ---------------------------------------------------------------------------
// 5. corrupt_pem_deterministic
// ---------------------------------------------------------------------------

#[test]
fn corrupt_pem_deterministic_is_stable() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:pem-stable");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:pem-stable");
    assert_eq!(a, b);
}

#[test]
fn corrupt_pem_deterministic_differs_across_variants() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "variant-x");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "variant-y");
    assert_ne!(a, b);
}

#[test]
fn corrupt_pem_deterministic_produces_multiple_shapes() {
    use std::collections::HashSet;
    let mut outputs = HashSet::new();
    for i in 0..20 {
        let v = format!("shape-{i}");
        outputs.insert(corrupt_pem_deterministic(SAMPLE_PEM, &v));
    }
    // With 20 variants hitting 5 arms, we expect at least 3 distinct shapes
    assert!(
        outputs.len() >= 3,
        "Expected diverse corruption shapes, got {}",
        outputs.len()
    );
}

// ---------------------------------------------------------------------------
// 6. Corrupt PEM is actually unparseable (structural checks)
// ---------------------------------------------------------------------------

#[test]
fn corrupt_pem_bad_header_lacks_valid_begin_marker() {
    let corrupted = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    // A valid PEM must start with "-----BEGIN <label>-----"
    // BadHeader replaces it, so the original label is gone.
    assert!(
        !corrupted.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "BadHeader should remove the original BEGIN marker"
    );
}

#[test]
fn corrupt_pem_bad_footer_lacks_valid_end_marker() {
    let corrupted = corrupt_pem(SAMPLE_PEM, CorruptPem::BadFooter);
    assert!(
        !corrupted.contains("-----END RSA PRIVATE KEY-----"),
        "BadFooter should remove the original END marker"
    );
}

#[test]
fn corrupt_pem_bad_base64_has_non_base64_content() {
    let corrupted = corrupt_pem(SAMPLE_PEM, CorruptPem::BadBase64);
    assert!(
        corrupted.contains("THIS_IS_NOT_BASE64!!!"),
        "BadBase64 should inject invalid base64 content"
    );
}

#[test]
fn corrupt_pem_truncated_lacks_end_marker() {
    let corrupted = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 20 });
    assert!(
        !corrupted.contains("-----END"),
        "Truncated PEM should lack the END marker"
    );
}

// ---------------------------------------------------------------------------
// 7. Display/Debug don't leak key material
// ---------------------------------------------------------------------------

#[test]
fn corrupt_pem_debug_does_not_contain_key_bytes() {
    // CorruptPem is an enum of corruption strategies, not key holders,
    // but verify that Debug output is safe and well-formed.
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 42 },
        CorruptPem::ExtraBlankLine,
    ];
    for v in &variants {
        let dbg = format!("{v:?}");
        assert!(
            !dbg.contains("BEGIN"),
            "Debug should not contain PEM data: {dbg}"
        );
        assert!(
            !dbg.contains("PRIVATE"),
            "Debug should not contain key-related words: {dbg}"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Exhaustive variant coverage
// ---------------------------------------------------------------------------

#[test]
fn all_corrupt_pem_variants_produce_different_output_from_original() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 10 },
        CorruptPem::ExtraBlankLine,
    ];
    for v in &variants {
        let corrupted = corrupt_pem(SAMPLE_PEM, *v);
        assert_ne!(
            corrupted, SAMPLE_PEM,
            "Variant {v:?} should produce output different from original"
        );
    }
}

#[test]
fn all_corrupt_pem_variants_are_distinct_from_each_other() {
    use std::collections::HashSet;
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 10 },
        CorruptPem::ExtraBlankLine,
    ];
    let mut outputs = HashSet::new();
    for v in &variants {
        outputs.insert(corrupt_pem(SAMPLE_PEM, *v));
    }
    assert_eq!(
        outputs.len(),
        variants.len(),
        "Each variant should produce distinct corrupt output"
    );
}

// ---------------------------------------------------------------------------
// 9. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn truncate_der_on_empty_input() {
    let out = truncate_der(&[], 5);
    assert!(out.is_empty());
}

#[test]
fn flip_byte_on_empty_input() {
    let out = flip_byte(&[], 0);
    assert!(out.is_empty());
}

#[test]
fn corrupt_der_deterministic_single_byte() {
    let der = vec![0xFF];
    let out = corrupt_der_deterministic(&der, "corrupt:single");
    // Single-byte input: truncation can yield empty, flip changes the byte
    assert!(out.is_empty() || (out.len() == 1 && out[0] != 0xFF));
}

#[test]
fn corrupt_pem_clone_and_copy() {
    // CorruptPem derives Clone + Copy
    let original = CorruptPem::BadHeader;
    let cloned = original;
    let _copied = cloned;
    assert!(matches!(cloned, CorruptPem::BadHeader));
}
