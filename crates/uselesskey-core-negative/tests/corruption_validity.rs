//! Tests that validate the *structural correctness* of negative fixtures.
//!
//! Existing test files cover basic behaviour and determinism. This file adds:
//! - PEM structural invalidity proofs (corrupt output fails PEM parse rules)
//! - Truncated DER is an exact byte-prefix of the original
//! - flip_byte is involutory (applying twice restores original)
//! - Corruption of every common PEM label type
//! - Deterministic corruption is isolated per-variant (no cross-talk)
//! - CorruptPem::Truncate operates on *chars*, not bytes (Unicode safety)
//! - Edge-case interactions (empty + corrupt, single-byte DER, etc.)

use std::collections::HashSet;

use rstest::rstest;
use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// ── helpers ──────────────────────────────────────────────────────────

/// Build a synthetic PEM block with the given label and body line.
fn make_pem(label: &str, body: &str) -> String {
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

/// Returns true when `s` looks like a structurally valid PEM block:
/// first line matches `-----BEGIN <label>-----`, last non-empty line
/// matches `-----END <label>-----` with the *same* label, and all
/// interior lines are valid base-64 characters.
fn is_structurally_valid_pem(s: &str) -> bool {
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() < 3 {
        return false;
    }

    let first = lines[0];
    let last = lines
        .iter()
        .rev()
        .find(|l| !l.is_empty())
        .copied()
        .unwrap_or("");

    let begin_label = first
        .strip_prefix("-----BEGIN ")
        .and_then(|r| r.strip_suffix("-----"));
    let end_label = last
        .strip_prefix("-----END ")
        .and_then(|r| r.strip_suffix("-----"));

    match (begin_label, end_label) {
        (Some(b), Some(e)) if b == e => {}
        _ => return false,
    }

    // Interior lines must be non-empty valid base-64
    for line in &lines[1..lines.len() - 1] {
        if line.is_empty() {
            return false;
        }
        if !line
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            return false;
        }
    }
    true
}

// ── 1. All CorruptPem variants produce structurally invalid PEM ──────

const VALID_PEM: &str =
    "-----BEGIN RSA PRIVATE KEY-----\nTWF0dGVyIGlzIG1hZGU=\n-----END RSA PRIVATE KEY-----\n";

#[test]
fn baseline_sample_is_structurally_valid() {
    assert!(
        is_structurally_valid_pem(VALID_PEM),
        "test precondition: VALID_PEM must parse as valid PEM"
    );
}

#[rstest]
#[case::bad_header(CorruptPem::BadHeader)]
#[case::bad_footer(CorruptPem::BadFooter)]
#[case::bad_base64(CorruptPem::BadBase64)]
#[case::extra_blank(CorruptPem::ExtraBlankLine)]
#[case::truncate(CorruptPem::Truncate { bytes: 20 })]
fn every_variant_produces_structurally_invalid_pem(#[case] variant: CorruptPem) {
    let out = corrupt_pem(VALID_PEM, variant);
    assert!(
        !is_structurally_valid_pem(&out),
        "{variant:?} should produce structurally invalid PEM, got:\n{out}"
    );
}

// ── 2. Truncated DER is an exact byte-prefix ─────────────────────────

#[rstest]
#[case::two(2)]
#[case::half(4)]
#[case::all_but_one(7)]
fn truncated_der_is_exact_prefix(#[case] len: usize) {
    let der: Vec<u8> = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let out = truncate_der(&der, len);
    assert_eq!(out.len(), len);
    assert_eq!(
        &out[..],
        &der[..len],
        "truncated output must be the first {len} bytes"
    );
}

#[test]
fn truncated_der_content_unchanged() {
    let der: Vec<u8> = (0u8..=255).collect();
    for len in [0, 1, 127, 128, 255, 256] {
        let out = truncate_der(&der, len);
        assert_eq!(out.len(), len.min(der.len()));
        for (i, &b) in out.iter().enumerate() {
            assert_eq!(b, der[i], "byte at index {i} must match original");
        }
    }
}

// ── 3. flip_byte is involutory ───────────────────────────────────────

#[test]
fn flip_byte_twice_restores_original() {
    let der: Vec<u8> = (0..16).collect();
    for offset in 0..der.len() {
        let once = flip_byte(&der, offset);
        let twice = flip_byte(&once, offset);
        assert_eq!(
            twice, der,
            "double flip at offset {offset} must restore original"
        );
    }
}

#[test]
fn flip_byte_xor_mask_is_0x01() {
    let der: Vec<u8> = (0..=255).collect();
    for offset in 0..der.len() {
        let out = flip_byte(&der, offset);
        let diff = out[offset] ^ der[offset];
        assert_eq!(
            diff, 0x01,
            "XOR mask at offset {offset} should be exactly 0x01"
        );
    }
}

// ── 4. Corruption across common PEM label types ─────────────────────

#[rstest]
#[case::rsa_private("RSA PRIVATE KEY", "TUlJQ1hn")]
#[case::public("PUBLIC KEY", "TUNpd0RR")]
#[case::ec_private("EC PRIVATE KEY", "TUhRQ0FR")]
#[case::certificate("CERTIFICATE", "TUlJQmtU")]
#[case::private("PRIVATE KEY", "TUNvd0JR")]
fn corruption_works_on_all_pem_types(#[case] label: &str, #[case] body: &str) {
    let pem = make_pem(label, body);
    assert!(is_structurally_valid_pem(&pem), "precondition");

    for variant in [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::ExtraBlankLine,
        CorruptPem::Truncate { bytes: 10 },
    ] {
        let out = corrupt_pem(&pem, variant);
        assert_ne!(out, pem, "{variant:?} on {label} must differ from original");
    }
}

// ── 5. Deterministic corruption: variant isolation ──────────────────

#[test]
fn deterministic_pem_variant_isolation() {
    // Changing only the variant must change the output (high probability).
    let outputs: HashSet<String> = (0..20)
        .map(|i| corrupt_pem_deterministic(VALID_PEM, &format!("iso-{i}")))
        .collect();
    assert!(
        outputs.len() >= 3,
        "20 distinct variant strings should produce at least 3 distinct outputs"
    );
}

#[test]
fn deterministic_der_variant_isolation() {
    let der: Vec<u8> = (0..48).collect();
    let outputs: HashSet<Vec<u8>> = (0..20)
        .map(|i| corrupt_der_deterministic(&der, &format!("der-iso-{i}")))
        .collect();
    assert!(
        outputs.len() >= 3,
        "20 distinct variant strings should produce at least 3 distinct DER corruptions"
    );
}

#[test]
fn deterministic_pem_same_variant_different_input_differs() {
    let pem_a = make_pem("RSA PRIVATE KEY", "AAAA");
    let pem_b = make_pem("EC PRIVATE KEY", "BBBB");
    let out_a = corrupt_pem_deterministic(&pem_a, "shared-variant");
    let out_b = corrupt_pem_deterministic(&pem_b, "shared-variant");
    assert_ne!(
        out_a, out_b,
        "same variant on different inputs should produce different outputs"
    );
}

#[test]
fn deterministic_der_same_variant_different_input_differs() {
    let der_a: Vec<u8> = vec![0x30, 0x82, 0x01, 0x22, 0xAA];
    let der_b: Vec<u8> = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
    let out_a = corrupt_der_deterministic(&der_a, "shared-der-variant");
    let out_b = corrupt_der_deterministic(&der_b, "shared-der-variant");
    assert_ne!(out_a, out_b);
}

// ── 6. Deterministic corruption is idempotent (stable across calls) ──

#[test]
fn deterministic_pem_stable_across_1000_calls() {
    let reference = corrupt_pem_deterministic(VALID_PEM, "stability-torture");
    for _ in 0..1000 {
        assert_eq!(
            corrupt_pem_deterministic(VALID_PEM, "stability-torture"),
            reference
        );
    }
}

#[test]
fn deterministic_der_stable_across_1000_calls() {
    let der: Vec<u8> = (0..32).collect();
    let reference = corrupt_der_deterministic(&der, "der-stability-torture");
    for _ in 0..1000 {
        assert_eq!(
            corrupt_der_deterministic(&der, "der-stability-torture"),
            reference
        );
    }
}

// ── 7. CorruptPem::Truncate operates on chars, not bytes ─────────────

#[test]
fn truncate_operates_on_chars_not_bytes() {
    // Multi-byte chars: each '€' is 3 bytes in UTF-8
    let pem_with_unicode = "-----BEGIN X-----\n€€€€€\n-----END X-----\n";
    let out = corrupt_pem(pem_with_unicode, CorruptPem::Truncate { bytes: 20 });
    assert_eq!(out.chars().count(), 20, "Truncate counts chars, not bytes");
    // The byte length will be >= 20 because of multi-byte chars
    assert!(out.len() >= 20);
}

// ── 8. BadHeader preserves body, BadFooter preserves body ────────────

#[test]
fn bad_header_preserves_body_and_footer() {
    let out = corrupt_pem(VALID_PEM, CorruptPem::BadHeader);
    // Body line should still be present
    assert!(out.contains("TWF0dGVyIGlzIG1hZGU="));
    // Original footer should still be present
    assert!(out.contains("-----END RSA PRIVATE KEY-----"));
}

#[test]
fn bad_footer_preserves_header_and_body() {
    let out = corrupt_pem(VALID_PEM, CorruptPem::BadFooter);
    // Original header should still be present
    assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"));
    // Body should still be present
    assert!(out.contains("TWF0dGVyIGlzIG1hZGU="));
}

#[test]
fn bad_base64_preserves_header_and_footer() {
    let out = corrupt_pem(VALID_PEM, CorruptPem::BadBase64);
    assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(out.contains("-----END RSA PRIVATE KEY-----"));
}

#[test]
fn extra_blank_line_preserves_header_and_footer() {
    let out = corrupt_pem(VALID_PEM, CorruptPem::ExtraBlankLine);
    assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(out.contains("-----END RSA PRIVATE KEY-----"));
}

// ── 9. DER corruption output never exceeds original length ───────────

#[test]
fn corrupt_der_deterministic_never_grows() {
    let der: Vec<u8> = (0..64).collect();
    for i in 0..50 {
        let variant = format!("grow-check-{i}");
        let out = corrupt_der_deterministic(&der, &variant);
        assert!(
            out.len() <= der.len(),
            "variant '{variant}' produced output ({}) longer than input ({})",
            out.len(),
            der.len()
        );
    }
}

// ── 10. Each CorruptPem variant produces pairwise-distinct output ────

#[test]
fn all_five_variants_pairwise_distinct() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::ExtraBlankLine,
        CorruptPem::Truncate { bytes: 15 },
    ];

    let outputs: Vec<String> = variants
        .iter()
        .map(|v| corrupt_pem(VALID_PEM, *v))
        .collect();

    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(
                outputs[i], outputs[j],
                "{:?} and {:?} produced identical output",
                variants[i], variants[j]
            );
        }
    }
}

// ── 11. Truncate edge cases ──────────────────────────────────────────

#[test]
fn pem_truncate_to_zero_is_empty() {
    let out = corrupt_pem(VALID_PEM, CorruptPem::Truncate { bytes: 0 });
    assert!(out.is_empty());
}

#[test]
fn pem_truncate_beyond_length_returns_full() {
    let char_count = VALID_PEM.chars().count();
    let out = corrupt_pem(
        VALID_PEM,
        CorruptPem::Truncate {
            bytes: char_count + 100,
        },
    );
    assert_eq!(out.chars().count(), char_count);
}

#[test]
fn pem_truncate_at_exact_length_returns_full() {
    let char_count = VALID_PEM.chars().count();
    let out = corrupt_pem(VALID_PEM, CorruptPem::Truncate { bytes: char_count });
    assert_eq!(out, VALID_PEM);
}

// ── 12. DER edge: single-byte and two-byte inputs ────────────────────

#[test]
fn flip_byte_single_byte_all_values() {
    for b in 0u16..=255 {
        let der = vec![b as u8];
        let out = flip_byte(&der, 0);
        assert_eq!(out[0], (b as u8) ^ 0x01);
    }
}

#[test]
fn corrupt_der_deterministic_two_bytes() {
    let der = vec![0xAA, 0xBB];
    let out = corrupt_der_deterministic(&der, "two-byte-test");
    // Should either truncate to 0..1 bytes, or flip one byte
    assert!(out.len() <= der.len());
    assert_ne!(out, der);
}

// ── 13. Deterministic DER corruption arms are reachable ──────────────

#[test]
fn corrupt_der_deterministic_all_arms_reachable() {
    let der: Vec<u8> = (0..16).collect();
    let mut saw_truncate_only = false;
    let mut saw_flip_only = false;
    let mut saw_flip_and_truncate = false;

    for i in 0u64..100 {
        let variant = format!("arm-{i}");
        let out = corrupt_der_deterministic(&der, &variant);

        if out.len() == der.len() {
            // Flip only (arm 1): same length, one byte differs
            saw_flip_only = true;
        } else if out.len() < der.len() {
            // Truncation happened; check if a byte was also flipped
            let prefix_matches = out.iter().zip(der.iter()).all(|(a, b)| a == b);
            if prefix_matches {
                saw_truncate_only = true;
            } else {
                saw_flip_and_truncate = true;
            }
        }
    }

    assert!(
        saw_truncate_only,
        "arm 0 (truncate only) should be reachable"
    );
    assert!(saw_flip_only, "arm 1 (flip only) should be reachable");
    assert!(
        saw_flip_and_truncate,
        "arm 2 (flip + truncate) should be reachable"
    );
}

// ── 14. Deterministic PEM corruption arms are reachable ──────────────

#[test]
fn corrupt_pem_deterministic_all_arms_reachable() {
    let mut saw = [false; 5]; // BadHeader, BadFooter, BadBase64, ExtraBlankLine, Truncate

    for i in 0u64..200 {
        let variant = format!("pem-arm-{i}");
        let out = corrupt_pem_deterministic(VALID_PEM, &variant);

        if out.contains("-----BEGIN CORRUPTED KEY-----") {
            saw[0] = true;
        } else if out.contains("-----END CORRUPTED KEY-----") {
            saw[1] = true;
        } else if out.contains("THIS_IS_NOT_BASE64!!!") {
            saw[2] = true;
        } else if out.contains("\n\n") && out.len() > VALID_PEM.len() {
            saw[3] = true;
        } else if out.len() < VALID_PEM.len() {
            saw[4] = true;
        }
    }

    assert!(saw[0], "BadHeader arm should be reachable");
    assert!(saw[1], "BadFooter arm should be reachable");
    assert!(saw[2], "BadBase64 arm should be reachable");
    assert!(saw[3], "ExtraBlankLine arm should be reachable");
    assert!(saw[4], "Truncate arm should be reachable");
}
