//! Insta snapshot tests for uselesskey-core-negative (facade).
//!
//! Snapshot the output shapes of CorruptPem variants and DER corruption
//! through the facade re-exports. No actual key material is captured.

use serde::Serialize;
use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

const SAMPLE_PEM: &str = "-----BEGIN PUBLIC KEY-----\nABCDEFGHIJ==\n-----END PUBLIC KEY-----\n";
const SAMPLE_DER: &[u8] = &[0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];

// ── PEM facade snapshots ────────────────────────────────────────────

#[derive(Serialize)]
struct PemCorruptionShape {
    variant: &'static str,
    original_len: usize,
    corrupted_len: usize,
    first_line: String,
    last_nonempty_line: String,
    differs_from_original: bool,
}

fn last_nonempty(s: &str) -> String {
    s.lines()
        .rev()
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string()
}

#[test]
fn snapshot_facade_pem_all_variants() {
    let variants: Vec<(&str, CorruptPem)> = vec![
        ("BadHeader", CorruptPem::BadHeader),
        ("BadFooter", CorruptPem::BadFooter),
        ("BadBase64", CorruptPem::BadBase64),
        ("ExtraBlankLine", CorruptPem::ExtraBlankLine),
        ("Truncate_20", CorruptPem::Truncate { bytes: 20 }),
    ];

    let results: Vec<PemCorruptionShape> = variants
        .into_iter()
        .map(|(name, how)| {
            let out = corrupt_pem(SAMPLE_PEM, how);
            PemCorruptionShape {
                variant: name,
                original_len: SAMPLE_PEM.len(),
                corrupted_len: out.len(),
                first_line: out.lines().next().unwrap_or("").to_string(),
                last_nonempty_line: last_nonempty(&out),
                differs_from_original: out != SAMPLE_PEM,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("facade_pem_all_variants", results);
}

#[test]
fn snapshot_facade_pem_deterministic() {
    #[derive(Serialize)]
    struct DeterministicShape {
        variant_string: &'static str,
        is_stable: bool,
        differs_from_original: bool,
        output_len: usize,
    }

    let a = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:facade-v1");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:facade-v1");

    let result = DeterministicShape {
        variant_string: "corrupt:facade-v1",
        is_stable: a == b,
        differs_from_original: a != SAMPLE_PEM,
        output_len: a.len(),
    };

    insta::assert_yaml_snapshot!("facade_pem_deterministic", result);
}

// ── DER facade snapshots ────────────────────────────────────────────

#[derive(Serialize)]
struct DerCorruptionShape {
    operation: &'static str,
    original_len: usize,
    result_len: usize,
    differs_from_original: bool,
}

#[test]
fn snapshot_facade_der_truncate() {
    let out = truncate_der(SAMPLE_DER, 4);
    let result = DerCorruptionShape {
        operation: "truncate_to_4",
        original_len: SAMPLE_DER.len(),
        result_len: out.len(),
        differs_from_original: out != SAMPLE_DER,
    };
    insta::assert_yaml_snapshot!("facade_der_truncate", result);
}

#[test]
fn snapshot_facade_der_flip_byte() {
    let out = flip_byte(SAMPLE_DER, 0);
    let result = DerCorruptionShape {
        operation: "flip_byte_0",
        original_len: SAMPLE_DER.len(),
        result_len: out.len(),
        differs_from_original: out != SAMPLE_DER,
    };
    insta::assert_yaml_snapshot!("facade_der_flip_byte", result);
}

#[test]
fn snapshot_facade_der_deterministic() {
    #[derive(Serialize)]
    struct DerDeterministicShape {
        variant_string: &'static str,
        original_len: usize,
        result_len: usize,
        is_stable: bool,
        differs_from_original: bool,
    }

    let a = corrupt_der_deterministic(SAMPLE_DER, "corrupt:facade-der-v1");
    let b = corrupt_der_deterministic(SAMPLE_DER, "corrupt:facade-der-v1");

    let result = DerDeterministicShape {
        variant_string: "corrupt:facade-der-v1",
        original_len: SAMPLE_DER.len(),
        result_len: a.len(),
        is_stable: a == b,
        differs_from_original: a != SAMPLE_DER,
    };

    insta::assert_yaml_snapshot!("facade_der_deterministic", result);
}
