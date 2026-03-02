//! Insta snapshot tests for uselesskey-core-negative-pem.
//!
//! Snapshot corrupt PEM variant shapes — what changed, not the content.

use serde::Serialize;
use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

const SAMPLE_PEM: &str = "-----BEGIN TEST KEY-----\nABCDEFGH=\n-----END TEST KEY-----\n";

#[derive(Serialize)]
struct CorruptPemShape {
    variant: &'static str,
    original_len: usize,
    corrupted_len: usize,
    first_line: String,
    last_line: String,
    differs_from_original: bool,
}

fn last_nonempty_line(s: &str) -> String {
    s.lines()
        .rev()
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string()
}

#[test]
fn snapshot_corrupt_pem_bad_header() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    let result = CorruptPemShape {
        variant: "BadHeader",
        original_len: SAMPLE_PEM.len(),
        corrupted_len: out.len(),
        first_line: out.lines().next().unwrap_or("").to_string(),
        last_line: last_nonempty_line(&out),
        differs_from_original: out != SAMPLE_PEM,
    };
    insta::assert_yaml_snapshot!("negative_pem_bad_header", result);
}

#[test]
fn snapshot_corrupt_pem_bad_footer() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadFooter);
    let result = CorruptPemShape {
        variant: "BadFooter",
        original_len: SAMPLE_PEM.len(),
        corrupted_len: out.len(),
        first_line: out.lines().next().unwrap_or("").to_string(),
        last_line: last_nonempty_line(&out),
        differs_from_original: out != SAMPLE_PEM,
    };
    insta::assert_yaml_snapshot!("negative_pem_bad_footer", result);
}

#[test]
fn snapshot_corrupt_pem_bad_base64() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadBase64);
    let result = CorruptPemShape {
        variant: "BadBase64",
        original_len: SAMPLE_PEM.len(),
        corrupted_len: out.len(),
        first_line: out.lines().next().unwrap_or("").to_string(),
        last_line: last_nonempty_line(&out),
        differs_from_original: out != SAMPLE_PEM,
    };
    insta::assert_yaml_snapshot!("negative_pem_bad_base64", result);
}

#[test]
fn snapshot_corrupt_pem_extra_blank_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::ExtraBlankLine);

    #[derive(Serialize)]
    struct BlankLineShape {
        variant: &'static str,
        original_line_count: usize,
        corrupted_line_count: usize,
        has_empty_line: bool,
        differs_from_original: bool,
    }

    let result = BlankLineShape {
        variant: "ExtraBlankLine",
        original_line_count: SAMPLE_PEM.lines().count(),
        corrupted_line_count: out.lines().count(),
        has_empty_line: out.lines().any(|l| l.is_empty()),
        differs_from_original: out != SAMPLE_PEM,
    };
    insta::assert_yaml_snapshot!("negative_pem_extra_blank_line", result);
}

#[test]
fn snapshot_corrupt_pem_truncate() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 20 });

    #[derive(Serialize)]
    struct TruncateShape {
        variant: &'static str,
        original_len: usize,
        truncated_len: usize,
        truncate_target: usize,
    }

    let result = TruncateShape {
        variant: "Truncate",
        original_len: SAMPLE_PEM.len(),
        truncated_len: out.len(),
        truncate_target: 20,
    };
    insta::assert_yaml_snapshot!("negative_pem_truncate", result);
}

#[test]
fn snapshot_corrupt_pem_deterministic_stability() {
    #[derive(Serialize)]
    struct DeterministicCheck {
        variant_string: &'static str,
        outputs_match: bool,
        differs_from_original: bool,
    }

    let a = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:snapshot-v1");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:snapshot-v1");

    let result = DeterministicCheck {
        variant_string: "corrupt:snapshot-v1",
        outputs_match: a == b,
        differs_from_original: a != SAMPLE_PEM,
    };
    insta::assert_yaml_snapshot!("negative_pem_deterministic", result);
}
