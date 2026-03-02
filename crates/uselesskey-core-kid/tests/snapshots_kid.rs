//! Insta snapshot tests for uselesskey-core-kid.
//!
//! Snapshot KID generation shapes — lengths, encoding format.
//! Actual hash values are redacted.

use serde::Serialize;
use uselesskey_core_kid::{DEFAULT_KID_PREFIX_BYTES, kid_from_bytes, kid_from_bytes_with_prefix};

#[derive(Serialize)]
struct KidShape {
    input_description: &'static str,
    kid_len: usize,
    prefix_bytes: usize,
    is_base64url: bool,
}

#[test]
fn snapshot_kid_default_shape() {
    let kid = kid_from_bytes(b"test-public-key-material");

    let result = KidShape {
        input_description: "test-public-key-material",
        kid_len: kid.len(),
        prefix_bytes: DEFAULT_KID_PREFIX_BYTES,
        is_base64url: kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
    };

    insta::assert_yaml_snapshot!("kid_default_shape", result);
}

#[test]
fn snapshot_kid_custom_prefix_lengths() {
    let prefix_sizes = [1, 4, 8, 12, 16, 32];

    let results: Vec<KidShape> = prefix_sizes
        .iter()
        .map(|&prefix| {
            let kid = kid_from_bytes_with_prefix(b"test-key", prefix);
            KidShape {
                input_description: "test-key",
                kid_len: kid.len(),
                prefix_bytes: prefix,
                is_base64url: kid
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("kid_custom_prefix_lengths", results);
}

#[test]
fn snapshot_kid_determinism() {
    #[derive(Serialize)]
    struct KidDeterminism {
        same_input_matches: bool,
        different_input_differs: bool,
        default_prefix_bytes: usize,
    }

    let a = kid_from_bytes(b"same-key");
    let b = kid_from_bytes(b"same-key");
    let c = kid_from_bytes(b"different-key");

    let result = KidDeterminism {
        same_input_matches: a == b,
        different_input_differs: a != c,
        default_prefix_bytes: DEFAULT_KID_PREFIX_BYTES,
    };

    insta::assert_yaml_snapshot!("kid_determinism", result);
}
