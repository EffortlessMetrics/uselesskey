//! Insta snapshot tests for uselesskey-pgp.
//!
//! These tests snapshot PGP key shapes, armor headers, fingerprints,
//! and negative fixtures to detect unintended changes.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

#[derive(Serialize)]
struct PgpKeySnapshot {
    label: &'static str,
    spec: &'static str,
    user_id: String,
    fingerprint_len: usize,
    private_armored_starts_with: String,
    public_armored_starts_with: String,
    private_binary_len: usize,
    public_binary_len: usize,
}

fn armored_header(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

#[test]
fn snapshot_pgp_ed25519_shape() {
    let fx = fx();
    let kp = fx.pgp("snapshot-ed25519", PgpSpec::ed25519());

    let result = PgpKeySnapshot {
        label: "snapshot-ed25519",
        spec: "Ed25519",
        user_id: kp.user_id().to_string(),
        fingerprint_len: kp.fingerprint().len(),
        private_armored_starts_with: armored_header(kp.private_key_armored()),
        public_armored_starts_with: armored_header(kp.public_key_armored()),
        private_binary_len: kp.private_key_binary().len(),
        public_binary_len: kp.public_key_binary().len(),
    };

    insta::assert_yaml_snapshot!("pgp_ed25519_shape", result);
}

#[test]
fn snapshot_pgp_rsa_2048_shape() {
    let fx = fx();
    let kp = fx.pgp("snapshot-rsa2048", PgpSpec::rsa_2048());

    let result = PgpKeySnapshot {
        label: "snapshot-rsa2048",
        spec: "RSA-2048",
        user_id: kp.user_id().to_string(),
        fingerprint_len: kp.fingerprint().len(),
        private_armored_starts_with: armored_header(kp.private_key_armored()),
        public_armored_starts_with: armored_header(kp.public_key_armored()),
        private_binary_len: kp.private_key_binary().len(),
        public_binary_len: kp.public_key_binary().len(),
    };

    insta::assert_yaml_snapshot!("pgp_rsa_2048_shape", result, {
        ".private_binary_len" => "[RSA_PRIV_LEN]",
        ".public_binary_len" => "[RSA_PUB_LEN]",
    });
}

#[test]
fn snapshot_pgp_negative_corrupt_armored() {
    let fx = fx();
    let kp = fx.pgp("snapshot-neg", PgpSpec::ed25519());
    let original = kp.private_key_armored();
    let corrupt = kp.private_key_armored_corrupt_deterministic("corrupt:swap");

    #[derive(Serialize)]
    struct CorruptInfo {
        original_header: String,
        corrupt_header: String,
        original_len: usize,
        corrupt_len: usize,
        differs: bool,
    }

    let result = CorruptInfo {
        original_header: armored_header(original),
        corrupt_header: armored_header(&corrupt),
        original_len: original.len(),
        corrupt_len: corrupt.len(),
        differs: original != corrupt,
    };

    insta::assert_yaml_snapshot!("pgp_negative_corrupt_armored", result);
}

#[test]
fn snapshot_pgp_negative_mismatch() {
    let fx = fx();
    let kp = fx.pgp("snapshot-mismatch", PgpSpec::ed25519());
    let normal_pub = kp.public_key_armored();
    let mismatch_pub = kp.mismatched_public_key_armored();

    #[derive(Serialize)]
    struct MismatchInfo {
        normal_header: String,
        mismatch_header: String,
        keys_differ: bool,
    }

    let result = MismatchInfo {
        normal_header: armored_header(normal_pub),
        mismatch_header: armored_header(&mismatch_pub),
        keys_differ: normal_pub != mismatch_pub,
    };

    insta::assert_yaml_snapshot!("pgp_negative_mismatch", result);
}

#[test]
fn snapshot_pgp_truncated_binary() {
    let fx = fx();
    let kp = fx.pgp("snapshot-trunc", PgpSpec::ed25519());
    let full_len = kp.private_key_binary().len();
    let truncated = kp.private_key_binary_truncated(full_len / 2);

    #[derive(Serialize)]
    struct TruncateInfo {
        full_len: usize,
        truncated_len: usize,
        is_shorter: bool,
    }

    let result = TruncateInfo {
        full_len,
        truncated_len: truncated.len(),
        is_shorter: truncated.len() < full_len,
    };

    insta::assert_yaml_snapshot!("pgp_truncated_binary", result);
}
