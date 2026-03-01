//! Insta snapshot tests for uselesskey-ed25519.
//!
//! These tests snapshot PEM shapes and key metadata to detect
//! unintended changes in deterministic Ed25519 key generation.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

#[derive(Serialize)]
struct Ed25519PemSnapshot {
    label: &'static str,
    private_pem_starts_with: String,
    private_pem_ends_with: String,
    private_pem_line_count: usize,
    public_pem_starts_with: String,
    public_pem_ends_with: String,
    public_pem_line_count: usize,
    private_der_len: usize,
    public_der_len: usize,
}

#[test]
fn snapshot_ed25519_pem_shape() {
    let fx = fx();
    let kp = fx.ed25519("snapshot-ed25519", Ed25519Spec::new());

    let priv_pem = kp.private_key_pkcs8_pem();
    let pub_pem = kp.public_key_spki_pem();
    let priv_lines: Vec<&str> = priv_pem.lines().collect();
    let pub_lines: Vec<&str> = pub_pem.lines().collect();

    let result = Ed25519PemSnapshot {
        label: "snapshot-ed25519",
        private_pem_starts_with: priv_lines.first().unwrap_or(&"").to_string(),
        private_pem_ends_with: priv_lines.last().unwrap_or(&"").to_string(),
        private_pem_line_count: priv_lines.len(),
        public_pem_starts_with: pub_lines.first().unwrap_or(&"").to_string(),
        public_pem_ends_with: pub_lines.last().unwrap_or(&"").to_string(),
        public_pem_line_count: pub_lines.len(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("ed25519_pem_shape", result);
}

#[test]
fn snapshot_ed25519_key_sizes() {
    let fx = fx();
    let kp = fx.ed25519("size-check", Ed25519Spec::new());

    #[derive(Serialize)]
    struct Ed25519SizeInfo {
        private_der_len: usize,
        public_der_len: usize,
    }

    let result = Ed25519SizeInfo {
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("ed25519_key_sizes", result);
}

#[test]
fn snapshot_ed25519_corrupt_pem_variants() {
    let fx = fx();
    let kp = fx.ed25519("snapshot-corrupt", Ed25519Spec::new());

    let original = kp.private_key_pkcs8_pem();

    #[derive(Serialize)]
    struct CorruptInfo {
        variant: &'static str,
        differs_from_original: bool,
    }

    let variants = [
        ("BadBase64", kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64)),
        ("BadHeader", kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader)),
        ("BadFooter", kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter)),
        ("ExtraBlankLine", kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine)),
    ];

    let results: Vec<CorruptInfo> = variants
        .iter()
        .map(|(name, corrupt)| CorruptInfo {
            variant: name,
            differs_from_original: corrupt != &original,
        })
        .collect();

    insta::assert_yaml_snapshot!("ed25519_corrupt_pem_variants", results);
}
