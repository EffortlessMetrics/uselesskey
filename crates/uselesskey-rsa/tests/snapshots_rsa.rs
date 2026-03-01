//! Insta snapshot tests for uselesskey-rsa.
//!
//! These tests snapshot PEM shapes and key metadata to detect
//! unintended changes in deterministic key generation.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[derive(Serialize)]
struct RsaPemSnapshot {
    label: &'static str,
    bits: usize,
    private_pem_starts_with: String,
    private_pem_ends_with: String,
    private_pem_line_count: usize,
    public_pem_starts_with: String,
    public_pem_ends_with: String,
    public_pem_line_count: usize,
    private_der_len: usize,
    public_der_len: usize,
}

#[derive(Serialize)]
struct RsaCorruptSnapshot {
    variant: &'static str,
    differs_from_original: bool,
}

#[test]
fn snapshot_rsa_2048_pem_shape() {
    let fx = fx();
    let kp = fx.rsa("snapshot-rsa-2048", RsaSpec::rs256());

    let priv_pem = kp.private_key_pkcs8_pem();
    let pub_pem = kp.public_key_spki_pem();
    let priv_lines: Vec<&str> = priv_pem.lines().collect();
    let pub_lines: Vec<&str> = pub_pem.lines().collect();

    let result = RsaPemSnapshot {
        label: "snapshot-rsa-2048",
        bits: 2048,
        private_pem_starts_with: priv_lines.first().unwrap_or(&"").to_string(),
        private_pem_ends_with: priv_lines.last().unwrap_or(&"").to_string(),
        private_pem_line_count: priv_lines.len(),
        public_pem_starts_with: pub_lines.first().unwrap_or(&"").to_string(),
        public_pem_ends_with: pub_lines.last().unwrap_or(&"").to_string(),
        public_pem_line_count: pub_lines.len(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("rsa_2048_pem_shape", result);
}

#[test]
fn snapshot_rsa_4096_pem_shape() {
    let fx = fx();
    let kp = fx.rsa("snapshot-rsa-4096", RsaSpec::new(4096));

    let priv_pem = kp.private_key_pkcs8_pem();
    let pub_pem = kp.public_key_spki_pem();
    let priv_lines: Vec<&str> = priv_pem.lines().collect();
    let pub_lines: Vec<&str> = pub_pem.lines().collect();

    let result = RsaPemSnapshot {
        label: "snapshot-rsa-4096",
        bits: 4096,
        private_pem_starts_with: priv_lines.first().unwrap_or(&"").to_string(),
        private_pem_ends_with: priv_lines.last().unwrap_or(&"").to_string(),
        private_pem_line_count: priv_lines.len(),
        public_pem_starts_with: pub_lines.first().unwrap_or(&"").to_string(),
        public_pem_ends_with: pub_lines.last().unwrap_or(&"").to_string(),
        public_pem_line_count: pub_lines.len(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("rsa_4096_pem_shape", result);
}

#[test]
fn snapshot_rsa_corrupt_pem_variants() {
    let fx = fx();
    let kp = fx.rsa("snapshot-corrupt", RsaSpec::rs256());

    let original = kp.private_key_pkcs8_pem();

    let variants = [
        (
            "BadBase64",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        ),
        (
            "BadHeader",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        ),
        (
            "BadFooter",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        ),
        (
            "ExtraBlankLine",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ),
    ];

    let results: Vec<RsaCorruptSnapshot> = variants
        .iter()
        .map(|(name, corrupt)| RsaCorruptSnapshot {
            variant: name,
            differs_from_original: corrupt != original,
        })
        .collect();

    insta::assert_yaml_snapshot!("rsa_corrupt_pem_variants", results);
}

#[test]
fn snapshot_rsa_key_sizes() {
    let fx = fx();

    #[derive(Serialize)]
    struct RsaSizeInfo {
        bits: usize,
        private_der_len: usize,
        public_der_len: usize,
    }

    let sizes: Vec<RsaSizeInfo> = [2048, 4096]
        .into_iter()
        .map(|bits| {
            let kp = fx.rsa(format!("size-{bits}"), RsaSpec::new(bits));
            RsaSizeInfo {
                bits,
                private_der_len: kp.private_key_pkcs8_der().len(),
                public_der_len: kp.public_key_spki_der().len(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("rsa_key_sizes", sizes);
}
