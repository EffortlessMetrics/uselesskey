//! Insta snapshot tests for uselesskey-ecdsa.
//!
//! These tests snapshot PEM shapes and key metadata to detect
//! unintended changes in deterministic ECDSA key generation.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

#[derive(Serialize)]
struct EcdsaPemSnapshot {
    label: &'static str,
    curve: &'static str,
    private_pem_starts_with: String,
    private_pem_ends_with: String,
    private_pem_line_count: usize,
    public_pem_starts_with: String,
    public_pem_ends_with: String,
    public_pem_line_count: usize,
    private_der_len: usize,
    public_der_len: usize,
}

fn build_snapshot(
    fx: &uselesskey_core::Factory,
    label: &'static str,
    curve: &'static str,
    spec: EcdsaSpec,
) -> EcdsaPemSnapshot {
    let kp = fx.ecdsa(label, spec);
    let priv_pem = kp.private_key_pkcs8_pem();
    let pub_pem = kp.public_key_spki_pem();
    let priv_lines: Vec<&str> = priv_pem.lines().collect();
    let pub_lines: Vec<&str> = pub_pem.lines().collect();

    EcdsaPemSnapshot {
        label,
        curve,
        private_pem_starts_with: priv_lines.first().unwrap_or(&"").to_string(),
        private_pem_ends_with: priv_lines.last().unwrap_or(&"").to_string(),
        private_pem_line_count: priv_lines.len(),
        public_pem_starts_with: pub_lines.first().unwrap_or(&"").to_string(),
        public_pem_ends_with: pub_lines.last().unwrap_or(&"").to_string(),
        public_pem_line_count: pub_lines.len(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    }
}

#[test]
fn snapshot_ecdsa_p256_pem_shape() {
    let fx = fx();
    let result = build_snapshot(&fx, "snapshot-p256", "P-256", EcdsaSpec::es256());
    insta::assert_yaml_snapshot!("ecdsa_p256_pem_shape", result);
}

#[test]
fn snapshot_ecdsa_p384_pem_shape() {
    let fx = fx();
    let result = build_snapshot(&fx, "snapshot-p384", "P-384", EcdsaSpec::es384());
    insta::assert_yaml_snapshot!("ecdsa_p384_pem_shape", result);
}

#[test]
fn snapshot_ecdsa_key_sizes() {
    let fx = fx();

    #[derive(Serialize)]
    struct EcdsaSizeInfo {
        curve: &'static str,
        private_der_len: usize,
        public_der_len: usize,
    }

    let sizes: Vec<EcdsaSizeInfo> = vec![
        {
            let kp = fx.ecdsa("size-p256", EcdsaSpec::es256());
            EcdsaSizeInfo {
                curve: "P-256",
                private_der_len: kp.private_key_pkcs8_der().len(),
                public_der_len: kp.public_key_spki_der().len(),
            }
        },
        {
            let kp = fx.ecdsa("size-p384", EcdsaSpec::es384());
            EcdsaSizeInfo {
                curve: "P-384",
                private_der_len: kp.private_key_pkcs8_der().len(),
                public_der_len: kp.public_key_spki_der().len(),
            }
        },
    ];

    insta::assert_yaml_snapshot!("ecdsa_key_sizes", sizes);
}

#[test]
fn snapshot_ecdsa_corrupt_pem_variants() {
    let fx = fx();
    let kp = fx.ecdsa("snapshot-corrupt", EcdsaSpec::es256());

    let original = kp.private_key_pkcs8_pem();

    #[derive(Serialize)]
    struct CorruptInfo {
        variant: &'static str,
        differs_from_original: bool,
    }

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

    let results: Vec<CorruptInfo> = variants
        .iter()
        .map(|(name, corrupt)| CorruptInfo {
            variant: name,
            differs_from_original: corrupt != original,
        })
        .collect();

    insta::assert_yaml_snapshot!("ecdsa_corrupt_pem_variants", results);
}
