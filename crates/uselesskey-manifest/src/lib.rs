#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Stable manifest / receipt schema for fixture outputs.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use blake3::Hasher as Blake3Hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uselesskey_core_id::ArtifactId;

/// Current manifest schema version.
pub const SCHEMA_VERSION: &str = "1";

/// How the artifact was generated.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationMode {
    /// Deterministic mode (`Factory::deterministic`).
    Deterministic,
    /// Random mode (`Factory::random`).
    Random,
}

/// One output file produced for a fixture.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputFile {
    /// Logical file role inside a fixture (`private_key`, `public_key`, etc).
    pub logical_name: String,
    /// Serialized path with normalized separators (`/`).
    pub path: String,
    /// Content format (`pem`, `der`, `json`, `jwks`, ...).
    pub format: String,
    /// SHA-256 hash (lowercase hex).
    pub sha256: String,
    /// BLAKE3 hash (lowercase hex).
    pub blake3: String,
    /// Number of bytes written.
    pub byte_len: u64,
}

impl OutputFile {
    /// Build an [`OutputFile`] entry from file bytes.
    pub fn from_bytes(
        logical_name: impl Into<String>,
        path: impl AsRef<Path>,
        format: impl Into<String>,
        bytes: &[u8],
    ) -> Self {
        Self {
            logical_name: logical_name.into(),
            path: normalize_path(path.as_ref()),
            format: format.into(),
            sha256: sha256_hex(bytes),
            blake3: blake3_hex(bytes),
            byte_len: bytes.len() as u64,
        }
    }

    fn sort_key(&self) -> (&str, &str, &str, &str, &str, u64) {
        (
            &self.logical_name,
            &self.path,
            &self.format,
            &self.sha256,
            &self.blake3,
            self.byte_len,
        )
    }
}

/// Manifest entry for a single deterministic/random fixture artifact.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureReceipt {
    /// Schema version for the receipt itself.
    pub schema_version: String,
    /// `uselesskey` version that produced this receipt.
    pub uselesskey_version: String,
    /// Artifact domain (`rsa`, `x509`, ...).
    pub domain: String,
    /// Artifact label (`issuer`, `leaf`, ...).
    pub label: String,
    /// Artifact variant (`default`, `mismatch`, `corrupt:*`, ...).
    pub variant: String,
    /// Hex-encoded spec fingerprint from [`ArtifactId`].
    pub spec_fingerprint: String,
    /// Derivation version from [`ArtifactId`].
    pub derivation_version: u16,
    /// Whether generation mode was deterministic or random.
    pub generated_at_mode: GenerationMode,
    /// Files produced for this artifact.
    pub files: Vec<OutputFile>,
    /// Free-form additional metadata, stably ordered.
    pub metadata: BTreeMap<String, String>,
}

impl FixtureReceipt {
    /// Create a receipt from existing artifact-id inputs.
    pub fn from_artifact_id(id: &ArtifactId, generated_at_mode: GenerationMode) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            uselesskey_version: env!("CARGO_PKG_VERSION").to_string(),
            domain: id.domain.to_string(),
            label: id.label.clone(),
            variant: id.variant.clone(),
            spec_fingerprint: hex::encode(id.spec_fingerprint),
            derivation_version: id.derivation_version.0,
            generated_at_mode,
            files: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add an output file from in-memory bytes.
    pub fn push_file_from_bytes(
        &mut self,
        logical_name: impl Into<String>,
        path: impl AsRef<Path>,
        format: impl Into<String>,
        bytes: &[u8],
    ) {
        self.files
            .push(OutputFile::from_bytes(logical_name, path, format, bytes));
    }

    /// Add an output file from an on-disk path.
    pub fn push_file_from_path(
        &mut self,
        logical_name: impl Into<String>,
        path: impl AsRef<Path>,
        format: impl Into<String>,
    ) -> std::io::Result<()> {
        let bytes = fs::read(path.as_ref())?;
        self.push_file_from_bytes(logical_name, path, format, &bytes);
        Ok(())
    }

    /// Normalize ordering for canonical serialization.
    pub fn canonicalize(&mut self) {
        self.files.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    }
}

/// Manifest for a related set of fixture receipts.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleReceipt {
    /// Bundle identifier.
    pub bundle_name: String,
    /// Receipts contained in this bundle.
    pub receipts: Vec<FixtureReceipt>,
    /// Optional relationship graph (edge key -> nodes/descriptor).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<BTreeMap<String, String>>,
}

impl BundleReceipt {
    /// Create an empty bundle receipt.
    pub fn new(bundle_name: impl Into<String>) -> Self {
        Self {
            bundle_name: bundle_name.into(),
            receipts: Vec::new(),
            relationships: None,
        }
    }

    /// Normalize ordering for canonical serialization.
    pub fn canonicalize(&mut self) {
        self.receipts.sort_by(compare_receipts);
        for receipt in &mut self.receipts {
            receipt.canonicalize();
        }
    }
}

/// Serialize a fixture receipt into canonical JSON bytes.
pub fn to_canonical_json_bytes(receipt: &FixtureReceipt) -> serde_json::Result<Vec<u8>> {
    let mut value = receipt.clone();
    value.canonicalize();
    serde_json::to_vec_pretty(&value)
}

/// Serialize a bundle receipt into canonical JSON bytes.
pub fn bundle_to_canonical_json_bytes(bundle: &BundleReceipt) -> serde_json::Result<Vec<u8>> {
    let mut value = bundle.clone();
    value.canonicalize();
    serde_json::to_vec_pretty(&value)
}

/// Write a fixture receipt to disk using canonical ordering.
pub fn write_fixture_receipt_json(
    path: impl AsRef<Path>,
    receipt: &FixtureReceipt,
) -> std::io::Result<()> {
    let bytes = to_canonical_json_bytes(receipt)
        .map_err(|err| std::io::Error::other(format!("serialize fixture receipt: {err}")))?;
    fs::write(path, bytes)
}

/// Write a bundle receipt to disk using canonical ordering.
pub fn write_bundle_receipt_json(path: impl AsRef<Path>, bundle: &BundleReceipt) -> std::io::Result<()> {
    let bytes = bundle_to_canonical_json_bytes(bundle)
        .map_err(|err| std::io::Error::other(format!("serialize bundle receipt: {err}")))?;
    fs::write(path, bytes)
}

/// Normalize a path for JSON portability by replacing `\\` with `/`.
pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut sha256 = Sha256::new();
    sha256.update(bytes);
    hex::encode(sha256.finalize())
}

fn blake3_hex(bytes: &[u8]) -> String {
    let mut blake = Blake3Hasher::new();
    blake.update(bytes);
    blake.finalize().to_hex().to_string()
}

fn compare_receipts(a: &FixtureReceipt, b: &FixtureReceipt) -> Ordering {
    (
        a.domain.as_str(),
        a.label.as_str(),
        a.variant.as_str(),
        a.spec_fingerprint.as_str(),
        a.derivation_version,
    )
        .cmp(&(
            b.domain.as_str(),
            b.label.as_str(),
            b.variant.as_str(),
            b.spec_fingerprint.as_str(),
            b.derivation_version,
        ))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use uselesskey_core_id::{ArtifactId, DerivationVersion};

    use super::*;

    #[test]
    fn fixture_manifest_is_stable_across_ordering() {
        let id = ArtifactId::new("rsa", "issuer", b"spec-a", "default", DerivationVersion::V1);

        let mut a = FixtureReceipt::from_artifact_id(&id, GenerationMode::Deterministic);
        a.metadata.insert("b".to_string(), "2".to_string());
        a.metadata.insert("a".to_string(), "1".to_string());
        a.push_file_from_bytes("z", "out\\issuer.pub.pem", "pem", b"pub");
        a.push_file_from_bytes("a", "out\\issuer.key.pem", "pem", b"key");

        let mut b = FixtureReceipt::from_artifact_id(&id, GenerationMode::Deterministic);
        b.metadata.insert("a".to_string(), "1".to_string());
        b.metadata.insert("b".to_string(), "2".to_string());
        b.push_file_from_bytes("a", "out/issuer.key.pem", "pem", b"key");
        b.push_file_from_bytes("z", "out/issuer.pub.pem", "pem", b"pub");

        let ja = to_canonical_json_bytes(&a).expect("serialize a");
        let jb = to_canonical_json_bytes(&b).expect("serialize b");
        assert_eq!(ja, jb);
    }

    #[test]
    fn fixture_manifest_round_trip_parse() {
        let id = ArtifactId::new("token", "audience", b"spec", "default", DerivationVersion::V1);
        let mut receipt = FixtureReceipt::from_artifact_id(&id, GenerationMode::Random);
        receipt.push_file_from_bytes("token", "fixtures/token.txt", "txt", b"abc123");

        let json = to_canonical_json_bytes(&receipt).expect("serialize");
        let parsed: FixtureReceipt = serde_json::from_slice(&json).expect("parse");

        assert_eq!(parsed, receipt);
    }

    #[test]
    fn bundle_manifest_snapshot() {
        let id_a = ArtifactId::new("rsa", "issuer", b"spec-a", "default", DerivationVersion::V1);
        let id_b = ArtifactId::new("rsa", "leaf", b"spec-b", "default", DerivationVersion::V1);

        let mut receipt_b = FixtureReceipt::from_artifact_id(&id_b, GenerationMode::Deterministic);
        receipt_b.push_file_from_bytes("leaf_pub", "bundle/leaf.pub.pem", "pem", b"leaf-pub");

        let mut receipt_a = FixtureReceipt::from_artifact_id(&id_a, GenerationMode::Deterministic);
        receipt_a.push_file_from_bytes("issuer_pub", "bundle/issuer.pub.pem", "pem", b"issuer-pub");

        let mut bundle = BundleReceipt::new("chain-bundle");
        bundle.receipts.push(receipt_b);
        bundle.receipts.push(receipt_a);
        bundle.relationships = Some(BTreeMap::from([(
            "cert_chain".to_string(),
            "issuer->leaf".to_string(),
        )]));

        let json = bundle_to_canonical_json_bytes(&bundle).expect("serialize");
        let json_str = String::from_utf8(json).expect("utf8");

        insta::assert_snapshot!(json_str);
    }

    #[test]
    fn write_and_read_fixture_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("receipt.json");
        let id = ArtifactId::new("hmac", "api", b"spec", "default", DerivationVersion::V1);
        let mut receipt = FixtureReceipt::from_artifact_id(&id, GenerationMode::Deterministic);
        receipt.push_file_from_bytes("secret", PathBuf::from("keys\\api.key"), "txt", b"k");

        write_fixture_receipt_json(&path, &receipt).expect("write");
        let content = fs::read_to_string(&path).expect("read");
        assert!(content.contains("keys/api.key"));
    }
}
