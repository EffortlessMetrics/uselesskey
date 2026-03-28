#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Stable fixture manifest / receipt schema for uselesskey.
//!
//! This crate provides deterministic, machine-readable JSON receipts that
//! describe which fixtures were produced, from which derivation identity, and
//! which files were emitted (including cryptographic hashes).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current schema version for serialized receipts.
pub const SCHEMA_VERSION: &str = "1";

/// Generation mode used to create fixture material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedAtMode {
    /// Fixture material was generated from deterministic seeds.
    Deterministic,
    /// Fixture material was generated from random entropy.
    Random,
}

/// Per-file output metadata captured in a fixture receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputFile {
    /// Stable logical role (e.g. `private_key`, `public_key`, `jwks`).
    pub logical_name: String,
    /// Portable path representation (always forward slashes).
    pub path: String,
    /// Output format (`pem`, `der`, `json`, `jwks`, ...).
    pub format: String,
    /// SHA-256 hash of file bytes, lower-case hex.
    pub sha256: String,
    /// BLAKE3 hash of file bytes, lower-case hex.
    pub blake3: String,
    /// Byte length of serialized output.
    pub byte_len: u64,
}

impl OutputFile {
    /// Build output metadata from raw bytes.
    pub fn from_bytes(logical_name: impl Into<String>, path: impl AsRef<Path>, format: impl Into<String>, bytes: &[u8]) -> Self {
        let sha256 = Sha256::digest(bytes);
        let blake3 = blake3::hash(bytes);
        Self {
            logical_name: logical_name.into(),
            path: normalize_path(path),
            format: format.into(),
            sha256: hex_lower(&sha256),
            blake3: blake3.to_hex().to_string(),
            byte_len: bytes.len() as u64,
        }
    }
}

/// Manifest describing a single deterministic fixture identity and its outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureReceipt {
    /// Schema version for this receipt payload.
    pub schema_version: String,
    /// `uselesskey` package version used to generate outputs.
    pub uselesskey_version: String,
    /// Artifact domain (e.g. `rsa`, `x509`, `jwks`).
    pub domain: String,
    /// Artifact label.
    pub label: String,
    /// Variant marker (e.g. `default`, `mismatch`, `corrupt:bad_header`).
    pub variant: String,
    /// Stable spec fingerprint already used by artifact derivation.
    pub spec_fingerprint: String,
    /// Derivation version used by the factory.
    pub derivation_version: u32,
    /// Whether generation used deterministic or random mode.
    pub generated_at_mode: GeneratedAtMode,
    /// Output files emitted for this fixture.
    pub files: Vec<OutputFile>,
    /// Optional stable metadata (sorted by key).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl FixtureReceipt {
    /// Create a new receipt with the current schema version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uselesskey_version: impl Into<String>,
        domain: impl Into<String>,
        label: impl Into<String>,
        variant: impl Into<String>,
        spec_fingerprint: impl Into<String>,
        derivation_version: u32,
        generated_at_mode: GeneratedAtMode,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            uselesskey_version: uselesskey_version.into(),
            domain: domain.into(),
            label: label.into(),
            variant: variant.into(),
            spec_fingerprint: spec_fingerprint.into(),
            derivation_version,
            generated_at_mode,
            files: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add an output file and keep stable ordering.
    pub fn push_file(&mut self, file: OutputFile) {
        self.files.push(file);
        sort_output_files(&mut self.files);
    }

    /// Serialize to canonical pretty JSON.
    pub fn to_canonical_json_pretty(&self) -> serde_json::Result<String> {
        let mut normalized = self.clone();
        normalized.normalize();
        serde_json::to_string_pretty(&normalized)
    }

    /// Write canonical pretty JSON to disk.
    pub fn write_canonical_json(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let json = self
            .to_canonical_json_pretty()
            .map_err(std::io::Error::other)?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, json)
    }

    fn normalize(&mut self) {
        self.schema_version = self.schema_version.trim().to_string();
        for file in &mut self.files {
            file.path = normalize_path(Path::new(&file.path));
        }
        sort_output_files(&mut self.files);
    }
}

/// Edge relation between fixture receipts inside a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleRelation {
    /// Type of relationship (e.g. `cert_chain`, `jwks_member`, `signed_by`).
    pub relation: String,
    /// Source node key.
    pub from: String,
    /// Target node key.
    pub to: String,
}

/// Group receipt for multi-artifact fixture bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleReceipt {
    /// Human-readable bundle name.
    pub bundle_name: String,
    /// Receipts contained in this bundle.
    pub receipts: Vec<FixtureReceipt>,
    /// Optional relationship graph.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<BundleRelation>,
}

impl BundleReceipt {
    /// Create an empty bundle with a stable name.
    pub fn new(bundle_name: impl Into<String>) -> Self {
        Self {
            bundle_name: bundle_name.into(),
            receipts: Vec::new(),
            relationships: Vec::new(),
        }
    }

    /// Push a fixture receipt and keep deterministic ordering.
    pub fn push_receipt(&mut self, receipt: FixtureReceipt) {
        self.receipts.push(receipt);
        self.normalize();
    }

    /// Push a relationship and keep deterministic ordering.
    pub fn push_relationship(&mut self, relation: BundleRelation) {
        self.relationships.push(relation);
        self.normalize();
    }

    /// Serialize to canonical pretty JSON.
    pub fn to_canonical_json_pretty(&self) -> serde_json::Result<String> {
        let mut normalized = self.clone();
        normalized.normalize();
        serde_json::to_string_pretty(&normalized)
    }

    /// Write canonical pretty JSON to disk.
    pub fn write_canonical_json(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let json = self
            .to_canonical_json_pretty()
            .map_err(std::io::Error::other)?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, json)
    }

    fn normalize(&mut self) {
        for receipt in &mut self.receipts {
            receipt.normalize();
        }
        self.receipts.sort_by(|a, b| {
            a.domain
                .cmp(&b.domain)
                .then(a.label.cmp(&b.label))
                .then(a.variant.cmp(&b.variant))
                .then(a.spec_fingerprint.cmp(&b.spec_fingerprint))
                .then(a.derivation_version.cmp(&b.derivation_version))
        });
        self.relationships.sort_by(|a, b| {
            a.relation
                .cmp(&b.relation)
                .then(a.from.cmp(&b.from))
                .then(a.to.cmp(&b.to))
        });
    }
}

fn sort_output_files(files: &mut [OutputFile]) {
    files.sort_by(|a, b| {
        a.logical_name
            .cmp(&b.logical_name)
            .then(a.path.cmp(&b.path))
            .then(a.format.cmp(&b.format))
    });
}

/// Normalize paths for cross-platform manifest portability.
pub fn normalize_path(path: impl AsRef<Path>) -> String {
    let normalized: PathBuf = path.as_ref().components().collect();
    normalized.to_string_lossy().replace('\\', "/")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_file_hashes_match_expected_vectors() {
        let output = OutputFile::from_bytes("key", "a/b.pem", "pem", b"hello");
        assert_eq!(
            output.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(
            output.blake3,
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
        assert_eq!(output.byte_len, 5);
    }

    #[test]
    fn normalize_path_rewrites_backslashes() {
        assert_eq!(normalize_path(r"foo\bar\baz.pem"), "foo/bar/baz.pem");
    }
}
