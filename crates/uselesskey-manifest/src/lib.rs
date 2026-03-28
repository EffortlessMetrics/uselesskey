#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Stable machine-readable receipt types for fixture generation outputs.
//!
//! This crate models two JSON payloads:
//! - [`FixtureReceipt`] for one fixture identity
//! - [`BundleReceipt`] for grouped fixture relationships

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uselesskey_core_id::ArtifactId;

/// Current receipt schema version.
pub const SCHEMA_VERSION_V1: u16 = 1;

/// Describes how a fixture was generated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedAtMode {
    /// Fixture came from deterministic mode.
    Deterministic,
    /// Fixture came from random mode.
    Random,
}

/// A single emitted file entry in a fixture receipt.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct OutputFile {
    /// Stable name used by callers for this file (e.g. `private_key_pkcs8`).
    pub logical_name: String,
    /// Relative or absolute path where output was written, normalized to `/` separators.
    pub path: String,
    /// Output format descriptor (`pem`, `der`, `json`, `jwks`, ...).
    pub format: String,
    /// SHA-256 digest (hex, lowercase).
    pub sha256: String,
    /// BLAKE3 digest (hex, lowercase).
    pub blake3: String,
    /// Number of bytes in this file.
    pub byte_len: u64,
}

impl OutputFile {
    /// Build a file descriptor from raw bytes.
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
            sha256: hex_encode(&Sha256::digest(bytes)),
            blake3: blake3::hash(bytes).to_hex().to_string(),
            byte_len: bytes.len() as u64,
        }
    }
}

/// Stable machine-readable receipt for a single fixture identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureReceipt {
    /// Manifest schema version.
    pub schema_version: u16,
    /// `uselesskey` crate ecosystem version string.
    pub uselesskey_version: String,
    /// Artifact identity domain.
    pub domain: String,
    /// Artifact identity label.
    pub label: String,
    /// Artifact identity variant.
    pub variant: String,
    /// Artifact identity spec fingerprint (hex lowercase).
    pub spec_fingerprint: String,
    /// Artifact identity derivation version.
    pub derivation_version: u16,
    /// Whether this was generated in deterministic or random mode.
    pub generated_at_mode: GeneratedAtMode,
    /// Stable sorted file entries.
    pub files: Vec<OutputFile>,
    /// Extensible metadata map.
    pub metadata: BTreeMap<String, String>,
}

impl FixtureReceipt {
    /// Create a receipt from an [`ArtifactId`].
    pub fn from_artifact_id(id: &ArtifactId, generated_at_mode: GeneratedAtMode) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            uselesskey_version: env!("CARGO_PKG_VERSION").to_string(),
            domain: id.domain.to_string(),
            label: id.label.clone(),
            variant: id.variant.clone(),
            spec_fingerprint: hex_encode(&id.spec_fingerprint),
            derivation_version: id.derivation_version.0,
            generated_at_mode,
            files: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Sort and attach file entries using stable order.
    pub fn with_files(mut self, mut files: Vec<OutputFile>) -> Self {
        files.sort_by(|a, b| {
            (&a.logical_name, &a.path, &a.format).cmp(&(&b.logical_name, &b.path, &b.format))
        });
        self.files = files;
        self
    }

    /// Add one metadata key/value pair.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let _ = self.metadata.insert(key.into(), value.into());
        self
    }

    /// Serialize as canonical, stable pretty JSON.
    pub fn to_canonical_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    /// Write canonical JSON to disk.
    pub fn write_canonical_json_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let json = self
            .to_canonical_json_vec()
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

/// Relationship edge between fixture receipts in a bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ReceiptRelationship {
    /// Edge kind (e.g. `cert_chain_parent`, `jwks_member`, `token_signed_by`).
    pub relation: String,
    /// From receipt key.
    pub from: String,
    /// To receipt key.
    pub to: String,
}

/// Bundle-level manifest collecting multiple fixture receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleReceipt {
    /// Bundle label.
    pub bundle_name: String,
    /// Stable sorted fixture receipts.
    pub receipts: Vec<FixtureReceipt>,
    /// Optional sorted relationship graph edges.
    pub relationships: Option<Vec<ReceiptRelationship>>,
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

    /// Add and stably sort receipts.
    pub fn with_receipts(mut self, mut receipts: Vec<FixtureReceipt>) -> Self {
        receipts.sort_by(|a, b| {
            (
                &a.domain,
                &a.label,
                &a.variant,
                &a.spec_fingerprint,
                a.derivation_version,
            )
                .cmp(&(
                    &b.domain,
                    &b.label,
                    &b.variant,
                    &b.spec_fingerprint,
                    b.derivation_version,
                ))
        });
        self.receipts = receipts;
        self
    }

    /// Add relationship edges using stable order.
    pub fn with_relationships(mut self, mut relationships: Vec<ReceiptRelationship>) -> Self {
        relationships.sort();
        self.relationships = Some(relationships);
        self
    }

    /// Serialize as canonical, stable pretty JSON.
    pub fn to_canonical_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }
}

/// Normalize a path for cross-platform manifests.
pub fn normalize_path(path: &Path) -> String {
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        normalized.push(comp);
    }
    normalized.to_string_lossy().replace('\\', "/")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
