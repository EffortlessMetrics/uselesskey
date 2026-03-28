#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Stable receipt/manifest schema for `uselesskey` fixture outputs.
//!
//! The schema captures the deterministic identity inputs (`domain`, `label`,
//! `spec_fingerprint`, `variant`, `derivation_version`) plus emitted files and
//! hashes. Canonical JSON writing ensures byte-stable output for identical data.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uselesskey_core_id::ArtifactId;

/// Current receipt schema version.
pub const SCHEMA_VERSION: u16 = 1;

/// Generation mode recorded in receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedAtMode {
    /// Fixture was generated from a deterministic seed.
    Deterministic,
    /// Fixture was generated from runtime randomness.
    Random,
}

/// Single output file produced by a fixture sink.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct OutputFile {
    /// Stable logical name (example: `private_key`, `public_key`, `cert_chain`).
    pub logical_name: String,
    /// Serialized, slash-normalized path.
    pub path: String,
    /// Output wire format (example: `pem`, `der`, `json`, `jwks`).
    pub format: String,
    /// Lowercase hex SHA-256 digest.
    pub sha256: String,
    /// Lowercase hex BLAKE3 digest.
    pub blake3: String,
    /// Output length in bytes.
    pub byte_len: u64,
}

impl OutputFile {
    /// Build an [`OutputFile`] from raw bytes and a path-like display string.
    pub fn from_bytes(
        logical_name: impl Into<String>,
        path: impl AsRef<Path>,
        format: impl Into<String>,
        bytes: &[u8],
    ) -> Self {
        let sha256 = hex_lower(Sha256::digest(bytes).as_ref());
        let blake3 = hex_lower(blake3::hash(bytes).as_bytes());
        Self {
            logical_name: logical_name.into(),
            path: normalize_path(path.as_ref()),
            format: format.into(),
            sha256,
            blake3,
            byte_len: bytes.len() as u64,
        }
    }

    /// Build an [`OutputFile`] by reading bytes from disk.
    pub fn from_path(
        logical_name: impl Into<String>,
        path: impl AsRef<Path>,
        format: impl Into<String>,
    ) -> std::io::Result<Self> {
        let path_ref = path.as_ref();
        let bytes = std::fs::read(path_ref)?;
        Ok(Self::from_bytes(logical_name, path_ref, format, &bytes))
    }
}

/// Manifest for one fixture artifact and its produced files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureReceipt {
    /// Schema version for this receipt payload.
    pub schema_version: u16,
    /// `uselesskey` crate/package version producing this receipt.
    pub uselesskey_version: String,
    /// Artifact id domain.
    pub domain: String,
    /// Artifact id label.
    pub label: String,
    /// Artifact id variant.
    pub variant: String,
    /// Hex-encoded artifact `spec_fingerprint`.
    pub spec_fingerprint: String,
    /// Derivation version value.
    pub derivation_version: u16,
    /// Recorded generation mode.
    pub generated_at_mode: GeneratedAtMode,
    /// Produced files, sorted canonically at serialization time.
    pub files: Vec<OutputFile>,
    /// Optional user metadata.
    pub metadata: BTreeMap<String, String>,
}

impl FixtureReceipt {
    /// Create a receipt from an [`ArtifactId`].
    pub fn from_artifact_id(
        artifact_id: &ArtifactId,
        generated_at_mode: GeneratedAtMode,
        files: Vec<OutputFile>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            uselesskey_version: env!("CARGO_PKG_VERSION").to_string(),
            domain: artifact_id.domain.to_string(),
            label: artifact_id.label.clone(),
            variant: artifact_id.variant.clone(),
            spec_fingerprint: hex_lower(&artifact_id.spec_fingerprint),
            derivation_version: artifact_id.derivation_version.0,
            generated_at_mode,
            files,
            metadata: BTreeMap::new(),
        }
    }

    /// Returns a canonicalized clone (stable sorting for vectors).
    pub fn canonicalized(mut self) -> Self {
        self.files.sort();
        self
    }

    /// Serialize to canonical JSON bytes.
    pub fn to_canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let canonical = self.clone().canonicalized();
        serde_json::to_vec(&canonical)
    }

    /// Write canonical JSON bytes to a writer.
    pub fn write_canonical_json(&self, mut writer: impl Write) -> std::io::Result<()> {
        let bytes = self.to_canonical_json_bytes().map_err(to_io_error)?;
        writer.write_all(&bytes)
    }
}

/// Relationship edge for bundle-level linkage.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct BundleRelationship {
    /// Relationship kind (example: `cert_chain`, `jwks_member`, `token_signing_key`).
    pub relation: String,
    /// Source receipt or file logical identifier.
    pub from: String,
    /// Destination receipt or file logical identifier.
    pub to: String,
}

/// Aggregate manifest for a fixture bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleReceipt {
    /// Bundle name chosen by the caller.
    pub bundle_name: String,
    /// Contained receipts.
    pub receipts: Vec<FixtureReceipt>,
    /// Optional relationship graph.
    pub relationship_graph: Vec<BundleRelationship>,
}

impl BundleReceipt {
    /// Returns a canonicalized clone (stable sorting for vectors).
    pub fn canonicalized(mut self) -> Self {
        self.receipts.sort_by(bundle_receipt_sort_key);
        self.receipts = self
            .receipts
            .into_iter()
            .map(FixtureReceipt::canonicalized)
            .collect();
        self.relationship_graph.sort();
        self
    }

    /// Serialize to canonical JSON bytes.
    pub fn to_canonical_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let canonical = self.clone().canonicalized();
        serde_json::to_vec(&canonical)
    }

    /// Write canonical JSON bytes to a writer.
    pub fn write_canonical_json(&self, mut writer: impl Write) -> std::io::Result<()> {
        let bytes = self.to_canonical_json_bytes().map_err(to_io_error)?;
        writer.write_all(&bytes)
    }
}

fn bundle_receipt_sort_key(a: &FixtureReceipt, b: &FixtureReceipt) -> std::cmp::Ordering {
    (&a.domain, &a.label, &a.variant, &a.spec_fingerprint, a.derivation_version).cmp(&(
        &b.domain,
        &b.label,
        &b.variant,
        &b.spec_fingerprint,
        b.derivation_version,
    ))
}

/// Normalize paths to slash separators for platform-portable serialization.
pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn to_io_error(err: serde_json::Error) -> std::io::Error {
    std::io::Error::other(err)
}

impl fmt::Display for GeneratedAtMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deterministic => f.write_str("deterministic"),
            Self::Random => f.write_str("random"),
        }
    }
}
