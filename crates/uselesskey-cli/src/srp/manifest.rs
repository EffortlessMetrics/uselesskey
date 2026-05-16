//! Bundle manifest and artifact metadata types.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Bundle manifest describing generated artifacts and handoff metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Schema version for downstream compatibility.
    pub schema_version: u32,
    /// Artifact records in stable order.
    pub artifacts: Vec<ManifestArtifact>,
}

impl BundleManifest {
    /// Create an empty manifest with schema version `1`.
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            artifacts: Vec::new(),
        }
    }

    /// Add an artifact record and return self for chaining.
    pub fn with_artifact(mut self, artifact: ManifestArtifact) -> Self {
        self.artifacts.push(artifact);
        self
    }

    /// Render the manifest as pretty JSON.
    pub fn to_pretty_json(&self) -> Result<String, BundleError> {
        serde_json::to_string_pretty(self).map_err(BundleError::from)
    }

    /// Persist the manifest as pretty JSON on disk.
    pub fn write_json<P: AsRef<Path>>(&self, path: P) -> Result<(), BundleError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_pretty_json()?)?;
        Ok(())
    }
}

impl Default for BundleManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-artifact metadata in [`BundleManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifact {
    pub artifact_type: ArtifactType,
    pub source_seed: Option<String>,
    pub source_label: String,
    pub output_paths: Vec<String>,
    pub fingerprints: Vec<Fingerprint>,
    pub env_var_names: Vec<String>,
    pub external_key_ref: Option<KeyRef>,
}

/// Secret-key external reference model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyRef {
    File { path: String },
    Env { var: String },
    Vault { path: String },
    AwsSecret { name: String },
    GcpSecret { name: String },
    K8sSecret { name: String, key: String },
}

/// Artifact kinds for bundle metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    RsaPkcs8Pem,
    SpkiPem,
    Jwk,
    Token,
    X509Pem,
    Opaque,
}

/// Cryptographic fingerprint metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub algorithm: String,
    pub value: String,
}

/// In-memory artifact material and metadata used by exporters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportArtifact {
    pub key: String,
    pub value: String,
    pub manifest: ManifestArtifact,
}

/// Export errors.
#[derive(Debug, Error)]
pub enum BundleError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
