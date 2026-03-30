#![forbid(unsafe_code)]

//! Export/bundle helpers for `uselesskey` fixture handoff.
//!
//! This crate intentionally focuses on one-shot local export targets and metadata
//! manifests. It does not implement rotation, retrieval, leasing, or long-running
//! key-store behavior.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
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

/// Write a set of artifacts to `root/<key>` as flat files.
pub fn export_flat_files<P: AsRef<Path>>(
    root: P,
    artifacts: &[ExportArtifact],
) -> Result<Vec<PathBuf>, BundleError> {
    let root = root.as_ref();
    fs::create_dir_all(root)?;

    let mut written = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let path = root.join(&artifact.key);
        fs::write(&path, artifact.value.as_bytes())?;
        written.push(path);
    }
    Ok(written)
}

/// Write artifacts as envdir files (`root/<ENV_VAR_NAME>` => value).
pub fn export_envdir<P: AsRef<Path>>(
    root: P,
    artifacts: &[ExportArtifact],
) -> Result<Vec<PathBuf>, BundleError> {
    let root = root.as_ref();
    fs::create_dir_all(root)?;

    let mut written = Vec::new();
    for artifact in artifacts {
        for var in &artifact.manifest.env_var_names {
            let path = root.join(var);
            fs::write(&path, artifact.value.as_bytes())?;
            written.push(path);
        }
    }
    Ok(written)
}

/// Render dotenv fragment (`KEY="value"`) using the first env-var name per artifact.
pub fn render_dotenv_fragment(artifacts: &[ExportArtifact]) -> String {
    let mut out = String::new();
    for artifact in artifacts {
        if let Some(var) = artifact.manifest.env_var_names.first() {
            let escaped = artifact
                .value
                .replace('\\', "\\\\")
                .replace('\n', "\\n")
                .replace('"', "\\\"");
            let _ = writeln!(&mut out, "{var}=\"{escaped}\"");
        }
    }
    out
}

/// Render a Kubernetes Secret manifest (opaque string data encoded as base64 under `data`).
pub fn render_k8s_secret_yaml(
    secret_name: &str,
    namespace: Option<&str>,
    artifacts: &[ExportArtifact],
) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "apiVersion: v1");
    let _ = writeln!(&mut out, "kind: Secret");
    let _ = writeln!(&mut out, "metadata:");
    let _ = writeln!(&mut out, "  name: {secret_name}");
    if let Some(ns) = namespace {
        let _ = writeln!(&mut out, "  namespace: {ns}");
    }
    let _ = writeln!(&mut out, "type: Opaque");
    let _ = writeln!(&mut out, "data:");
    for artifact in artifacts {
        let encoded = BASE64_STD.encode(artifact.value.as_bytes());
        let _ = writeln!(&mut out, "  {}: {}", artifact.key, encoded);
    }
    out
}

/// Render a SOPS-ready YAML skeleton with encrypted placeholders and metadata section.
pub fn render_sops_ready_yaml(artifacts: &[ExportArtifact]) -> String {
    let mut out = String::new();
    for artifact in artifacts {
        let _ = writeln!(
            &mut out,
            "{}: ENC[AES256_GCM,data:REDACTED,type:str]",
            artifact.key
        );
    }
    let _ = writeln!(&mut out, "sops:");
    let _ = writeln!(&mut out, "  version: 3.9.0");
    let _ = writeln!(&mut out, "  mac: ENC[AES256_GCM,data:REDACTED,type:str]");
    out
}

/// Render a Vault KV-v2 JSON payload (`{"data":{...},"metadata":{...}}`).
pub fn render_vault_kv_json(artifacts: &[ExportArtifact]) -> Result<String, BundleError> {
    #[derive(Serialize)]
    struct VaultPayload<'a> {
        data: BTreeMap<&'a str, &'a str>,
        metadata: BTreeMap<&'a str, &'a str>,
    }

    let data = artifacts
        .iter()
        .map(|a| (a.key.as_str(), a.value.as_str()))
        .collect::<BTreeMap<_, _>>();

    let metadata = [("source", "uselesskey-cli"), ("mode", "one_shot_export")]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    serde_json::to_string_pretty(&VaultPayload { data, metadata }).map_err(BundleError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_escapes_special_characters() {
        let artifacts = vec![ExportArtifact {
            key: "issuer_pem".to_string(),
            value: "line1\nline\"2".to_string(),
            manifest: ManifestArtifact {
                artifact_type: ArtifactType::RsaPkcs8Pem,
                source_seed: Some("seed-a".to_string()),
                source_label: "issuer".to_string(),
                output_paths: vec![],
                fingerprints: vec![],
                env_var_names: vec!["ISSUER_PEM".to_string()],
                external_key_ref: None,
            },
        }];

        let rendered = render_dotenv_fragment(&artifacts);
        assert_eq!(rendered, "ISSUER_PEM=\"line1\\nline\\\"2\"\n");
    }
}
