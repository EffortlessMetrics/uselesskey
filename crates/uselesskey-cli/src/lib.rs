#![forbid(unsafe_code)]

//! Export-focused manifest and rendering helpers for `uselesskey` fixtures.
//!
//! This crate intentionally stops at **artifact handoff**: generate fixtures once,
//! emit files and manifest metadata, and let external systems (Vault/SOPS/Kubernetes
//! or cloud secret stores) own lifecycle thereafter.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Versioned manifest for fixture bundle handoff.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BundleManifest {
    /// Monotonic schema version for the manifest shape.
    pub schema_version: u32,
    /// Entries emitted by the fixture generation process.
    pub artifacts: Vec<ManifestArtifact>,
}

/// Single artifact entry in a bundle manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ManifestArtifact {
    /// Stable identifier for this artifact in the manifest.
    pub artifact_id: String,
    /// Logical artifact category.
    pub artifact_type: ArtifactType,
    /// Source metadata (seed mode and label lineage).
    pub source: SourceMetadata,
    /// Paths written during export.
    pub output_paths: Vec<OutputPath>,
    /// Fingerprints for traceability.
    pub fingerprints: Vec<Fingerprint>,
    /// Intended environment variable names.
    pub env_vars: Vec<String>,
    /// Optional references to external systems.
    #[serde(default)]
    pub external_key_refs: Vec<KeyRef>,
}

/// Supported artifact types for export metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Rsa,
    Ecdsa,
    Ed25519,
    Hmac,
    Token,
    X509,
    Pgp,
    Generic,
}

/// Seed/label metadata for generated fixtures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceMetadata {
    /// Domain used in fixture factory identity.
    pub domain: String,
    /// Label passed by caller when generating artifact.
    pub label: String,
    /// Human-readable seed mode (`deterministic` or `random`).
    pub seed_mode: String,
}

/// Destination path metadata for a rendered output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OutputPath {
    /// Export target kind (e.g. `flat_file`, `envdir`, `dotenv_fragment`).
    pub target: String,
    /// Relative or absolute output path.
    pub path: String,
}

/// Fingerprint metadata tied to an exported artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Fingerprint {
    /// Algorithm name (`sha256`, `sha1`, etc.).
    pub algorithm: String,
    /// Hex- or base64-encoded fingerprint.
    pub value: String,
}

/// Reference to a key value stored outside the bundle itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyRef {
    File { path: String },
    Env { var: String },
    Vault { path: String },
    AwsSecret { name: String },
    GcpSecret { name: String },
    K8sSecret { name: String, key: String },
}

/// Errors returned by export helpers.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Write a flat-file envdir (`VAR_NAME` files containing plain values).
pub fn write_envdir<P: AsRef<Path>>(
    base_dir: P,
    entries: &BTreeMap<String, String>,
) -> Result<Vec<OutputPath>, ExportError> {
    let base_dir = base_dir.as_ref();
    fs::create_dir_all(base_dir)?;

    let mut outputs = Vec::with_capacity(entries.len());
    for (name, value) in entries {
        let file_path = base_dir.join(name);
        fs::write(&file_path, value)?;

        outputs.push(OutputPath {
            target: "envdir".to_owned(),
            path: file_path.to_string_lossy().into_owned(),
        });
    }

    Ok(outputs)
}

/// Render a dotenv fragment (`KEY='value'` lines).
pub fn render_dotenv_fragment(entries: &BTreeMap<String, String>) -> String {
    entries
        .iter()
        .map(|(k, v)| format!("{}='{}'", k, escape_dotenv_value(v)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_dotenv_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Render Kubernetes Secret YAML with `stringData` for plaintext handoff.
pub fn render_k8s_secret_yaml(
    name: &str,
    namespace: Option<&str>,
    entries: &BTreeMap<String, String>,
) -> Result<String, ExportError> {
    let mut metadata = serde_json::Map::new();
    metadata.insert("name".into(), json!(name));
    if let Some(namespace) = namespace {
        metadata.insert("namespace".into(), json!(namespace));
    }

    let doc = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": metadata,
        "type": "Opaque",
        "stringData": entries,
    });

    Ok(serde_yaml::to_string(&doc)?)
}

/// Render a SOPS-ready YAML skeleton with cleartext values and empty metadata.
pub fn render_sops_ready_yaml(entries: &BTreeMap<String, String>) -> Result<String, ExportError> {
    let doc = json!({
        "data": entries,
        "sops": {
            "kms": [],
            "gcp_kms": [],
            "azure_kv": [],
            "hc_vault": [],
            "age": [],
            "lastmodified": null,
            "mac": null,
            "pgp": [],
            "encrypted_regex": "^(data|stringData)$",
            "version": "3.9.0",
        }
    });

    Ok(serde_yaml::to_string(&doc)?)
}

/// Render Vault KV v2 payload JSON (`{"data": {...}}`).
pub fn render_vault_kv_payload(entries: &BTreeMap<String, String>) -> Result<String, ExportError> {
    let payload = json!({ "data": entries });
    Ok(serde_json::to_string_pretty(&payload)?)
}

/// Render generic metadata manifest JSON.
pub fn render_manifest_json(manifest: &BundleManifest) -> Result<String, ExportError> {
    Ok(serde_json::to_string_pretty(manifest)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_escapes_quotes_and_backslashes() {
        let mut data = BTreeMap::new();
        data.insert("TOKEN".to_string(), "path\\o'hare".to_string());

        let out = render_dotenv_fragment(&data);
        assert_eq!(out, "TOKEN='path\\\\o\\'hare'");
    }
}
