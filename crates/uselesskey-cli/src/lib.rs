#![forbid(unsafe_code)]

//! Bundle manifest and export helpers for test fixtures.
//!
//! This crate exists to hand fixture outputs to ecosystem tools (Vault, SOPS,
//! Kubernetes, dotenv/envdir, local file trees) without becoming a secret
//! management system.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Reference to externally-managed secret material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyRef {
    File { path: String },
    Env { var: String },
    Vault { path: String },
    AwsSecret { name: String },
    GcpSecret { name: String },
    K8sSecret { name: String, key: String },
}

/// Stable source metadata for generated fixtures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceMetadata {
    pub seed_fingerprint: String,
    pub label: String,
    pub domain: String,
}

/// Fingerprint metadata for an artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub algorithm: String,
    pub value: String,
}

/// Portable metadata manifest for a generated bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub artifact_type: String,
    pub source: SourceMetadata,
    pub output_paths: Vec<String>,
    pub fingerprints: Vec<Fingerprint>,
    pub env_vars: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_key_refs: Vec<KeyRef>,
}

/// Errors returned by export helpers.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("failed to serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to serialize YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("failed to write output: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid environment variable key: {0}")]
    InvalidEnvKey(String),
}

impl BundleManifest {
    /// Serialize manifest as pretty JSON.
    pub fn to_pretty_json(&self) -> Result<String, ExportError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Write manifest JSON to disk.
    pub fn write_json_file(&self, path: impl AsRef<Path>) -> Result<(), ExportError> {
        fs::write(path, self.to_pretty_json()?)?;
        Ok(())
    }
}

/// Write key/value pairs as envdir files.
///
/// Each key becomes `<dir>/<KEY>` and contains the raw value bytes.
pub fn write_envdir(
    dir: impl AsRef<Path>,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<PathBuf>, ExportError> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;

    let mut paths = Vec::with_capacity(values.len());
    for (key, value) in values {
        validate_env_key(key)?;
        let path = dir.join(key);
        fs::write(&path, value)?;
        paths.push(path);
    }

    Ok(paths)
}

/// Render `KEY=value` lines suitable for appending to a dotenv file.
pub fn render_dotenv_fragment(values: &BTreeMap<String, String>) -> Result<String, ExportError> {
    let mut out = String::new();
    for (key, value) in values {
        validate_env_key(key)?;
        out.push_str(key);
        out.push('=');
        out.push_str(&escape_dotenv(value));
        out.push('\n');
    }

    Ok(out)
}

/// Render a Kubernetes Secret YAML document.
pub fn render_kubernetes_secret_yaml(
    name: &str,
    namespace: Option<&str>,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<String, ExportError> {
    let data = values
        .iter()
        .map(|(k, v)| (k.clone(), STANDARD.encode(v)))
        .collect::<BTreeMap<_, _>>();

    let mut metadata = Map::new();
    metadata.insert("name".to_string(), Value::String(name.to_owned()));
    if let Some(ns) = namespace {
        metadata.insert("namespace".to_string(), Value::String(ns.to_owned()));
    }

    let doc = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": metadata,
        "data": data,
    });

    Ok(serde_yaml::to_string(&doc)?)
}

/// Render a SOPS-ready YAML skeleton with plaintext placeholders.
pub fn render_sops_ready_yaml_skeleton(
    values: &BTreeMap<String, String>,
) -> Result<String, ExportError> {
    let mut string_data = BTreeMap::new();
    for (key, value) in values {
        validate_env_key(key)?;
        string_data.insert(key.clone(), format!("ENC[PLACEHOLDER,{value}]"));
    }

    let doc = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "stringData": string_data,
        "sops": {
            "metadata": "fill with your local sops configuration",
        }
    });

    Ok(serde_yaml::to_string(&doc)?)
}

/// Render a Vault KV v2 JSON payload (`{"data":{...}}`).
pub fn render_vault_kv_json_payload(values: &BTreeMap<String, String>) -> Result<String, ExportError> {
    for key in values.keys() {
        validate_env_key(key)?;
    }

    Ok(serde_json::to_string_pretty(&json!({ "data": values }))?)
}

fn validate_env_key(key: &str) -> Result<(), ExportError> {
    if key.is_empty() {
        return Err(ExportError::InvalidEnvKey("<empty>".to_string()));
    }

    if key
        .chars()
        .all(|c| c == '_' || c.is_ascii_alphanumeric())
    {
        return Ok(());
    }

    Err(ExportError::InvalidEnvKey(key.to_string()))
}

fn escape_dotenv(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
    {
        return value.to_string();
    }

    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_quotes_unsafe_values() {
        let mut values = BTreeMap::new();
        values.insert("API_KEY".to_string(), "a value with spaces".to_string());

        let out = render_dotenv_fragment(&values).expect("dotenv should render");
        assert_eq!(out, "API_KEY=\"a value with spaces\"\n");
    }

    #[test]
    fn vault_payload_wraps_data() {
        let mut values = BTreeMap::new();
        values.insert("TOKEN".to_string(), "abc123".to_string());

        let payload = render_vault_kv_json_payload(&values).expect("payload should render");
        let parsed: Value = serde_json::from_str(&payload).expect("payload should parse");
        assert_eq!(parsed["data"]["TOKEN"], "abc123");
    }
}
