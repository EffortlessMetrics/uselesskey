use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde_json::json;
use thiserror::Error;

use crate::manifest::BundleManifest;

/// A secret key/value entry used by export targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretEntry {
    pub key: String,
    pub value: String,
}

impl SecretEntry {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Export errors for local target generation.
#[derive(Debug, Error)]
pub enum ExportError {
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write file {path}: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize JSON: {0}")]
    SerializeJson(#[from] serde_json::Error),
}

/// Write flat files in envdir style (`<dir>/<KEY>` with secret value contents).
pub fn write_envdir(dir: impl AsRef<Path>, entries: &[SecretEntry]) -> Result<Vec<PathBuf>, ExportError> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir).map_err(|source| ExportError::CreateDir {
        path: dir.display().to_string(),
        source,
    })?;

    let mut outputs = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = dir.join(&entry.key);
        fs::write(&path, &entry.value).map_err(|source| ExportError::WriteFile {
            path: path.display().to_string(),
            source,
        })?;
        outputs.push(path);
    }

    Ok(outputs)
}

/// Render dotenv fragment output (`KEY='VALUE'`).
pub fn render_dotenv_fragment(entries: &[SecretEntry]) -> String {
    entries
        .iter()
        .map(|entry| {
            let escaped = entry.value.replace('\\', "\\\\").replace('\'', "\\'");
            format!("{}='{}'", entry.key, escaped)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render a Kubernetes Secret YAML-style payload as JSON text.
///
/// The output is serialized JSON for deterministic rendering while retaining the
/// same schema shape (`apiVersion`, `kind`, `metadata`, `stringData`).
pub fn render_kubernetes_secret(name: &str, entries: &[SecretEntry]) -> Result<String, ExportError> {
    let payload = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": { "name": name },
        "type": "Opaque",
        "stringData": into_map(entries),
    });
    Ok(serde_json::to_string_pretty(&payload)?)
}

/// Render a SOPS-ready YAML skeleton payload as JSON text.
///
/// This includes top-level `sops` metadata placeholders and a `stringData` map.
pub fn render_sops_skeleton(entries: &[SecretEntry]) -> Result<String, ExportError> {
    let payload = json!({
        "stringData": into_map(entries),
        "sops": {
            "kms": [],
            "gcp_kms": [],
            "azure_kv": [],
            "hc_vault": [],
            "age": [],
            "lastmodified": null,
            "mac": null,
            "version": "3.9.0"
        }
    });
    Ok(serde_json::to_string_pretty(&payload)?)
}

/// Render a Vault KV v2 write payload (`{"data": {...}}`).
pub fn render_vault_kv_json(entries: &[SecretEntry]) -> Result<String, ExportError> {
    let payload = json!({ "data": into_map(entries) });
    Ok(serde_json::to_string_pretty(&payload)?)
}

/// Serialize a metadata manifest to deterministic pretty JSON text.
pub fn render_bundle_manifest(manifest: &BundleManifest) -> Result<String, ExportError> {
    Ok(serde_json::to_string_pretty(manifest)?)
}

fn into_map(entries: &[SecretEntry]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect::<BTreeMap<_, _>>()
}
