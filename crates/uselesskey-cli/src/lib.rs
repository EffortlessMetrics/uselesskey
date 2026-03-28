//! Export support for `uselesskey` CLI outputs.
//!
//! The export layer writes fixture values to common file formats and emits
//! references/manifests that downstream secret-delivery tools ingest.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

/// Reference to where a generated fixture was written for downstream tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyRef {
    /// File path containing fixture material.
    File {
        /// Path to the generated fixture file.
        path: PathBuf,
    },
    /// Environment variable key containing fixture material.
    Env {
        /// Environment variable name consumers should read.
        var_name: String,
    },
    /// Vault KV path where fixture payload can be written by user tooling.
    Vault {
        /// Vault path (mount-relative or fully-qualified) for payload write.
        path: String,
    },
    /// AWS Secrets Manager secret name.
    AwsSecret {
        /// AWS Secrets Manager secret name.
        name: String,
    },
    /// Google Secret Manager secret name.
    GcpSecret {
        /// GCP Secret Manager secret name.
        name: String,
    },
    /// Kubernetes Secret name and key entry.
    K8sSecret {
        /// Kubernetes Secret resource name.
        name: String,
        /// Secret data key within the Kubernetes Secret object.
        key: String,
    },
}

/// Export format target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ExportTargetFormat {
    /// One file per item in a bundle directory.
    FlatFileBundle,
    /// Envdir format (`<dir>/<VAR>` files).
    Envdir,
    /// `.env` fragment.
    DotenvFragment,
    /// Kubernetes `Secret` YAML.
    KubernetesSecretYaml,
    /// SOPS-ready YAML skeleton.
    SopsReadyYaml,
    /// Vault KV JSON payload (`{"data": {...}}`).
    VaultKvJson,
    /// Reference-only JSON manifest.
    GenericManifest,
}

/// Specification for a bundle export operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundleSpec {
    /// Human-oriented bundle name.
    pub bundle_name: String,
    /// Output root directory.
    pub out_dir: PathBuf,
    /// Selected export target format.
    pub target_format: ExportTargetFormat,
    /// Material map keyed by logical identifier.
    pub outputs: BTreeMap<String, String>,
    /// Optional explicit env-var names per output key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_var_names: BTreeMap<String, String>,
    /// Optional explicit provider secret names per output key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_names: BTreeMap<String, String>,
    /// Optional link to upstream fixture receipt/manifest path for coherence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_receipt_path: Option<PathBuf>,
}

/// Result emitted from a bundle export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundleResult {
    /// Written output files.
    pub written_files: Vec<PathBuf>,
    /// Reference manifest path.
    pub manifest_path: PathBuf,
    /// Logical references emitted by export.
    pub references: BTreeMap<String, Vec<KeyRef>>,
}

/// Execute an export bundle write.
pub fn export_bundle(spec: &ExportBundleSpec) -> Result<ExportBundleResult> {
    fs::create_dir_all(&spec.out_dir)
        .with_context(|| format!("failed to create output dir {}", spec.out_dir.display()))?;

    let mut written_files = Vec::new();
    let mut references: BTreeMap<String, Vec<KeyRef>> = BTreeMap::new();

    match spec.target_format {
        ExportTargetFormat::FlatFileBundle | ExportTargetFormat::Envdir => {
            for (logical, value) in &spec.outputs {
                let file_key = sanitize_key(logical);
                let file_path = spec.out_dir.join(file_key);
                fs::write(&file_path, value)
                    .with_context(|| format!("failed to write {}", file_path.display()))?;
                written_files.push(file_path.clone());
                references
                    .entry(logical.clone())
                    .or_default()
                    .push(KeyRef::File { path: file_path });
            }
        }
        ExportTargetFormat::DotenvFragment => {
            let file_path = spec.out_dir.join(format!("{}.env", spec.bundle_name));
            let mut body = String::new();
            for (logical, value) in &spec.outputs {
                let var = env_name_for(spec, logical);
                body.push_str(&format!("{}={}\n", var, escape_dotenv_value(value)));
                references
                    .entry(logical.clone())
                    .or_default()
                    .push(KeyRef::Env { var_name: var });
            }
            fs::write(&file_path, body)
                .with_context(|| format!("failed to write {}", file_path.display()))?;
            written_files.push(file_path);
        }
        ExportTargetFormat::KubernetesSecretYaml => {
            let secret_name = spec
                .secret_names
                .get("k8s_secret_name")
                .cloned()
                .unwrap_or_else(|| spec.bundle_name.clone());
            let yaml = build_k8s_secret_yaml(&secret_name, &spec.outputs)?;
            let file_path = spec.out_dir.join(format!("{}-k8s-secret.yaml", spec.bundle_name));
            fs::write(&file_path, yaml)
                .with_context(|| format!("failed to write {}", file_path.display()))?;
            for logical in spec.outputs.keys() {
                references
                    .entry(logical.clone())
                    .or_default()
                    .push(KeyRef::K8sSecret {
                        name: secret_name.clone(),
                        key: sanitize_key(logical),
                    });
            }
            written_files.push(file_path);
        }
        ExportTargetFormat::SopsReadyYaml => {
            let yaml = build_sops_skeleton(&spec.bundle_name, &spec.outputs)?;
            let file_path = spec.out_dir.join(format!("{}.sops.yaml", spec.bundle_name));
            fs::write(&file_path, yaml)
                .with_context(|| format!("failed to write {}", file_path.display()))?;
            for logical in spec.outputs.keys() {
                references
                    .entry(logical.clone())
                    .or_default()
                    .push(KeyRef::File {
                        path: file_path.clone(),
                    });
            }
            written_files.push(file_path);
        }
        ExportTargetFormat::VaultKvJson => {
            let mount = spec
                .secret_names
                .get("vault_mount")
                .cloned()
                .unwrap_or_else(|| "secret".to_string());
            let path = spec
                .secret_names
                .get("vault_path")
                .cloned()
                .unwrap_or_else(|| format!("uselesskey/{}", spec.bundle_name));
            let body = serde_json::json!({
                "mount": mount,
                "path": path,
                "data": spec.outputs,
                "options": { "cas": 0 }
            });
            let file_path = spec.out_dir.join(format!("{}-vault-kv.json", spec.bundle_name));
            fs::write(&file_path, serde_json::to_string_pretty(&body)?)
                .with_context(|| format!("failed to write {}", file_path.display()))?;
            for logical in spec.outputs.keys() {
                references
                    .entry(logical.clone())
                    .or_default()
                    .push(KeyRef::Vault {
                        path: format!("{mount}/data/{path}"),
                    });
            }
            written_files.push(file_path);
        }
        ExportTargetFormat::GenericManifest => {}
    }

    let manifest = serde_json::json!({
        "bundle_name": spec.bundle_name,
        "target_format": spec.target_format,
        "source_receipt_path": spec.source_receipt_path,
        "written_files": written_files,
        "references": references,
    });
    let manifest_path = spec.out_dir.join(format!("{}-manifest.json", spec.bundle_name));
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;

    if matches!(spec.target_format, ExportTargetFormat::GenericManifest) {
        for logical in spec.outputs.keys() {
            references
                .entry(logical.clone())
                .or_default()
                .push(KeyRef::File {
                    path: manifest_path.clone(),
                });
        }
    }

    Ok(ExportBundleResult {
        written_files,
        manifest_path,
        references,
    })
}

/// Build Kubernetes Secret YAML with `stringData` fields.
pub fn build_k8s_secret_yaml(secret_name: &str, outputs: &BTreeMap<String, String>) -> Result<String> {
    if secret_name.trim().is_empty() {
        return Err(anyhow!("k8s secret name cannot be empty"));
    }

    let mut root = serde_yaml::Mapping::new();
    root.insert("apiVersion".into(), "v1".into());
    root.insert("kind".into(), "Secret".into());

    let mut metadata = serde_yaml::Mapping::new();
    metadata.insert("name".into(), secret_name.into());
    root.insert("metadata".into(), metadata.into());

    root.insert("type".into(), "Opaque".into());

    let mut string_data = serde_yaml::Mapping::new();
    for (key, value) in outputs {
        string_data.insert(sanitize_key(key).into(), value.clone().into());
    }
    root.insert("stringData".into(), string_data.into());

    serde_yaml::to_string(&root).context("failed to serialize k8s yaml")
}

/// Build a SOPS-ready YAML skeleton for users to encrypt with their own workflow.
pub fn build_sops_skeleton(bundle_name: &str, outputs: &BTreeMap<String, String>) -> Result<String> {
    let doc = serde_json::json!({
        "bundle": bundle_name,
        "data": outputs,
        "sops": {
            "note": "Run your standard sops workflow to encrypt this file.",
            "kms": [],
            "gcp_kms": [],
            "hc_vault": [],
            "azure_kv": [],
            "age": [],
            "lastmodified": "1970-01-01T00:00:00Z",
            "mac": "ENC[AES256_GCM,data:placeholder,iv:placeholder,tag:placeholder,type:str]",
            "version": "3.9.0"
        }
    });
    serde_yaml::to_string(&doc).context("failed to serialize sops skeleton")
}

fn sanitize_key(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' => c,
            _ => '_',
        })
        .collect()
}

fn env_name_for(spec: &ExportBundleSpec, logical: &str) -> String {
    spec.env_var_names
        .get(logical)
        .cloned()
        .unwrap_or_else(|| sanitize_key(logical).to_ascii_uppercase())
}

fn escape_dotenv_value(value: &str) -> String {
    if value.contains('\n') || value.contains(' ') || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

/// Parse repeated `KEY=VALUE` CLI flags into a map.
pub fn parse_entries(entries: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for entry in entries {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("entry must be KEY=VALUE: {entry}"))?;
        if key.trim().is_empty() {
            return Err(anyhow!("entry key cannot be empty"));
        }
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}
