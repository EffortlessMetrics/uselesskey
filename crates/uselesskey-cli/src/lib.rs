#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const RECEIPT_SCHEMA: &str = "uselesskey.export.receipt/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyRef {
    File {
        #[serde(with = "portable_path")]
        path: PathBuf,
    },
    Env {
        var_name: String,
    },
    Vault {
        path: String,
    },
    AwsSecret {
        name: String,
    },
    GcpSecret {
        name: String,
    },
    K8sSecret {
        name: String,
        key: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEntry {
    pub id: String,
    pub value: String,
    pub file_name: String,
    pub env_var_name: Option<String>,
    pub secret_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportTarget {
    FlatFileBundle,
    EnvDir,
    DotEnvFragment,
    KubernetesSecretYaml,
    SopsReadyYamlSkeleton,
    VaultKvJsonPayload,
    GenericManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundleSpec {
    pub bundle_name: String,
    pub target: ExportTarget,
    pub output_dir: PathBuf,
    pub entries: Vec<ExportEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundleResult {
    pub written_files: Vec<PathBuf>,
    pub manifest_path: PathBuf,
    pub references: BTreeMap<String, KeyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReceipt {
    pub schema: String,
    pub bundle_name: String,
    pub target: ExportTarget,
    pub written_files: Vec<String>,
    pub references: BTreeMap<String, KeyRef>,
}

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("bundle requires at least one export entry")]
    EmptyEntries,
    #[error("entry `{0}` has an empty file name")]
    EmptyFileName(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

pub fn export_bundle(spec: &ExportBundleSpec) -> Result<ExportBundleResult, ExportError> {
    validate_spec(spec)?;
    fs::create_dir_all(&spec.output_dir)?;

    let mut written_files = Vec::new();
    let mut references = BTreeMap::new();

    match spec.target {
        ExportTarget::FlatFileBundle => {
            let dir = spec.output_dir.join("bundle");
            fs::create_dir_all(&dir)?;
            for entry in &spec.entries {
                let path = dir.join(&entry.file_name);
                fs::write(&path, &entry.value)?;
                written_files.push(path.clone());
                references.insert(entry.id.clone(), KeyRef::File { path });
            }
        }
        ExportTarget::EnvDir => {
            let dir = spec.output_dir.join("envdir");
            fs::create_dir_all(&dir)?;
            for entry in &spec.entries {
                let var = entry
                    .env_var_name
                    .clone()
                    .unwrap_or_else(|| sanitize_env_name(&entry.id));
                let path = dir.join(&var);
                fs::write(&path, &entry.value)?;
                written_files.push(path);
                references.insert(entry.id.clone(), KeyRef::Env { var_name: var });
            }
        }
        ExportTarget::DotEnvFragment => {
            let path = spec.output_dir.join(format!("{}.env", spec.bundle_name));
            let mut out = String::new();
            for entry in &spec.entries {
                let var = entry
                    .env_var_name
                    .clone()
                    .unwrap_or_else(|| sanitize_env_name(&entry.id));
                out.push_str(&format!("{}={}\n", var, shell_escape(&entry.value)));
                references.insert(entry.id.clone(), KeyRef::Env { var_name: var });
            }
            fs::write(&path, out)?;
            written_files.push(path);
        }
        ExportTarget::KubernetesSecretYaml => {
            let path = spec
                .output_dir
                .join(format!("{}-secret.yaml", spec.bundle_name));
            let name = spec.bundle_name.replace('_', "-");
            let mut data: BTreeMap<String, String> = BTreeMap::new();
            for entry in &spec.entries {
                data.insert(
                    entry.file_name.clone(),
                    base64::engine::general_purpose::STANDARD.encode(&entry.value),
                );
                references.insert(
                    entry.id.clone(),
                    KeyRef::K8sSecret {
                        name: name.clone(),
                        key: entry.file_name.clone(),
                    },
                );
            }

            let doc = serde_yaml::to_string(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": name},
                "type": "Opaque",
                "data": data,
            }))?;
            fs::write(&path, doc)?;
            written_files.push(path);
        }
        ExportTarget::SopsReadyYamlSkeleton => {
            let path = spec
                .output_dir
                .join(format!("{}-sops.yaml", spec.bundle_name));
            let mut values = BTreeMap::new();
            for entry in &spec.entries {
                values.insert(
                    entry.id.clone(),
                    format!("ENC[AES256_GCM,data:{},type:str]", entry.value),
                );
                references.insert(entry.id.clone(), KeyRef::File { path: path.clone() });
            }
            let doc = serde_yaml::to_string(&serde_json::json!({
                "bundle": spec.bundle_name,
                "values": values,
                "sops": {
                    "kms": [],
                    "gcp_kms": [],
                    "hc_vault": [],
                    "age": [],
                    "lastmodified": "1970-01-01T00:00:00Z",
                    "mac": "ENC[UNSET]",
                    "version": "3.8.0"
                }
            }))?;
            fs::write(&path, doc)?;
            written_files.push(path);
        }
        ExportTarget::VaultKvJsonPayload => {
            let path = spec
                .output_dir
                .join(format!("{}-vault-kv.json", spec.bundle_name));
            let mount_path = format!("kv/data/{}", spec.bundle_name);
            let mut kv = BTreeMap::new();
            for entry in &spec.entries {
                kv.insert(entry.file_name.clone(), entry.value.clone());
                references.insert(
                    entry.id.clone(),
                    KeyRef::Vault {
                        path: format!("{}/{}", mount_path, entry.file_name),
                    },
                );
            }
            let payload = serde_json::json!({
                "data": {
                    "data": kv,
                }
            });
            fs::write(&path, serde_json::to_vec_pretty(&payload)?)?;
            written_files.push(path);
        }
        ExportTarget::GenericManifest => {
            for entry in &spec.entries {
                let default_path = spec.output_dir.join(&entry.file_name);
                references.insert(entry.id.clone(), KeyRef::File { path: default_path });
            }
        }
    }

    let manifest_path = write_receipt(spec, &written_files, &references)?;

    Ok(ExportBundleResult {
        written_files,
        manifest_path,
        references,
    })
}

fn write_receipt(
    spec: &ExportBundleSpec,
    written_files: &[PathBuf],
    references: &BTreeMap<String, KeyRef>,
) -> Result<PathBuf, ExportError> {
    let manifest_path = spec
        .output_dir
        .join(format!("{}-manifest.json", spec.bundle_name));
    let receipt = ExportReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        bundle_name: spec.bundle_name.clone(),
        target: spec.target.clone(),
        written_files: written_files
            .iter()
            .map(|path| path_to_string(path.as_path()))
            .collect(),
        references: references.clone(),
    };
    fs::write(&manifest_path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(manifest_path)
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

mod portable_path {
    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&path.to_string_lossy().replace('\\', "/"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(PathBuf::from)
    }
}

fn validate_spec(spec: &ExportBundleSpec) -> Result<(), ExportError> {
    if spec.entries.is_empty() {
        return Err(ExportError::EmptyEntries);
    }
    for entry in &spec.entries {
        if entry.file_name.trim().is_empty() {
            return Err(ExportError::EmptyFileName(entry.id.clone()));
        }
    }
    Ok(())
}

fn sanitize_env_name(s: &str) -> String {
    s.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn shell_escape(value: &str) -> String {
    let escaped = value.replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_env_name_normalizes_values() {
        assert_eq!(sanitize_env_name("rsa.private-key"), "RSA_PRIVATE_KEY");
    }
}
