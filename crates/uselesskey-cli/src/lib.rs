#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyRef {
    File { path: PathBuf },
    Env { var_name: String },
    Vault { path: String },
    AwsSecret { name: String },
    GcpSecret { name: String },
    K8sSecret { name: String, key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetFormat {
    FlatFiles,
    EnvDir,
    DotEnvFragment,
    KubernetesSecretYaml,
    SopsYamlSkeleton,
    VaultKvJson,
    GenericManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundleSpec {
    pub bundle_name: String,
    pub outputs: Vec<PathBuf>,
    pub target_format: TargetFormat,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_names: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_names: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrittenFile {
    pub path: PathBuf,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundleResult {
    pub written_files: Vec<WrittenFile>,
    pub manifest_path: PathBuf,
    pub references: BTreeMap<String, KeyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    pub name: String,
    pub value: String,
}

pub mod exporters {
    use super::*;

    pub fn export_bundle(
        spec: &ExportBundleSpec,
        entries: &[BundleEntry],
        source_receipt: Option<&Path>,
    ) -> anyhow::Result<ExportBundleResult> {
        let mut written_files = Vec::new();
        let mut references = BTreeMap::new();

        for output_root in &spec.outputs {
            fs::create_dir_all(output_root)
                .with_context(|| format!("failed to create output dir {}", output_root.display()))?;
            match spec.target_format {
                TargetFormat::FlatFiles => {
                    write_flat_files(output_root, entries, &mut written_files, &mut references)?;
                }
                TargetFormat::EnvDir => {
                    write_envdir(output_root, entries, &mut written_files, &mut references)?;
                }
                TargetFormat::DotEnvFragment => {
                    write_dotenv(output_root, entries, &mut written_files, &mut references)?;
                }
                TargetFormat::KubernetesSecretYaml => {
                    write_k8s_secret(output_root, spec, entries, &mut written_files, &mut references)?;
                }
                TargetFormat::SopsYamlSkeleton => {
                    write_sops_skeleton(output_root, spec, entries, &mut written_files, &mut references)?;
                }
                TargetFormat::VaultKvJson => {
                    write_vault_kv_json(output_root, spec, entries, &mut written_files, &mut references)?;
                }
                TargetFormat::GenericManifest => {}
            }
        }

        let manifest_path = spec
            .outputs
            .first()
            .map(|p| p.join(format!("{}-manifest.json", spec.bundle_name)))
            .unwrap_or_else(|| PathBuf::from(format!("{}-manifest.json", spec.bundle_name)));

        let manifest = serde_json::json!({
            "bundle": spec.bundle_name,
            "target_format": spec.target_format,
            "references": references,
            "written_files": written_files,
            "source_receipt": source_receipt.map(|p| p.display().to_string()),
        });
        fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

        Ok(ExportBundleResult {
            written_files,
            manifest_path,
            references,
        })
    }

    fn write_flat_files(
        output_root: &Path,
        entries: &[BundleEntry],
        written: &mut Vec<WrittenFile>,
        refs: &mut BTreeMap<String, KeyRef>,
    ) -> anyhow::Result<()> {
        for entry in entries {
            let path = output_root.join(format!("{}.key", entry.name));
            fs::write(&path, &entry.value)?;
            written.push(WrittenFile {
                path: path.clone(),
                bytes: entry.value.len(),
            });
            refs.insert(entry.name.clone(), KeyRef::File { path });
        }
        Ok(())
    }

    fn write_envdir(
        output_root: &Path,
        entries: &[BundleEntry],
        written: &mut Vec<WrittenFile>,
        refs: &mut BTreeMap<String, KeyRef>,
    ) -> anyhow::Result<()> {
        for entry in entries {
            let var_name = sanitize_env_name(&entry.name);
            let path = output_root.join(&var_name);
            fs::write(&path, &entry.value)?;
            written.push(WrittenFile {
                path,
                bytes: entry.value.len(),
            });
            refs.insert(entry.name.clone(), KeyRef::Env { var_name });
        }
        Ok(())
    }

    fn write_dotenv(
        output_root: &Path,
        entries: &[BundleEntry],
        written: &mut Vec<WrittenFile>,
        refs: &mut BTreeMap<String, KeyRef>,
    ) -> anyhow::Result<()> {
        let path = output_root.join("bundle.env");
        let mut body = String::new();
        for entry in entries {
            let var_name = sanitize_env_name(&entry.name);
            body.push_str(&format!("{}={}\n", var_name, shell_escape(&entry.value)));
            refs.insert(entry.name.clone(), KeyRef::Env { var_name });
        }
        fs::write(&path, &body)?;
        written.push(WrittenFile {
            path,
            bytes: body.len(),
        });
        Ok(())
    }

    fn write_k8s_secret(
        output_root: &Path,
        spec: &ExportBundleSpec,
        entries: &[BundleEntry],
        written: &mut Vec<WrittenFile>,
        refs: &mut BTreeMap<String, KeyRef>,
    ) -> anyhow::Result<()> {
        let path = output_root.join("secret.yaml");
        let mut string_data = BTreeMap::new();
        for entry in entries {
            string_data.insert(entry.name.clone(), entry.value.clone());
            refs.insert(
                entry.name.clone(),
                KeyRef::K8sSecret {
                    name: spec.bundle_name.clone(),
                    key: entry.name.clone(),
                },
            );
        }

        let doc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": spec.bundle_name },
            "type": "Opaque",
            "stringData": string_data,
        });
        let yaml = serde_yaml::to_string(&doc)?;
        fs::write(&path, &yaml)?;
        written.push(WrittenFile {
            path,
            bytes: yaml.len(),
        });
        Ok(())
    }

    fn write_sops_skeleton(
        output_root: &Path,
        spec: &ExportBundleSpec,
        entries: &[BundleEntry],
        written: &mut Vec<WrittenFile>,
        refs: &mut BTreeMap<String, KeyRef>,
    ) -> anyhow::Result<()> {
        let path = output_root.join("sops-ready.yaml");
        let mut values = BTreeMap::new();
        for entry in entries {
            values.insert(entry.name.clone(), format!("ENC[AES256_GCM,data:{},type:str]", entry.value));
            refs.insert(
                entry.name.clone(),
                KeyRef::File { path: path.clone() },
            );
        }

        let doc = serde_json::json!({
            "bundle": spec.bundle_name,
            "values": values,
            "sops": {
                "kms": [],
                "gcp_kms": [],
                "azure_kv": [],
                "hc_vault": [],
                "age": [],
                "lastmodified": "1970-01-01T00:00:00Z",
                "mac": "",
                "version": "3.9.0"
            }
        });
        let yaml = serde_yaml::to_string(&doc)?;
        fs::write(&path, &yaml)?;
        written.push(WrittenFile {
            path,
            bytes: yaml.len(),
        });
        Ok(())
    }

    fn write_vault_kv_json(
        output_root: &Path,
        spec: &ExportBundleSpec,
        entries: &[BundleEntry],
        written: &mut Vec<WrittenFile>,
        refs: &mut BTreeMap<String, KeyRef>,
    ) -> anyhow::Result<()> {
        let path = output_root.join("vault-kv.json");
        let mut data = BTreeMap::new();
        for entry in entries {
            data.insert(entry.name.clone(), entry.value.clone());
            refs.insert(
                entry.name.clone(),
                KeyRef::Vault {
                    path: format!("secret/data/{}", spec.bundle_name),
                },
            );
        }

        let payload = serde_json::json!({
            "path": format!("secret/data/{}", spec.bundle_name),
            "data": { "data": data }
        });
        let body = serde_json::to_vec_pretty(&payload)?;
        fs::write(&path, &body)?;
        written.push(WrittenFile {
            path,
            bytes: body.len(),
        });
        Ok(())
    }

    fn sanitize_env_name(name: &str) -> String {
        name.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn shell_escape(value: &str) -> String {
        if value.chars().all(|c| c.is_ascii_alphanumeric() || "-_:./".contains(c)) {
            value.to_string()
        } else {
            format!("'{}'", value.replace('\'', "'\\''"))
        }
    }
}
