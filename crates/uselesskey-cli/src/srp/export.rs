//! One-shot artifact exporters for local handoff formats.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use serde::Serialize;

use super::manifest::{BundleError, ExportArtifact};

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
    use crate::{ArtifactType, ManifestArtifact};

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
