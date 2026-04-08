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
use uselesskey_core::{Factory, Seed};
#[cfg(feature = "rsa-materialize")]
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

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

/// Materialization manifest schema version supported by this crate.
pub const MATERIALIZE_MANIFEST_VERSION: u32 = 1;

/// Errors for manifest-driven fixture materialization.
#[derive(Debug, Error)]
pub enum MaterializeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("manifest parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("{0}")]
    InvalidManifest(String),
}

/// Manifest describing deterministic fixture outputs that can be written or verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializeManifest {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default, alias = "fixture")]
    pub fixtures: Vec<MaterializeFixtureSpec>,
}

/// One fixture entry in a [`MaterializeManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializeFixtureSpec {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(alias = "path")]
    pub out: PathBuf,
    pub kind: MaterializeKind,
    pub seed: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub len: Option<usize>,
}

/// Supported fixture kinds for manifest-driven materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializeKind {
    #[serde(rename = "entropy.bytes", alias = "entropy_bytes")]
    EntropyBytes,
    #[serde(rename = "token.jwt_shape", alias = "jwt_shape")]
    TokenJwtShape,
    #[serde(rename = "rsa.pkcs8_der", alias = "pkcs8_der")]
    RsaPkcs8Der,
    #[serde(rename = "rsa.pkcs8_pem", alias = "pkcs8_pem")]
    RsaPkcs8Pem,
    #[serde(rename = "pem.block_shape", alias = "pem_block_shape")]
    PemBlockShape,
    #[serde(rename = "ssh.public_key_shape", alias = "ssh_public_key_shape")]
    SshPublicKeyShape,
    #[serde(rename = "token.api_key", alias = "token")]
    TokenApiKey,
}

/// Summary returned after a materialize or verify pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaterializeSummary {
    pub count: usize,
    pub files: Vec<PathBuf>,
}

/// Parse a manifest string and validate the supported schema.
pub fn parse_materialize_manifest_str(raw: &str) -> Result<MaterializeManifest, MaterializeError> {
    let manifest: MaterializeManifest = toml::from_str(raw)?;
    validate_materialize_manifest(manifest)
}

/// Load and validate a manifest from disk.
pub fn load_materialize_manifest(path: &Path) -> Result<MaterializeManifest, MaterializeError> {
    let raw = fs::read_to_string(path)?;
    parse_materialize_manifest_str(&raw)
}

/// Materialize or verify the manifest contents under `out_dir`.
pub fn materialize_manifest_to_dir(
    manifest: &MaterializeManifest,
    out_dir: &Path,
    check: bool,
) -> Result<MaterializeSummary, MaterializeError> {
    if manifest.fixtures.is_empty() {
        return Err(MaterializeError::InvalidManifest(
            "materialize manifest has no fixtures".to_string(),
        ));
    }

    let mut files = Vec::with_capacity(manifest.fixtures.len());
    for fixture in &manifest.fixtures {
        let out_path = resolve_fixture_path(out_dir, &fixture.out);
        let bytes = materialized_fixture_bytes(fixture)?;
        if check {
            verify_fixture_bytes(&out_path, &bytes)?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&out_path, bytes)?;
        }
        files.push(out_path);
    }

    Ok(MaterializeSummary {
        count: manifest.fixtures.len(),
        files,
    })
}

/// Load a manifest from disk, then materialize or verify it under `out_dir`.
pub fn materialize_manifest_file(
    manifest_path: &Path,
    out_dir: &Path,
    check: bool,
) -> Result<MaterializeSummary, MaterializeError> {
    let manifest = load_materialize_manifest(manifest_path)?;
    materialize_manifest_to_dir(&manifest, out_dir, check)
}

/// Emit a Rust module containing `include_bytes!` constants for each manifest entry.
pub fn emit_include_bytes_module(
    manifest: &MaterializeManifest,
    out_dir: &Path,
    module_path: &Path,
) -> Result<(), MaterializeError> {
    if manifest.fixtures.is_empty() {
        return Err(MaterializeError::InvalidManifest(
            "cannot emit module for empty materialize manifest".to_string(),
        ));
    }

    let mut out = String::from("// @generated by uselesskey-cli materialize\n");
    let mut seen = std::collections::BTreeSet::new();
    for fixture in &manifest.fixtures {
        let const_name = fixture_const_name(fixture);
        if !seen.insert(const_name.clone()) {
            return Err(MaterializeError::InvalidManifest(format!(
                "duplicate emitted constant name `{const_name}`"
            )));
        }

        let include_path = resolve_fixture_path(out_dir, &fixture.out);
        let escaped = include_path
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let _ = writeln!(
            &mut out,
            "pub const {const_name}: &[u8] = include_bytes!(\"{escaped}\");"
        );
    }

    if let Some(parent) = module_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(module_path, out)?;
    Ok(())
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

fn validate_materialize_manifest(
    manifest: MaterializeManifest,
) -> Result<MaterializeManifest, MaterializeError> {
    let version = manifest.version.unwrap_or(MATERIALIZE_MANIFEST_VERSION);
    if version != MATERIALIZE_MANIFEST_VERSION {
        return Err(MaterializeError::InvalidManifest(format!(
            "unsupported manifest version {version}"
        )));
    }
    Ok(manifest)
}

fn resolve_fixture_path(out_dir: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        out_dir.join(target)
    }
}

fn materialized_fixture_bytes(spec: &MaterializeFixtureSpec) -> Result<Vec<u8>, MaterializeError> {
    let label = spec
        .label
        .clone()
        .unwrap_or_else(|| fallback_label(&spec.out));
    let fx = Factory::deterministic_from_str(&spec.seed);

    match spec.kind {
        MaterializeKind::EntropyBytes => {
            let len = spec.len.unwrap_or(32);
            let seed = Seed::from_text(&spec.seed);
            let mut bytes = vec![0u8; len];
            seed.fill_bytes(&mut bytes);
            Ok(bytes)
        }
        MaterializeKind::TokenJwtShape => Ok(fx
            .token(&label, TokenSpec::oauth_access_token())
            .value()
            .as_bytes()
            .to_vec()),
        MaterializeKind::RsaPkcs8Der => {
            #[cfg(feature = "rsa-materialize")]
            {
                Ok(fx
                    .rsa(&label, RsaSpec::rs256())
                    .private_key_pkcs8_der()
                    .to_vec())
            }
            #[cfg(not(feature = "rsa-materialize"))]
            {
                Err(MaterializeError::InvalidManifest(
                    "rsa.pkcs8_der requires uselesskey-cli feature `rsa-materialize`".to_string(),
                ))
            }
        }
        MaterializeKind::RsaPkcs8Pem => {
            #[cfg(feature = "rsa-materialize")]
            {
                Ok(fx
                    .rsa(&label, RsaSpec::rs256())
                    .private_key_pkcs8_pem()
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(not(feature = "rsa-materialize"))]
            {
                Err(MaterializeError::InvalidManifest(
                    "rsa.pkcs8_pem requires uselesskey-cli feature `rsa-materialize`".to_string(),
                ))
            }
        }
        MaterializeKind::PemBlockShape => {
            let len = spec.len.unwrap_or(256);
            let seed = Seed::from_text(&spec.seed);
            let mut bytes = vec![0u8; len];
            seed.fill_bytes(&mut bytes);
            let payload = BASE64_STD.encode(bytes);
            let block_label = normalize_pem_label(&label);
            let mut out = String::new();
            let _ = writeln!(&mut out, "-----BEGIN {block_label}-----");
            for chunk in payload.as_bytes().chunks(64) {
                let _ = writeln!(
                    &mut out,
                    "{}",
                    std::str::from_utf8(chunk).map_err(|err| {
                        MaterializeError::InvalidManifest(format!(
                            "generated base64 payload was not utf-8: {err}"
                        ))
                    })?
                );
            }
            let _ = writeln!(&mut out, "-----END {block_label}-----");
            Ok(out.into_bytes())
        }
        MaterializeKind::SshPublicKeyShape => {
            let seed = Seed::from_text(&spec.seed);
            let mut bytes = [0u8; 32];
            seed.fill_bytes(&mut bytes);
            Ok(format!(
                "ssh-ed25519 {} {}\n",
                BASE64_STD.encode(bytes),
                normalize_ssh_comment(&label)
            )
            .into_bytes())
        }
        MaterializeKind::TokenApiKey => Ok(fx
            .token(&label, TokenSpec::api_key())
            .value()
            .as_bytes()
            .to_vec()),
    }
}

fn verify_fixture_bytes(path: &Path, expected: &[u8]) -> Result<(), MaterializeError> {
    let actual = fs::read(path)?;
    if actual != expected {
        return Err(MaterializeError::InvalidManifest(format!(
            "materialize check failed: {} content mismatch",
            path.display()
        )));
    }
    Ok(())
}

fn fallback_label(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("fixture")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn normalize_pem_label(label: &str) -> String {
    let normalized: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if normalized.is_empty() {
        "SECRET".to_string()
    } else {
        normalized
    }
}

fn normalize_ssh_comment(label: &str) -> String {
    let normalized: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if normalized.is_empty() {
        "fixture".to_string()
    } else {
        normalized
    }
}

fn fixture_const_name(spec: &MaterializeFixtureSpec) -> String {
    let base = spec.id.clone().unwrap_or_else(|| fallback_label(&spec.out));
    let mut out = String::with_capacity(base.len());
    for ch in base.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    out
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

    #[test]
    fn materialize_manifest_accepts_singular_fixture_and_dot_kinds() {
        let manifest = parse_materialize_manifest_str(
            r#"
version = 1

[[fixture]]
id = "entropy"
kind = "entropy.bytes"
seed = "seed-a"
len = 16
out = "entropy.bin"
"#,
        )
        .expect("manifest should parse");

        assert_eq!(manifest.fixtures.len(), 1);
        assert_eq!(manifest.fixtures[0].id.as_deref(), Some("entropy"));
        assert_eq!(manifest.fixtures[0].kind, MaterializeKind::EntropyBytes);
        assert_eq!(manifest.fixtures[0].out, PathBuf::from("entropy.bin"));
    }

    #[test]
    fn ssh_public_key_shape_stays_shape_only() {
        let bytes = materialized_fixture_bytes(&MaterializeFixtureSpec {
            id: Some("ssh-shape".to_string()),
            out: PathBuf::from("id_ed25519.pub"),
            kind: MaterializeKind::SshPublicKeyShape,
            seed: "seed-a".to_string(),
            label: Some("deploy@example".to_string()),
            len: None,
        })
        .expect("ssh shape should render");
        let rendered = String::from_utf8(bytes).expect("shape should be utf-8");
        assert!(rendered.starts_with("ssh-ed25519 "));
        assert!(rendered.ends_with(" deploy-example\n"));
    }

    #[cfg(not(feature = "rsa-materialize"))]
    #[test]
    fn rsa_materialize_requires_feature() {
        let error = materialized_fixture_bytes(&MaterializeFixtureSpec {
            id: Some("rsa".to_string()),
            out: PathBuf::from("private-key.pk8"),
            kind: MaterializeKind::RsaPkcs8Der,
            seed: "seed-a".to_string(),
            label: Some("issuer".to_string()),
            len: None,
        })
        .expect_err("rsa materialize should require feature");
        assert!(
            error
                .to_string()
                .contains("rsa.pkcs8_der requires uselesskey-cli feature `rsa-materialize`")
        );
    }
}
