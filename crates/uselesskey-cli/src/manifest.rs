use serde::{Deserialize, Serialize};

/// Artifact category represented in a bundle manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Rsa,
    Ecdsa,
    Ed25519,
    Hmac,
    Token,
    X509,
    Other,
}

/// Source metadata for deterministic fixture generation inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceMetadata {
    pub seed_id: Option<String>,
    pub label: String,
    pub variant: Option<String>,
}

/// File path emitted for a concrete export target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputPath {
    pub target: String,
    pub path: String,
}

/// Fingerprint metadata emitted with bundle artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub algorithm: String,
    pub value: String,
}

/// External key reference information for handoff systems.
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

/// Generic metadata manifest for fixture handoff bundles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub artifact_type: ArtifactType,
    pub source: SourceMetadata,
    #[serde(default)]
    pub output_paths: Vec<OutputPath>,
    #[serde(default)]
    pub fingerprints: Vec<Fingerprint>,
    #[serde(default)]
    pub intended_env_vars: Vec<String>,
    #[serde(default)]
    pub external_key_refs: Vec<KeyRef>,
}
