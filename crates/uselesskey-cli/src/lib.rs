#![forbid(unsafe_code)]

//! Export/bundle helpers for `uselesskey` fixture handoff.
//!
//! This crate intentionally focuses on one-shot local export targets and metadata
//! manifests. It does not implement rotation, retrieval, leasing, or long-running
//! key-store behavior.

pub mod srp;

pub use srp::export::{
    export_envdir, export_flat_files, render_dotenv_fragment, render_k8s_secret_yaml,
    render_sops_ready_yaml, render_vault_kv_json,
};
pub use srp::manifest::{
    ArtifactType, BundleError, BundleManifest, ExportArtifact, Fingerprint, KeyRef,
    ManifestArtifact,
};
pub use srp::materialize::{
    MATERIALIZE_MANIFEST_VERSION, MaterializeError, MaterializeFixtureSpec, MaterializeKind,
    MaterializeManifest, MaterializeSummary, emit_include_bytes_module, load_materialize_manifest,
    materialize_manifest_file, materialize_manifest_to_dir, parse_materialize_manifest_str,
};
