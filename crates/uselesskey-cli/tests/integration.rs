use schemars::schema_for;
use std::collections::BTreeMap;
use tempfile::tempdir;
use uselesskey_cli::{
    ArtifactType, BundleManifest, Fingerprint, KeyRef, ManifestArtifact, OutputPath, SourceMetadata,
    render_dotenv_fragment, render_k8s_secret_yaml, render_manifest_json, render_sops_ready_yaml,
    render_vault_kv_payload, write_envdir,
};

fn sample_entries() -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    entries.insert("API_KEY".to_owned(), "uk_test_12345".to_owned());
    entries.insert("PRIVATE_KEY_PEM".to_owned(), "-----BEGIN PRIVATE KEY-----".to_owned());
    entries
}

fn sample_manifest() -> BundleManifest {
    BundleManifest {
        schema_version: 1,
        artifacts: vec![ManifestArtifact {
            artifact_id: "token:issuer".to_owned(),
            artifact_type: ArtifactType::Token,
            source: SourceMetadata {
                domain: "token".to_owned(),
                label: "issuer".to_owned(),
                seed_mode: "deterministic".to_owned(),
            },
            output_paths: vec![OutputPath {
                target: "envdir".to_owned(),
                path: "./fixtures/env/API_KEY".to_owned(),
            }],
            fingerprints: vec![Fingerprint {
                algorithm: "sha256".to_owned(),
                value: "abc123".to_owned(),
            }],
            env_vars: vec!["API_KEY".to_owned()],
            external_key_refs: vec![
                KeyRef::Vault {
                    path: "kv/dev/uselesskey/api_key".to_owned(),
                },
                KeyRef::K8sSecret {
                    name: "issuer-keys".to_owned(),
                    key: "api-key".to_owned(),
                },
            ],
        }],
    }
}

#[test]
fn golden_manifest_json() {
    let manifest = sample_manifest();
    let rendered = render_manifest_json(&manifest).expect("manifest should serialize");
    let expected = include_str!("golden/manifest.json");
    assert_eq!(rendered, expected.trim_end());
}

#[test]
fn golden_export_formats() {
    let entries = sample_entries();

    let dotenv = render_dotenv_fragment(&entries);
    assert_eq!(dotenv, include_str!("golden/dotenv.env").trim_end());

    let k8s = render_k8s_secret_yaml("issuer", Some("dev"), &entries)
        .expect("k8s yaml should serialize");
    assert_eq!(k8s, include_str!("golden/k8s-secret.yaml"));

    let sops = render_sops_ready_yaml(&entries).expect("sops yaml should serialize");
    assert_eq!(sops, include_str!("golden/sops-ready.yaml"));

    let vault = render_vault_kv_payload(&entries).expect("vault payload should serialize");
    assert_eq!(vault, include_str!("golden/vault-kv.json").trim_end());
}

#[test]
fn bundle_manifest_schema_validation() {
    let schema = schema_for!(BundleManifest);
    let schema_value = serde_json::to_value(schema).expect("schema should serialize");
    let validator = jsonschema::validator_for(&schema_value).expect("schema should compile");

    let manifest = sample_manifest();
    let instance = serde_json::to_value(manifest).expect("manifest should serialize");
    assert!(validator.is_valid(&instance));
}

#[test]
fn envdir_round_trip() {
    let dir = tempdir().expect("tempdir should exist");
    let entries = sample_entries();

    let outputs = write_envdir(dir.path(), &entries).expect("envdir write should succeed");
    assert_eq!(outputs.len(), entries.len());

    for (name, expected_value) in entries {
        let file = dir.path().join(name);
        let actual = std::fs::read_to_string(file).expect("file should be readable");
        assert_eq!(actual, expected_value);
    }
}
