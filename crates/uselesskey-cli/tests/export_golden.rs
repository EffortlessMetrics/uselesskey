use std::collections::BTreeMap;

use uselesskey_cli::{BundleEntry, ExportBundleSpec, TargetFormat, exporters};

fn sample_entries() -> Vec<BundleEntry> {
    vec![
        BundleEntry {
            name: "issuer_key".to_string(),
            value: "pem-value".to_string(),
        },
        BundleEntry {
            name: "access.token".to_string(),
            value: "token with spaces".to_string(),
        },
    ]
}

#[test]
fn golden_k8s_yaml_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = ExportBundleSpec {
        bundle_name: "demo-bundle".to_string(),
        outputs: vec![dir.path().to_path_buf()],
        target_format: TargetFormat::KubernetesSecretYaml,
        env_names: BTreeMap::new(),
        secret_names: BTreeMap::new(),
    };

    let result = exporters::export_bundle(&spec, &sample_entries(), None).expect("export");
    let yaml_path = dir.path().join("secret.yaml");
    let yaml = std::fs::read_to_string(yaml_path).expect("yaml");
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("valid yaml");

    assert_eq!(parsed["kind"], "Secret");
    assert_eq!(parsed["metadata"]["name"], "demo-bundle");
    assert_eq!(result.references.len(), 2);
}

#[test]
fn golden_vault_json_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = ExportBundleSpec {
        bundle_name: "payments".to_string(),
        outputs: vec![dir.path().to_path_buf()],
        target_format: TargetFormat::VaultKvJson,
        env_names: BTreeMap::new(),
        secret_names: BTreeMap::new(),
    };

    exporters::export_bundle(&spec, &sample_entries(), None).expect("export");
    let payload = std::fs::read_to_string(dir.path().join("vault-kv.json")).expect("json");
    let parsed: serde_json::Value = serde_json::from_str(&payload).expect("valid json");

    assert_eq!(parsed["path"], "secret/data/payments");
    assert!(parsed["data"]["data"]["issuer_key"].is_string());
}

#[test]
fn path_portability_and_manifest_coherence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = ExportBundleSpec {
        bundle_name: "portable".to_string(),
        outputs: vec![dir.path().join("nested/out")],
        target_format: TargetFormat::EnvDir,
        env_names: BTreeMap::new(),
        secret_names: BTreeMap::new(),
    };

    let result = exporters::export_bundle(&spec, &sample_entries(), None).expect("export");
    assert!(result.manifest_path.exists());

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&result.manifest_path).expect("manifest read"),
    )
    .expect("manifest parse");

    assert_eq!(manifest["bundle"], "portable");
    assert_eq!(manifest["references"].as_object().map(|m| m.len()), Some(2));
    assert_eq!(manifest["written_files"].as_array().map(|a| a.len()), Some(2));
}

#[test]
fn dotenv_fragment_is_generated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = ExportBundleSpec {
        bundle_name: "dot".to_string(),
        outputs: vec![dir.path().to_path_buf()],
        target_format: TargetFormat::DotEnvFragment,
        env_names: BTreeMap::new(),
        secret_names: BTreeMap::new(),
    };

    exporters::export_bundle(&spec, &sample_entries(), None).expect("export");
    let env_text = std::fs::read_to_string(dir.path().join("bundle.env")).expect("env");
    assert!(env_text.contains("ISSUER_KEY=pem-value"));
    assert!(env_text.contains("ACCESS_TOKEN='token with spaces'"));
}
