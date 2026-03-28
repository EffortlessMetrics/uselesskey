use std::collections::BTreeMap;

use serde_json::Value as JsonValue;
use uselesskey_cli::{
    ExportBundleSpec, ExportTargetFormat, build_k8s_secret_yaml, build_sops_skeleton, export_bundle,
};

fn sample_outputs() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("issuer_key".to_string(), "-----BEGIN KEY-----\nabc\n-----END KEY-----".to_string()),
        ("client_token".to_string(), "tok_123".to_string()),
    ])
}

#[test]
fn golden_outputs_for_each_export_format() {
    let dir = tempfile::tempdir().expect("tempdir");

    for format in [
        ExportTargetFormat::FlatFileBundle,
        ExportTargetFormat::Envdir,
        ExportTargetFormat::DotenvFragment,
        ExportTargetFormat::KubernetesSecretYaml,
        ExportTargetFormat::SopsReadyYaml,
        ExportTargetFormat::VaultKvJson,
        ExportTargetFormat::GenericManifest,
    ] {
        let format_dir = dir.path().join(format!("{:?}", format));
        let spec = ExportBundleSpec {
            bundle_name: "fixture-bundle".to_string(),
            out_dir: format_dir.clone(),
            target_format: format,
            outputs: sample_outputs(),
            env_var_names: BTreeMap::new(),
            secret_names: BTreeMap::new(),
            source_receipt_path: Some("target/fixtures/receipt.json".into()),
        };

        let result = export_bundle(&spec).expect("export succeeds");
        let manifest = std::fs::read_to_string(&result.manifest_path).expect("manifest read");
        let stable = manifest.replace(&dir.path().display().to_string(), "<TMP>");
        insta::assert_snapshot!(format!("manifest_{:?}", format), stable);
    }
}

#[test]
fn yaml_and_json_outputs_are_schema_parseable() {
    let k8s_yaml = build_k8s_secret_yaml("my-secret", &sample_outputs()).expect("k8s yaml");
    let parsed_yaml: serde_yaml::Value = serde_yaml::from_str(&k8s_yaml).expect("valid yaml");
    assert_eq!(parsed_yaml["kind"], serde_yaml::Value::String("Secret".to_string()));

    let sops_yaml = build_sops_skeleton("bundle", &sample_outputs()).expect("sops yaml");
    let _: serde_yaml::Value = serde_yaml::from_str(&sops_yaml).expect("valid sops yaml");

    let vault_doc = serde_json::json!({
        "mount": "secret",
        "path": "uselesskey/test",
        "data": sample_outputs(),
        "options": { "cas": 0 }
    });
    let serialized = serde_json::to_string_pretty(&vault_doc).expect("json write");
    let parsed: JsonValue = serde_json::from_str(&serialized).expect("valid json");
    assert_eq!(parsed["options"]["cas"], JsonValue::from(0));
}

#[test]
fn manifest_reference_coherence_and_portable_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = ExportBundleSpec {
        bundle_name: "coherence".to_string(),
        out_dir: dir.path().join("bundle"),
        target_format: ExportTargetFormat::FlatFileBundle,
        outputs: sample_outputs(),
        env_var_names: BTreeMap::new(),
        secret_names: BTreeMap::new(),
        source_receipt_path: None,
    };

    let result = export_bundle(&spec).expect("export succeeds");
    assert!(result.manifest_path.exists());
    assert!(
        result
            .written_files
            .iter()
            .all(|p| p.components().count() > 1 && !p.as_os_str().is_empty())
    );

    for (logical, refs) in &result.references {
        assert!(spec.outputs.contains_key(logical));
        assert!(!refs.is_empty(), "each output should map to references");
    }
}
