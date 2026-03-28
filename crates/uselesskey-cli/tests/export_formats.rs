use std::collections::BTreeMap;
use std::fs;

use serde_json::Value as JsonValue;
use tempfile::tempdir;
use uselesskey_cli::{
    ExportBundleSpec, ExportEntry, ExportReceipt, ExportTarget, KeyRef, RECEIPT_SCHEMA, export_bundle,
};

fn spec(target: ExportTarget, dir: &std::path::Path) -> ExportBundleSpec {
    ExportBundleSpec {
        bundle_name: "deterministic-fixtures".to_string(),
        target,
        output_dir: dir.to_path_buf(),
        entries: vec![
            ExportEntry {
                id: "rsa_private".to_string(),
                value: "pem-rsa-private".to_string(),
                file_name: "rsa-private.pem".to_string(),
                env_var_name: Some("RSA_PRIVATE_PEM".to_string()),
                secret_name: None,
            },
            ExportEntry {
                id: "rsa_public".to_string(),
                value: "pem-rsa-public".to_string(),
                file_name: "rsa-public.pem".to_string(),
                env_var_name: Some("RSA_PUBLIC_PEM".to_string()),
                secret_name: None,
            },
        ],
    }
}

#[test]
fn golden_outputs_are_written_for_each_target() {
    let targets = vec![
        ExportTarget::FlatFileBundle,
        ExportTarget::EnvDir,
        ExportTarget::DotEnvFragment,
        ExportTarget::KubernetesSecretYaml,
        ExportTarget::SopsReadyYamlSkeleton,
        ExportTarget::VaultKvJsonPayload,
        ExportTarget::GenericManifest,
    ];

    for target in targets {
        let dir = tempdir().expect("tempdir");
        let res = export_bundle(&spec(target.clone(), dir.path())).expect("export succeeded");

        assert!(res.manifest_path.exists(), "manifest missing for {target:?}");
        let manifest_json = fs::read_to_string(&res.manifest_path).expect("read manifest");
        let receipt: ExportReceipt = serde_json::from_str(&manifest_json).expect("parse receipt");
        assert_eq!(receipt.schema, RECEIPT_SCHEMA);
        assert_eq!(receipt.bundle_name, "deterministic-fixtures");
        assert_eq!(receipt.target, target);
    }
}

#[test]
fn yaml_and_json_outputs_are_schema_parseable() {
    let dir = tempdir().expect("tempdir");
    let k8s = export_bundle(&spec(ExportTarget::KubernetesSecretYaml, dir.path())).expect("k8s");
    let k8s_file = k8s.written_files.first().expect("k8s file");
    let doc: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(k8s_file).expect("read")).expect("parse yaml");
    assert_eq!(doc["kind"], "Secret");

    let vault = export_bundle(&spec(ExportTarget::VaultKvJsonPayload, dir.path())).expect("vault");
    let vault_file = vault.written_files.first().expect("vault file");
    let payload: JsonValue =
        serde_json::from_str(&fs::read_to_string(vault_file).expect("read")).expect("parse json");
    assert!(payload["data"]["data"].is_object());
}

#[test]
fn manifest_references_align_with_written_files() {
    let dir = tempdir().expect("tempdir");
    let result = export_bundle(&spec(ExportTarget::FlatFileBundle, dir.path())).expect("export");
    assert_eq!(result.references.len(), 2);

    let paths: BTreeMap<_, _> = result
        .references
        .iter()
        .filter_map(|(id, r)| match r {
            KeyRef::File { path } => Some((id.clone(), path.clone())),
            _ => None,
        })
        .collect();

    for path in paths.values() {
        assert!(path.exists(), "reference path should exist: {}", path.display());
    }

    assert_eq!(result.written_files.len(), paths.len());
}

#[test]
fn receipt_paths_are_portable_forward_slashes() {
    let dir = tempdir().expect("tempdir");
    let result = export_bundle(&spec(ExportTarget::FlatFileBundle, dir.path())).expect("export");
    let manifest = fs::read_to_string(result.manifest_path).expect("manifest");
    let parsed: JsonValue = serde_json::from_str(&manifest).expect("json");

    let arr = parsed["written_files"].as_array().expect("array");
    for value in arr {
        let s = value.as_str().expect("string");
        assert!(!s.contains('\\'));
    }
}
