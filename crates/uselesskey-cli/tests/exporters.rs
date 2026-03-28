use std::fs;

use uselesskey_cli::{
    ArtifactType, BundleManifest, Fingerprint, KeyRef, OutputPath, SecretEntry, SourceMetadata,
    export,
};

fn sample_entries() -> Vec<SecretEntry> {
    vec![
        SecretEntry::new("API_TOKEN", "tok_abc123"),
        SecretEntry::new("PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----"),
    ]
}

fn sample_manifest() -> BundleManifest {
    BundleManifest {
        artifact_type: ArtifactType::Rsa,
        source: SourceMetadata {
            seed_id: Some("seed:integration-tests".to_owned()),
            label: "issuer".to_owned(),
            variant: Some("default".to_owned()),
        },
        output_paths: vec![OutputPath {
            target: "envdir".to_owned(),
            path: "/tmp/bundle/envdir".to_owned(),
        }],
        fingerprints: vec![Fingerprint {
            algorithm: "sha256".to_owned(),
            value: "f00dbabe".to_owned(),
        }],
        intended_env_vars: vec!["API_TOKEN".to_owned(), "PRIVATE_KEY".to_owned()],
        external_key_refs: vec![
            KeyRef::Vault {
                path: "kv/data/service/dev".to_owned(),
            },
            KeyRef::K8sSecret {
                name: "service-secret".to_owned(),
                key: "api-token".to_owned(),
            },
        ],
    }
}

#[test]
fn golden_bundle_manifest_json() {
    let manifest = sample_manifest();
    let rendered = export::render_bundle_manifest(&manifest).expect("render manifest");
    insta::assert_snapshot!("bundle_manifest_json", rendered);
}

#[test]
fn target_outputs_are_valid_json_shapes() {
    let entries = sample_entries();

    let k8s = export::render_kubernetes_secret("uk-secret", &entries).expect("k8s render");
    let sops = export::render_sops_skeleton(&entries).expect("sops render");
    let vault = export::render_vault_kv_json(&entries).expect("vault render");

    let k8s_value: serde_json::Value = serde_json::from_str(&k8s).expect("k8s parse");
    let sops_value: serde_json::Value = serde_json::from_str(&sops).expect("sops parse");
    let vault_value: serde_json::Value = serde_json::from_str(&vault).expect("vault parse");

    assert_eq!(k8s_value["kind"], "Secret");
    assert!(k8s_value["stringData"]["API_TOKEN"].is_string());

    assert!(sops_value["sops"].is_object());
    assert!(sops_value["stringData"]["PRIVATE_KEY"].is_string());

    assert!(vault_value["data"].is_object());
    assert!(vault_value["data"]["API_TOKEN"].is_string());
}

#[test]
fn round_trip_local_file_targets() {
    let entries = sample_entries();
    let dir = tempfile::tempdir().expect("tmpdir");

    let written = export::write_envdir(dir.path(), &entries).expect("write envdir");
    assert_eq!(written.len(), entries.len());

    for entry in &entries {
        let content = fs::read_to_string(dir.path().join(&entry.key)).expect("read envdir file");
        assert_eq!(content, entry.value);
    }

    let dotenv = export::render_dotenv_fragment(&entries);
    let parsed = dotenv
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').expect("dotenv key/value");
            let unwrapped = value
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
                .expect("single-quoted value");
            (
                key.to_owned(),
                unwrapped.replace("\\'", "'").replace("\\\\", "\\"),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    assert_eq!(parsed["API_TOKEN"], "tok_abc123");
    assert!(parsed["PRIVATE_KEY"].contains("BEGIN PRIVATE KEY"));
}
