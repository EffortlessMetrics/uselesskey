use std::collections::BTreeMap;

use uselesskey_cli::{
    BundleManifest, Fingerprint, KeyRef, SourceMetadata, render_kubernetes_secret_yaml,
    render_sops_ready_yaml_skeleton, render_vault_kv_json_payload, write_envdir,
};

#[test]
fn manifest_matches_golden_json() {
    let manifest = BundleManifest {
        artifact_type: "rsa_pkcs8_pem".to_string(),
        source: SourceMetadata {
            seed_fingerprint: "blake3:5f1c1c".to_string(),
            label: "issuer".to_string(),
            domain: "rsa".to_string(),
        },
        output_paths: vec![
            "fixtures/issuer.pem".to_string(),
            "fixtures/issuer.pub.pem".to_string(),
        ],
        fingerprints: vec![Fingerprint {
            algorithm: "sha256".to_string(),
            value: "aabbcc".to_string(),
        }],
        env_vars: vec!["ISSUER_PRIVATE_KEY".to_string()],
        external_key_refs: vec![KeyRef::Vault {
            path: "kv/dev/issuer".to_string(),
        }],
    };

    let actual = manifest.to_pretty_json().expect("manifest json");
    let expected = include_str!("golden/bundle_manifest.json");
    assert_eq!(actual.trim_end(), expected.trim_end());
}

#[test]
fn yaml_and_json_outputs_parse_as_expected_shapes() {
    let mut bytes = BTreeMap::new();
    bytes.insert("PRIVATE_KEY".to_string(), b"pem-data".to_vec());

    let k8s_yaml =
        render_kubernetes_secret_yaml("issuer", Some("default"), &bytes).expect("k8s yaml");
    let k8s_value: serde_yaml::Value = serde_yaml::from_str(&k8s_yaml).expect("yaml parse");
    assert_eq!(k8s_value["kind"], "Secret");
    assert_eq!(k8s_value["data"]["PRIVATE_KEY"], "cGVtLWRhdGE=");

    let mut strings = BTreeMap::new();
    strings.insert("PRIVATE_KEY".to_string(), "pem-data".to_string());

    let sops = render_sops_ready_yaml_skeleton(&strings).expect("sops yaml");
    let sops_value: serde_yaml::Value = serde_yaml::from_str(&sops).expect("yaml parse");
    assert_eq!(sops_value["sops"]["metadata"], "fill with your local sops configuration");

    let vault = render_vault_kv_json_payload(&strings).expect("vault json");
    let vault_value: serde_json::Value = serde_json::from_str(&vault).expect("json parse");
    assert_eq!(vault_value["data"]["PRIVATE_KEY"], "pem-data");
}

#[test]
fn envdir_round_trip_for_local_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut values = BTreeMap::new();
    values.insert("API_TOKEN".to_string(), b"tok_123".to_vec());
    values.insert("PRIVATE_KEY".to_string(), b"pem-data".to_vec());

    let paths = write_envdir(dir.path(), &values).expect("envdir write");
    assert_eq!(paths.len(), 2);

    for (key, expected) in values {
        let actual = std::fs::read(dir.path().join(key)).expect("read file");
        assert_eq!(actual, expected);
    }
}

#[test]
fn manifest_schema_validation() {
    let schema = serde_json::json!({
        "type": "object",
        "required": ["artifact_type", "source", "output_paths", "fingerprints", "env_vars"],
        "properties": {
            "artifact_type": {"type": "string"},
            "source": {
                "type": "object",
                "required": ["seed_fingerprint", "label", "domain"],
                "properties": {
                    "seed_fingerprint": {"type": "string"},
                    "label": {"type": "string"},
                    "domain": {"type": "string"}
                }
            },
            "output_paths": {"type": "array", "items": {"type": "string"}},
            "fingerprints": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["algorithm", "value"],
                    "properties": {
                        "algorithm": {"type": "string"},
                        "value": {"type": "string"}
                    }
                }
            },
            "env_vars": {"type": "array", "items": {"type": "string"}},
            "external_key_refs": {"type": "array"}
        }
    });

    let manifest = BundleManifest {
        artifact_type: "token_api_key".to_string(),
        source: SourceMetadata {
            seed_fingerprint: "blake3:abc".to_string(),
            label: "app".to_string(),
            domain: "token".to_string(),
        },
        output_paths: vec!["/tmp/token.txt".to_string()],
        fingerprints: vec![Fingerprint {
            algorithm: "sha256".to_string(),
            value: "ff00".to_string(),
        }],
        env_vars: vec!["APP_TOKEN".to_string()],
        external_key_refs: vec![KeyRef::Env {
            var: "APP_TOKEN".to_string(),
        }],
    };

    let instance = serde_json::to_value(manifest).expect("serialize manifest");
    let validator =
        jsonschema::validator_for(&schema)
            .expect("compile schema");
    assert!(validator.is_valid(&instance));
}
