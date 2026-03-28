use std::fs;

use serde_json::Value;
use tempfile::tempdir;
use uselesskey_cli::{
    ArtifactType, BundleManifest, ExportArtifact, Fingerprint, ManifestArtifact,
    render_dotenv_fragment, render_k8s_secret_yaml, render_sops_ready_yaml, render_vault_kv_json,
};

fn sample_artifacts() -> Vec<ExportArtifact> {
    vec![
        ExportArtifact {
            key: "issuer_pem".to_string(),
            value: "fixture-private-key-line-1\nfixture-private-key-line-2\n".to_string(),
            manifest: ManifestArtifact {
                artifact_type: ArtifactType::RsaPkcs8Pem,
                source_seed: Some("seed-1".to_string()),
                source_label: "issuer".to_string(),
                output_paths: vec!["out/issuer.pem".to_string()],
                fingerprints: vec![Fingerprint {
                    algorithm: "sha256".to_string(),
                    value: "77fbb9".to_string(),
                }],
                env_var_names: vec!["ISSUER_PEM".to_string()],
                external_key_ref: None,
            },
        },
        ExportArtifact {
            key: "service_token".to_string(),
            value: "fixture-demo-token-value".to_string(),
            manifest: ManifestArtifact {
                artifact_type: ArtifactType::Token,
                source_seed: Some("seed-1".to_string()),
                source_label: "svc-token".to_string(),
                output_paths: vec!["out/token.txt".to_string()],
                fingerprints: vec![Fingerprint {
                    algorithm: "sha256".to_string(),
                    value: "8cae31".to_string(),
                }],
                env_var_names: vec!["SERVICE_TOKEN".to_string()],
                external_key_ref: None,
            },
        },
    ]
}

#[test]
fn golden_manifest_json() {
    let manifest = BundleManifest::new()
        .with_artifact(sample_artifacts()[0].manifest.clone())
        .with_artifact(sample_artifacts()[1].manifest.clone());

    let got = manifest
        .to_pretty_json()
        .expect("manifest should serialize to json");
    let expected =
        fs::read_to_string("tests/golden/manifest.json").expect("golden manifest should exist");

    assert_eq!(got.trim_end(), expected.trim_end());
}

#[test]
fn golden_renderer_outputs_match_expected_files() {
    let artifacts = sample_artifacts();

    let vault_json = render_vault_kv_json(&artifacts).expect("vault payload should render");
    let vault_expected =
        fs::read_to_string("tests/golden/vault-kv.json").expect("vault golden should exist");
    assert_eq!(vault_json.trim_end(), vault_expected.trim_end());

    let k8s = render_k8s_secret_yaml("demo", Some("default"), &artifacts);
    let k8s_expected =
        fs::read_to_string("tests/golden/k8s-secret.yaml").expect("k8s golden should exist");
    assert_eq!(k8s.trim_end(), k8s_expected.trim_end());

    let sops = render_sops_ready_yaml(&artifacts);
    let sops_expected =
        fs::read_to_string("tests/golden/sops-ready.yaml").expect("sops golden should exist");
    assert_eq!(sops.trim_end(), sops_expected.trim_end());

    let dotenv = render_dotenv_fragment(&artifacts);
    let dotenv_expected =
        fs::read_to_string("tests/golden/dotenv.env").expect("dotenv golden should exist");
    assert_eq!(dotenv.trim_end(), dotenv_expected.trim_end());

    let parsed: Value = serde_json::from_str(&vault_json).expect("vault payload should parse");
    assert_eq!(parsed["metadata"]["source"], "uselesskey-cli");
    assert_eq!(parsed["metadata"]["mode"], "one_shot_export");
}

#[test]
fn local_file_target_round_trip() {
    let artifacts = sample_artifacts();
    let temp = tempdir().expect("tempdir");

    let flat_root = temp.path().join("flat");
    let env_root = temp.path().join("envdir");

    let flat_written =
        uselesskey_cli::export_flat_files(&flat_root, &artifacts).expect("flat file export");
    assert_eq!(flat_written.len(), 2);
    assert_eq!(
        fs::read_to_string(flat_root.join("issuer_pem")).expect("issuer flat file"),
        artifacts[0].value
    );

    let env_written = uselesskey_cli::export_envdir(&env_root, &artifacts).expect("envdir export");
    assert_eq!(env_written.len(), 2);
    assert_eq!(
        fs::read_to_string(env_root.join("SERVICE_TOKEN")).expect("token env file"),
        artifacts[1].value
    );

    let dotenv = render_dotenv_fragment(&artifacts);
    assert!(dotenv.contains("ISSUER_PEM=\""));
    assert!(dotenv.contains("SERVICE_TOKEN=\"fixture-demo-token-value\""));
}

#[test]
fn manifest_write_json_round_trip() {
    let temp = tempdir().expect("tempdir");
    let manifest = BundleManifest::new()
        .with_artifact(sample_artifacts()[0].manifest.clone())
        .with_artifact(sample_artifacts()[1].manifest.clone());

    let path = temp.path().join("manifest.json");
    manifest.write_json(&path).expect("manifest should write");

    let written = fs::read_to_string(&path).expect("written manifest should exist");
    assert_eq!(
        written.trim_end(),
        manifest
            .to_pretty_json()
            .expect("manifest should serialize")
            .trim_end()
    );
}
