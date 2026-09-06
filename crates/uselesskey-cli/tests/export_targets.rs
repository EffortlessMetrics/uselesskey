use uselesskey_test_support::{TestResult, require_ok, require_some};

trait TestContext<T> {
    fn test_context(self, message: impl std::fmt::Display) -> TestResult<T>;
}

impl<T, E: std::fmt::Display> TestContext<T> for std::result::Result<T, E> {
    fn test_context(self, message: impl std::fmt::Display) -> TestResult<T> {
        require_ok(self, message)
    }
}

impl<T> TestContext<T> for Option<T> {
    fn test_context(self, message: impl std::fmt::Display) -> TestResult<T> {
        require_some(self, message)
    }
}

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
fn golden_manifest_json() -> TestResult<()> {
    let manifest = BundleManifest::new()
        .with_artifact(sample_artifacts()[0].manifest.clone())
        .with_artifact(sample_artifacts()[1].manifest.clone());

    let got = manifest
        .to_pretty_json()
        .test_context("manifest should serialize to json")?;
    let expected = fs::read_to_string("tests/golden/manifest.json")
        .test_context("golden manifest should exist")?;

    assert_eq!(got.trim_end(), expected.trim_end());
    Ok(())
}

#[test]
fn golden_renderer_outputs_match_expected_files() -> TestResult<()> {
    let artifacts = sample_artifacts();

    let vault_json =
        render_vault_kv_json(&artifacts).test_context("vault payload should render")?;
    let vault_expected = fs::read_to_string("tests/golden/vault-kv.json")
        .test_context("vault golden should exist")?;
    assert_eq!(vault_json.trim_end(), vault_expected.trim_end());

    let k8s = render_k8s_secret_yaml("demo", Some("default"), &artifacts);
    let k8s_expected = fs::read_to_string("tests/golden/k8s-secret.yaml")
        .test_context("k8s golden should exist")?;
    assert_eq!(k8s.trim_end(), k8s_expected.trim_end());

    let sops = render_sops_ready_yaml(&artifacts);
    let sops_expected = fs::read_to_string("tests/golden/sops-ready.yaml")
        .test_context("sops golden should exist")?;
    assert_eq!(sops.trim_end(), sops_expected.trim_end());

    let dotenv = render_dotenv_fragment(&artifacts);
    let dotenv_expected =
        fs::read_to_string("tests/golden/dotenv.env").test_context("dotenv golden should exist")?;
    assert_eq!(dotenv.trim_end(), dotenv_expected.trim_end());

    let parsed: Value =
        serde_json::from_str(&vault_json).test_context("vault payload should parse")?;
    assert_eq!(parsed["metadata"]["source"], "uselesskey-cli");
    assert_eq!(parsed["metadata"]["mode"], "one_shot_export");
    Ok(())
}

#[test]
fn local_file_target_round_trip() -> TestResult<()> {
    let artifacts = sample_artifacts();
    let temp = tempdir().test_context("tempdir")?;

    let flat_root = temp.path().join("flat");
    let env_root = temp.path().join("envdir");

    let flat_written = uselesskey_cli::export_flat_files(&flat_root, &artifacts)
        .test_context("flat file export")?;
    assert_eq!(flat_written.len(), 2);
    assert_eq!(
        fs::read_to_string(flat_root.join("issuer_pem")).test_context("issuer flat file")?,
        artifacts[0].value
    );

    let env_written =
        uselesskey_cli::export_envdir(&env_root, &artifacts).test_context("envdir export")?;
    assert_eq!(env_written.len(), 2);
    assert_eq!(
        fs::read_to_string(env_root.join("SERVICE_TOKEN")).test_context("token env file")?,
        artifacts[1].value
    );

    let dotenv = render_dotenv_fragment(&artifacts);
    assert!(dotenv.contains("ISSUER_PEM=\""));
    assert!(dotenv.contains("SERVICE_TOKEN=\"fixture-demo-token-value\""));
    Ok(())
}

#[test]
fn manifest_write_json_round_trip() -> TestResult<()> {
    let temp = tempdir().test_context("tempdir")?;
    let manifest = BundleManifest::new()
        .with_artifact(sample_artifacts()[0].manifest.clone())
        .with_artifact(sample_artifacts()[1].manifest.clone());

    let path = temp.path().join("manifest.json");
    manifest
        .write_json(&path)
        .test_context("manifest should write")?;

    let written = fs::read_to_string(&path).test_context("written manifest should exist")?;
    assert_eq!(
        written.trim_end(),
        manifest
            .to_pretty_json()
            .test_context("manifest should serialize")?
            .trim_end()
    );
    Ok(())
}
