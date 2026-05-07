use std::fs;

use assert_cmd::Command;
use insta::{assert_snapshot, assert_yaml_snapshot};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn generate_rsa_pem_is_deterministic() {
    let output1 = run([
        "generate", "rsa", "--seed", "det-seed", "--label", "issuer", "--format", "pem",
    ]);
    let output2 = run([
        "generate", "rsa", "--seed", "det-seed", "--label", "issuer", "--format", "pem",
    ]);
    assert_eq!(output1, output2);
    let shape = serde_json::json!({
        "bytes_len": output1.len(),
        "first_line": output1.lines().next().expect("header"),
        "last_line": output1.lines().last().expect("footer"),
        "line_count": output1.lines().count(),
    });
    assert_yaml_snapshot!("generate_rsa_pem_shape", shape);
}

#[test]
fn generate_jwk_outputs_json() {
    let out = run([
        "generate", "jwk", "--seed", "det-seed", "--label", "issuer", "--format", "jwk",
    ]);
    let value: Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(value["kty"], "RSA");
    assert_snapshot!("generate_jwk", out);
}

#[test]
fn bad_format_for_kind_exits_nonzero() {
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args([
        "generate", "hmac", "--seed", "det-seed", "--label", "issuer", "--format", "pem",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unsupported format"));
}

#[test]
fn bundle_writes_manifest_schema() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args([
        "bundle",
        "--seed",
        "det-seed",
        "--label",
        "bundle-label",
        "--format",
        "jwk",
        "--out",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    cmd.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    assert!(manifest_path.exists());
    let value: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
        .expect("manifest json");
    assert_eq!(value["version"], 1);
    assert_eq!(value["profile"], "scanner-safe");
    assert_eq!(value["seed"], "det-seed");
    assert_eq!(value["label"], "bundle-label");
    assert!(value["files"].as_array().expect("array").len() >= 8);
    let artifacts = value["artifacts"].as_array().expect("artifacts array");
    assert_eq!(
        artifacts.len(),
        value["files"].as_array().expect("array").len()
    );
    assert!(
        artifacts
            .iter()
            .all(|artifact| artifact["scanner_safe"] == true)
    );
    assert!(artifacts.iter().all(|artifact| {
        artifact["lanes"]
            .as_array()
            .expect("lanes")
            .iter()
            .any(|lane| lane.as_str() == Some("runtime"))
    }));
    assert!(artifacts.iter().all(|artifact| {
        artifact["lanes"]
            .as_array()
            .expect("lanes")
            .iter()
            .any(|lane| lane.as_str() == Some("materialized"))
    }));
}

#[test]
fn bundle_profile_scanner_safe_is_the_default_path() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args(["bundle", "--out", bundle_dir.to_str().expect("utf-8")]);
    cmd.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let value: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
        .expect("manifest json");
    assert_eq!(value["profile"], "scanner-safe");
    assert_eq!(value["format"], "jwk");
    assert_eq!(value["seed"], "uselesskey-bundle-seed");
    assert_eq!(value["label"], "bundle");

    let hmac = fs::read_to_string(bundle_dir.join("hmac.jwk.json")).expect("hmac jwk");
    assert!(hmac.contains("not_base64url!*"));

    let artifacts = value["artifacts"].as_array().expect("artifacts");
    let hmac_record = artifacts
        .iter()
        .find(|artifact| artifact["kind"].as_str() == Some("hmac"))
        .expect("hmac artifact record");
    assert_eq!(
        hmac_record["description"],
        "scanner-safe symmetric JWK shape with invalid material"
    );
    let token_record = artifacts
        .iter()
        .find(|artifact| artifact["kind"].as_str() == Some("token"))
        .expect("token artifact record");
    assert_eq!(
        token_record["description"],
        "scanner-safe near-miss token shape for parser tests"
    );

    let token: Value =
        serde_json::from_slice(&fs::read(bundle_dir.join("token.json")).expect("token json"))
            .expect("token manifest");
    let token_value = token["value"].as_str().expect("token value");
    assert!(token_value.starts_with("uk_tset_"));
    assert!(!token_value.starts_with("uk_test_"));
}

#[test]
fn bundle_profile_runtime_preserves_requested_material_format() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args([
        "bundle",
        "--profile",
        "runtime",
        "--format",
        "pem",
        "--seed",
        "det-seed",
        "--label",
        "issuer",
        "--out",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    cmd.assert().success();

    assert!(bundle_dir.join("rsa.pem").exists());
    let manifest_path = bundle_dir.join("manifest.json");
    let value: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
        .expect("manifest json");
    assert_eq!(value["profile"], "runtime");
    assert_eq!(value["format"], "pem");
    assert!(
        value["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(|artifact| artifact["kind"].as_str() == Some("rsa")
                && artifact["scanner_safe"] == false)
    );
}

#[test]
fn verify_bundle_accepts_generated_bundle_and_detects_mismatch() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").expect("bin exists");
    bundle.args([
        "bundle",
        "--seed",
        "det-seed",
        "--label",
        "bundle-label",
        "--format",
        "jwk",
        "--out",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    bundle.assert().success();

    let mut verify = Command::cargo_bin("uselesskey").expect("bin exists");
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));

    fs::write(bundle_dir.join("token.json"), "corrupt").expect("mutate token fixture");

    let mut verify_bad = Command::cargo_bin("uselesskey").expect("bin exists");
    verify_bad.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    verify_bad
        .assert()
        .failure()
        .stderr(predicate::str::contains("content mismatch"));
}

#[test]
fn verify_bundle_rejects_manifest_metadata_drift() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").expect("bin exists");
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("manifest json");
    manifest["artifacts"][0]["scanner_safe"] = Value::Bool(false);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("mutate manifest");

    let mut verify = Command::cargo_bin("uselesskey").expect("bin exists");
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("artifact metadata mismatch"));
}

#[test]
fn verify_bundle_accepts_legacy_manifest_without_profile_metadata() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").expect("bin exists");
    bundle.args([
        "bundle",
        "--profile",
        "runtime",
        "--format",
        "jwk",
        "--seed",
        "legacy-seed",
        "--label",
        "legacy",
        "--out",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("manifest json");
    manifest
        .as_object_mut()
        .expect("manifest object")
        .remove("profile");
    manifest
        .as_object_mut()
        .expect("manifest object")
        .remove("artifacts");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write legacy manifest");

    let mut verify = Command::cargo_bin("uselesskey").expect("bin exists");
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));
}

#[test]
fn export_k8s_and_vault_payloads_from_scanner_safe_bundle() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("bundle");
    let k8s_path = dir.path().join("secret.yaml");
    let vault_path = dir.path().join("kv-v2.json");

    let mut bundle = Command::cargo_bin("uselesskey").expect("bin exists");
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    bundle.assert().success();

    let mut k8s = Command::cargo_bin("uselesskey").expect("bin exists");
    k8s.args([
        "export",
        "k8s",
        "--bundle-dir",
        bundle_dir.to_str().expect("utf-8"),
        "--name",
        "uselesskey-fixtures",
        "--namespace",
        "tests",
        "--out",
        k8s_path.to_str().expect("utf-8"),
    ]);
    k8s.assert().success();

    let rendered_k8s = fs::read_to_string(&k8s_path).expect("k8s payload");
    assert!(rendered_k8s.contains("kind: Secret"));
    assert!(rendered_k8s.contains("  name: uselesskey-fixtures"));
    assert!(rendered_k8s.contains("  namespace: tests"));
    assert!(rendered_k8s.contains("  token.json: "));

    let mut vault = Command::cargo_bin("uselesskey").expect("bin exists");
    vault.args([
        "export",
        "vault-kv-json",
        "--bundle-dir",
        bundle_dir.to_str().expect("utf-8"),
        "--out",
        vault_path.to_str().expect("utf-8"),
    ]);
    vault.assert().success();

    let vault_json: Value =
        serde_json::from_slice(&fs::read(&vault_path).expect("vault payload")).expect("vault json");
    assert_eq!(vault_json["metadata"]["source"], "uselesskey-cli");
    assert_eq!(vault_json["metadata"]["mode"], "one_shot_export");
    assert!(
        vault_json["data"]["token.json"]
            .as_str()
            .expect("token payload")
            .contains("uk_tset_")
    );
}

#[test]
fn inspect_reads_stdin_writes_json() {
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args(["inspect", "--format", "pem"])
        .write_stdin("-----BEGIN PRIVATE KEY-----\nabc\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"private_key\""));
}

#[test]
fn inspect_detects_jwks_json() {
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args(["inspect", "--format", "jwk"])
        .write_stdin("{\"keys\":[{\"kty\":\"RSA\"}]}")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"jwks\""));
}

#[test]
fn inspect_detects_jwk_json() {
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args(["inspect", "--format", "jwk"])
        .write_stdin("{\"kty\":\"RSA\",\"kid\":\"fixture\"}")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"jwk\""));
}

#[test]
fn inspect_leaves_non_key_json_unknown() {
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args(["inspect", "--format", "jwk"])
        .write_stdin("{\"hello\":\"world\"}")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"unknown\""));
}

#[test]
fn materialize_writes_deterministic_fixtures() {
    let dir = tempdir().expect("tempdir");
    let out_dir = dir.path().join("materialized");
    let manifest_path = dir.path().join("materialize.toml");
    let manifest = r#"
version = 1

[[fixture]]
id = "entropy"
out = "seed.bin"
kind = "entropy.bytes"
seed = "materialize-seed"
len = 16

[[fixture]]
id = "token"
out = "session.jwt"
kind = "token.jwt_shape"
seed = "materialize-seed"
label = "svc.jwt"
"#;
    fs::write(&manifest_path, manifest).expect("manifest should be written");

    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args([
        "materialize",
        "--manifest",
        manifest_path.to_str().expect("utf-8"),
        "--out-dir",
        out_dir.to_str().expect("utf-8"),
    ])
    .assert()
    .success();

    let entropy = fs::read(out_dir.join("seed.bin")).expect("materialized entropy");
    let jwt = fs::read_to_string(out_dir.join("session.jwt")).expect("materialized jwt");
    assert_eq!(entropy.len(), 16);
    assert_eq!(jwt.split('.').count(), 3);
}

#[test]
fn materialize_check_fails_on_mismatch() {
    let dir = tempdir().expect("tempdir");
    let out_dir = dir.path().join("materialized");
    let manifest_path = dir.path().join("materialize.toml");
    let manifest = r#"
version = 1

[[fixture]]
id = "entropy"
out = "seed.bin"
seed = "materialize-seed-check"
kind = "entropy.bytes"
len = 8
"#;
    fs::write(&manifest_path, manifest).expect("manifest should be written");

    let mut write = Command::cargo_bin("uselesskey").expect("bin exists");
    write.args([
        "materialize",
        "--manifest",
        manifest_path.to_str().expect("utf-8"),
        "--out-dir",
        out_dir.to_str().expect("utf-8"),
    ]);
    write.assert().success();

    let actual = out_dir.join("seed.bin");
    fs::write(&actual, b"corrupt").expect("mutate fixture");

    let mut check = Command::cargo_bin("uselesskey").expect("bin exists");
    check.args([
        "verify",
        "--manifest",
        manifest_path.to_str().expect("utf-8"),
        "--out-dir",
        out_dir.to_str().expect("utf-8"),
    ]);
    check
        .assert()
        .failure()
        .stderr(predicate::str::contains("content mismatch"));
}

#[test]
fn materialize_can_emit_include_bytes_module() {
    let dir = tempdir().expect("tempdir");
    let out_dir = dir.path().join("materialized");
    let manifest_path = dir.path().join("materialize.toml");
    let module_path = dir.path().join("fixtures.rs");
    let manifest = r#"
version = 1

[[fixture]]
id = "entropy"
kind = "entropy.bytes"
seed = "materialize-emit-rs"
len = 4
out = "seed.bin"
"#;
    fs::write(&manifest_path, manifest).expect("manifest should be written");

    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args([
        "materialize",
        "--manifest",
        manifest_path.to_str().expect("utf-8"),
        "--out-dir",
        out_dir.to_str().expect("utf-8"),
        "--emit-rs",
        module_path.to_str().expect("utf-8"),
    ]);
    cmd.assert().success();

    let emitted = fs::read_to_string(&module_path).expect("emitted module");
    assert!(emitted.contains("pub const ENTROPY: &[u8] = include_bytes!"));
}

fn run<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    let assert = cmd.args(args).assert().success();
    String::from_utf8(assert.get_output().stdout.clone()).expect("utf8")
}
