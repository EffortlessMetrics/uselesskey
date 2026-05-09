use std::fs;

use assert_cmd::Command;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    assert!(bundle_dir.join("receipts/materialization.json").exists());
    assert!(bundle_dir.join("receipts/audit-surface.json").exists());
    assert!(
        value["files"]
            .as_array()
            .expect("array")
            .iter()
            .any(|file| file.as_str() == Some("receipts/materialization.json"))
    );
    assert!(
        value["files"]
            .as_array()
            .expect("array")
            .iter()
            .any(|file| file.as_str() == Some("receipts/audit-surface.json"))
    );
    let artifacts = value["artifacts"].as_array().expect("artifacts array");
    assert_eq!(
        artifacts.len(),
        value["files"].as_array().expect("array").len() - 2
    );
    let receipts = value["receipts"].as_array().expect("receipts array");
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().any(|receipt| {
        receipt["path"].as_str() == Some("receipts/materialization.json")
            && receipt["kind"].as_str() == Some("materialization")
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt["path"].as_str() == Some("receipts/audit-surface.json")
            && receipt["kind"].as_str() == Some("audit-surface")
    }));
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

    let materialization: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/materialization.json"))
            .expect("materialization receipt"),
    )
    .expect("materialization receipt json");
    assert_eq!(materialization["receipt"], "materialization");
    assert_eq!(materialization["profile"], "scanner-safe");
    assert_eq!(
        materialization["artifact_count"].as_u64(),
        Some(artifacts.len() as u64)
    );
    assert!(
        materialization["lanes"]
            .as_array()
            .expect("lanes")
            .iter()
            .any(|lane| lane.as_str() == Some("runtime"))
    );

    let audit: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/audit-surface.json")).expect("audit receipt"),
    )
    .expect("audit receipt json");
    assert_eq!(audit["receipt"], "audit-surface");
    assert_eq!(audit["scanner_safe"], true);
    assert_eq!(audit["runtime_material_count"], 0);
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
fn bundle_profile_oidc_writes_contract_pack() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("oidc");

    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args([
        "bundle",
        "--profile",
        "oidc",
        "--seed",
        "oidc-seed",
        "--label",
        "issuer",
        "--out",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    cmd.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
        .expect("manifest json");
    assert_eq!(manifest["profile"], "oidc");
    assert_eq!(manifest["format"], "jwk");
    assert_eq!(manifest["files"][0], "jwks/valid.json");
    assert_eq!(manifest["files"][1], "jwks/negative-duplicate-kid.json");
    assert_eq!(manifest["files"][2], "jwks/negative-missing-kid.json");
    assert_eq!(manifest["files"][3], "tokens/valid-rs256.json");
    assert_eq!(manifest["files"][4], "tokens/negative-alg-none.json");
    assert_eq!(manifest["files"][5], "tokens/negative-bad-audience.json");
    assert_eq!(manifest["files"][6], "receipts/materialization.json");
    assert_eq!(manifest["files"][7], "receipts/audit-surface.json");

    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert_eq!(artifacts.len(), 6);
    assert!(
        artifacts
            .iter()
            .all(|artifact| artifact["profile"] == "oidc" && artifact["scanner_safe"] == true)
    );
    assert!(
        artifacts
            .iter()
            .any(|artifact| artifact["description"]
                == "OIDC negative JWKS with duplicate kid values")
    );
    assert!(
        artifacts
            .iter()
            .any(|artifact| artifact["description"] == "OIDC negative token with alg none")
    );

    let valid_jwks: Value =
        serde_json::from_slice(&fs::read(bundle_dir.join("jwks/valid.json")).expect("valid jwks"))
            .expect("valid jwks json");
    assert_eq!(valid_jwks["keys"][0]["kty"], "RSA");
    assert_eq!(valid_jwks["keys"][0]["alg"], "RS256");
    assert!(valid_jwks["keys"][0]["kid"].is_string());

    let duplicate: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("jwks/negative-duplicate-kid.json")).expect("duplicate kid jwks"),
    )
    .expect("duplicate kid jwks json");
    let duplicate_keys = duplicate["keys"].as_array().expect("duplicate keys");
    assert_eq!(duplicate_keys.len(), 2);
    assert_eq!(duplicate_keys[0]["kid"], duplicate_keys[1]["kid"]);
    assert_ne!(duplicate_keys[0], duplicate_keys[1]);

    let missing: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("jwks/negative-missing-kid.json")).expect("missing kid jwks"),
    )
    .expect("missing kid jwks json");
    assert!(missing["keys"][0].get("kid").is_none());

    let valid_token: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("tokens/valid-rs256.json")).expect("valid token"),
    )
    .expect("valid token json");
    assert_eq!(valid_token["alg"], "RS256");
    let valid_header = decode_jwt_segment(valid_token["value"].as_str().expect("token"), 0);
    assert_eq!(valid_header["alg"], "RS256");

    let alg_none: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("tokens/negative-alg-none.json")).expect("alg none token"),
    )
    .expect("alg none token json");
    assert_eq!(alg_none["negative"], "alg_none");
    let alg_none_header = decode_jwt_segment(alg_none["value"].as_str().expect("token"), 0);
    assert_eq!(alg_none_header["alg"], "none");

    let bad_audience: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("tokens/negative-bad-audience.json"))
            .expect("bad audience token"),
    )
    .expect("bad audience token json");
    assert_eq!(bad_audience["negative"], "bad_audience");
    let bad_audience_payload =
        decode_jwt_segment(bad_audience["value"].as_str().expect("token"), 1);
    assert_eq!(bad_audience_payload["aud"], "wrong-audience");

    let audit: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/audit-surface.json")).expect("audit receipt"),
    )
    .expect("audit receipt json");
    assert_eq!(audit["profile"], "oidc");
    assert_eq!(audit["scanner_safe"], true);
    assert_eq!(audit["artifact_count"], 6);
    assert_eq!(audit["runtime_material_count"], 0);

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
fn verify_bundle_rejects_receipt_drift() {
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

    fs::write(
        bundle_dir.join("receipts/materialization.json"),
        "{\"receipt\":\"materialization\",\"mutated\":true}\n",
    )
    .expect("mutate receipt");

    let mut verify = Command::cargo_bin("uselesskey").expect("bin exists");
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("receipt mismatch"));
}

#[test]
fn verify_bundle_rejects_receipt_metadata_drift() {
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
    manifest["receipts"][0]["description"] = Value::String("mutated receipt".to_string());
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
        .stderr(predicate::str::contains("receipt metadata mismatch"));
}

#[test]
fn verify_bundle_rejects_missing_receipt_metadata_on_current_manifest() {
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
    manifest
        .as_object_mut()
        .expect("manifest object")
        .remove("receipts");
    let files = manifest["files"].as_array_mut().expect("files array");
    files.retain(|file| !file.as_str().expect("file string").starts_with("receipts/"));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let mut verify = Command::cargo_bin("uselesskey").expect("bin exists");
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8"),
    ]);
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("receipt metadata missing"));
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
    manifest
        .as_object_mut()
        .expect("manifest object")
        .remove("receipts");
    let files = manifest["files"].as_array_mut().expect("files array");
    files.retain(|file| !file.as_str().expect("file string").starts_with("receipts/"));
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

fn decode_jwt_segment(token: &str, index: usize) -> Value {
    let segment = token
        .split('.')
        .nth(index)
        .expect("jwt segment should exist");
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("segment should be base64url");
    serde_json::from_slice(&bytes).expect("segment should be json")
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
