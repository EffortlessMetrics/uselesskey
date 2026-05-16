use std::{fmt, fs};

use uselesskey_test_support::{TestResult, require_ok, require_some};

use assert_cmd::Command;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use insta::{assert_snapshot, assert_yaml_snapshot};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

trait TestContext<T> {
    fn test_context(self, msg: impl fmt::Display) -> TestResult<T>;
}

impl<T, E: fmt::Display> TestContext<T> for Result<T, E> {
    fn test_context(self, msg: impl fmt::Display) -> TestResult<T> {
        require_ok(self, msg)
    }
}

impl<T> TestContext<T> for Option<T> {
    fn test_context(self, msg: impl fmt::Display) -> TestResult<T> {
        require_some(self, msg)
    }
}

#[test]
fn generate_rsa_pem_is_deterministic() -> TestResult<()> {
    let output1 = run([
        "generate", "rsa", "--seed", "det-seed", "--label", "issuer", "--format", "pem",
    ])?;
    let output2 = run([
        "generate", "rsa", "--seed", "det-seed", "--label", "issuer", "--format", "pem",
    ])?;
    assert_eq!(output1, output2);
    let shape = serde_json::json!({
        "bytes_len": output1.len(),
        "first_line": output1.lines().next().test_context("header")?,
        "last_line": output1.lines().last().test_context("footer")?,
        "line_count": output1.lines().count(),
    });
    assert_yaml_snapshot!("generate_rsa_pem_shape", shape);
    Ok(())
}

#[test]
fn generate_jwk_outputs_json() -> TestResult<()> {
    let out = run([
        "generate", "jwk", "--seed", "det-seed", "--label", "issuer", "--format", "jwk",
    ])?;
    let value: Value = serde_json::from_str(&out).test_context("valid json")?;
    assert_eq!(value["kty"], "RSA");
    assert_snapshot!("generate_jwk", out);
    Ok(())
}

#[test]
fn profiles_command_lists_copyable_contract_pack_paths() -> TestResult<()> {
    let out = run(["profiles"])?;

    assert!(out.contains("Available uselesskey profiles"));
    assert!(out.contains("uselesskey profile <name> --explain"));
    assert!(out.contains("claim-proof --claim webhook-contract-pack"));
    Ok(())
}

#[test]
fn profile_command_summary_has_copyable_webhook_paths() -> TestResult<()> {
    let out = run(["profile", "webhook"])?;

    assert!(out.contains("Profile: webhook"));
    assert!(
        out.contains(
            "Generate: uselesskey bundle --profile webhook --out target/uselesskey-webhook"
        )
    );
    assert!(out.contains("Verify: uselesskey verify-bundle --path target/uselesskey-webhook"));
    assert!(out.contains("Proof: cargo xtask claim-proof --claim webhook-contract-pack"));
    Ok(())
}

#[test]
fn bundle_explain_has_copyable_webhook_paths_without_writing_bundle() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");
    let out = run([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
        "--explain",
    ])?;

    assert!(out.contains("Profile: webhook"));
    assert!(
        out.contains(
            "Generate: uselesskey bundle --profile webhook --out target/uselesskey-webhook"
        )
    );
    assert!(out.contains("Does not prove"));
    assert!(out.contains("provider compatibility"));
    assert!(!bundle_dir.exists());
    Ok(())
}

#[test]
fn bad_format_for_kind_exits_nonzero() -> TestResult<()> {
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "generate", "hmac", "--seed", "det-seed", "--label", "issuer", "--format", "pem",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unsupported format"));
    Ok(())
}

#[test]
fn bundle_writes_manifest_schema() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "bundle",
        "--seed",
        "det-seed",
        "--label",
        "bundle-label",
        "--format",
        "jwk",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    cmd.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    assert!(manifest_path.exists());
    let value: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    assert_eq!(value["version"], 1);
    assert_eq!(value["profile"], "scanner-safe");
    assert_eq!(value["seed"], "det-seed");
    assert_eq!(value["label"], "bundle-label");
    assert!(value["files"].as_array().test_context("array")?.len() >= 8);
    assert!(bundle_dir.join("receipts/materialization.json").exists());
    assert!(bundle_dir.join("receipts/audit-surface.json").exists());
    assert!(
        value["files"]
            .as_array()
            .test_context("array")?
            .iter()
            .any(|file| file.as_str() == Some("receipts/materialization.json"))
    );
    assert!(
        value["files"]
            .as_array()
            .test_context("array")?
            .iter()
            .any(|file| file.as_str() == Some("receipts/audit-surface.json"))
    );
    let artifacts = value["artifacts"]
        .as_array()
        .test_context("artifacts array")?;
    assert_eq!(
        artifacts.len(),
        value["files"].as_array().test_context("array")?.len() - 2
    );
    let receipts = value["receipts"]
        .as_array()
        .test_context("receipts array")?;
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
    for artifact in artifacts {
        let lanes = artifact["lanes"].as_array().test_context("lanes")?;
        assert!(lanes.iter().any(|lane| lane.as_str() == Some("runtime")));
        assert!(
            lanes
                .iter()
                .any(|lane| lane.as_str() == Some("materialized"))
        );
    }
    Ok(())
}

#[test]
fn bundle_profile_scanner_safe_is_the_default_path() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "bundle",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    cmd.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let value: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    assert_eq!(value["profile"], "scanner-safe");
    assert_eq!(value["format"], "jwk");
    assert_eq!(value["seed"], "uselesskey-bundle-seed");
    assert_eq!(value["label"], "bundle");

    let hmac = fs::read_to_string(bundle_dir.join("hmac.jwk.json")).test_context("hmac jwk")?;
    assert!(hmac.contains("not_base64url!*"));

    let artifacts = value["artifacts"].as_array().test_context("artifacts")?;
    let hmac_record = artifacts
        .iter()
        .find(|artifact| artifact["kind"].as_str() == Some("hmac"))
        .test_context("hmac artifact record")?;
    assert_eq!(
        hmac_record["description"],
        "scanner-safe symmetric JWK shape with invalid material"
    );
    let token_record = artifacts
        .iter()
        .find(|artifact| artifact["kind"].as_str() == Some("token"))
        .test_context("token artifact record")?;
    assert_eq!(
        token_record["description"],
        "scanner-safe near-miss token shape for parser tests"
    );

    let token: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("token.json")).test_context("token json")?,
    )
    .test_context("token manifest")?;
    let token_value = token["value"].as_str().test_context("token value")?;
    assert!(token_value.starts_with("uk_tset_"));
    assert!(!token_value.starts_with("uk_test_"));

    let materialization: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/materialization.json"))
            .test_context("materialization receipt")?,
    )
    .test_context("materialization receipt json")?;
    assert_eq!(materialization["receipt"], "materialization");
    assert_eq!(materialization["profile"], "scanner-safe");
    assert_eq!(
        materialization["artifact_count"].as_u64(),
        Some(artifacts.len() as u64)
    );
    assert!(
        materialization["lanes"]
            .as_array()
            .test_context("lanes")?
            .iter()
            .any(|lane| lane.as_str() == Some("runtime"))
    );

    let audit: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/audit-surface.json")).test_context("audit receipt")?,
    )
    .test_context("audit receipt json")?;
    assert_eq!(audit["receipt"], "audit-surface");
    assert_eq!(audit["scanner_safe"], true);
    assert_eq!(audit["runtime_material_count"], 0);
    Ok(())
}

#[test]
fn bundle_profile_runtime_preserves_requested_material_format() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
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
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    cmd.assert().success();

    assert!(bundle_dir.join("rsa.pem").exists());
    let manifest_path = bundle_dir.join("manifest.json");
    let value: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    assert_eq!(value["profile"], "runtime");
    assert_eq!(value["format"], "pem");
    assert!(
        value["artifacts"]
            .as_array()
            .test_context("artifacts")?
            .iter()
            .any(|artifact| artifact["kind"].as_str() == Some("rsa")
                && artifact["scanner_safe"] == false)
    );
    Ok(())
}

#[test]
fn bundle_profile_runtime_jwk_marks_public_key_artifacts_scanner_safe() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "bundle",
        "--profile",
        "runtime",
        "--format",
        "jwk",
        "--seed",
        "det-seed",
        "--label",
        "issuer",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    cmd.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    let artifacts = manifest["artifacts"]
        .as_array()
        .test_context("artifacts array")?;

    let public_jwk_kinds = ["rsa", "ecdsa", "ed25519"];
    for kind in public_jwk_kinds {
        let artifact = artifacts
            .iter()
            .find(|a| a["kind"].as_str() == Some(kind) && a["format"].as_str() == Some("jwk"))
            .test_context(format!("{kind} jwk artifact"))?;
        assert_eq!(
            artifact["scanner_safe"], true,
            "{kind} JWK only contains public components and must be scanner-safe",
        );
    }

    let hmac = artifacts
        .iter()
        .find(|a| a["kind"].as_str() == Some("hmac"))
        .test_context("hmac artifact")?;
    assert_eq!(
        hmac["scanner_safe"], false,
        "hmac JWK includes the symmetric `k` secret",
    );

    let audit: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/audit-surface.json"))
            .test_context("read audit surface")?,
    )
    .test_context("audit json")?;
    assert_eq!(
        audit["runtime_material_count"], 2,
        "only hmac + token carry secret material in runtime+jwk bundles",
    );
    Ok(())
}

#[test]
fn bundle_profile_oidc_writes_contract_pack() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("oidc");

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "bundle",
        "--profile",
        "oidc",
        "--seed",
        "oidc-seed",
        "--label",
        "issuer",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    cmd.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
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

    let artifacts = manifest["artifacts"].as_array().test_context("artifacts")?;
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

    let valid_jwks: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("jwks/valid.json")).test_context("valid jwks")?,
    )
    .test_context("valid jwks json")?;
    assert_eq!(valid_jwks["keys"][0]["kty"], "RSA");
    assert_eq!(valid_jwks["keys"][0]["alg"], "RS256");
    assert!(valid_jwks["keys"][0]["kid"].is_string());

    let duplicate: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("jwks/negative-duplicate-kid.json"))
            .test_context("duplicate kid jwks")?,
    )
    .test_context("duplicate kid jwks json")?;
    let duplicate_keys = duplicate["keys"]
        .as_array()
        .test_context("duplicate keys")?;
    assert_eq!(duplicate_keys.len(), 2);
    assert_eq!(duplicate_keys[0]["kid"], duplicate_keys[1]["kid"]);
    assert_ne!(duplicate_keys[0], duplicate_keys[1]);

    let missing: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("jwks/negative-missing-kid.json"))
            .test_context("missing kid jwks")?,
    )
    .test_context("missing kid jwks json")?;
    assert!(missing["keys"][0].get("kid").is_none());

    let valid_token: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("tokens/valid-rs256.json")).test_context("valid token")?,
    )
    .test_context("valid token json")?;
    assert_eq!(valid_token["alg"], "RS256");
    let valid_header = decode_jwt_segment(valid_token["value"].as_str().test_context("token")?, 0)?;
    assert_eq!(valid_header["alg"], "RS256");

    let alg_none: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("tokens/negative-alg-none.json"))
            .test_context("alg none token")?,
    )
    .test_context("alg none token json")?;
    assert_eq!(alg_none["negative"], "alg_none");
    let alg_none_header = decode_jwt_segment(alg_none["value"].as_str().test_context("token")?, 0)?;
    assert_eq!(alg_none_header["alg"], "none");

    let bad_audience: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("tokens/negative-bad-audience.json"))
            .test_context("bad audience token")?,
    )
    .test_context("bad audience token json")?;
    assert_eq!(bad_audience["negative"], "bad_audience");
    let bad_audience_payload =
        decode_jwt_segment(bad_audience["value"].as_str().test_context("token")?, 1)?;
    assert_eq!(bad_audience_payload["aud"], "wrong-audience");

    let audit: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/audit-surface.json")).test_context("audit receipt")?,
    )
    .test_context("audit receipt json")?;
    assert_eq!(audit["profile"], "oidc");
    assert_eq!(audit["scanner_safe"], true);
    assert_eq!(audit["artifact_count"], 6);
    assert_eq!(audit["runtime_material_count"], 0);

    let mut verify = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));
    Ok(())
}

#[test]
fn inspect_bundle_summarizes_verified_scanner_safe_receipts() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut inspect = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    inspect.args([
        "inspect-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    inspect
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle profile: scanner-safe"))
        .stdout(predicate::str::contains("Artifacts: 8"))
        .stdout(predicate::str::contains("Verified files: 10"))
        .stdout(predicate::str::contains("Scanner-safe: yes"))
        .stdout(predicate::str::contains("Private key material: no"))
        .stdout(predicate::str::contains("Symmetric secret material: no"))
        .stdout(predicate::str::contains("Runtime material artifacts: 0"))
        .stdout(predicate::str::contains("Verification: ok"))
        .stdout(predicate::str::contains(
            "Receipts: materialization, audit-surface",
        ));
    Ok(())
}

#[test]
fn inspect_bundle_reports_runtime_material_without_printing_payloads() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("runtime");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "runtime",
        "--format",
        "pem",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut inspect = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    inspect.args([
        "inspect-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    let output = inspect.assert().success().get_output().stdout.clone();
    let summary = String::from_utf8(output).test_context("utf-8")?;

    assert!(summary.contains("Bundle profile: runtime"));
    assert!(summary.contains("Scanner-safe: no"));
    assert!(summary.contains("Private key material: yes"));
    assert!(summary.contains("Symmetric secret material: yes"));
    assert!(summary.contains("Runtime material artifacts: 5"));
    assert!(summary.contains("Verification: ok"));
    assert!(!summary.contains("BEGIN PRIVATE KEY"));
    assert!(!summary.contains("uk_test_"));
    Ok(())
}

#[test]
fn inspect_bundle_fails_when_bundle_drift_is_detected() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    fs::write(bundle_dir.join("token.json"), "corrupt").test_context("mutate token fixture")?;

    let mut inspect = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    inspect.args([
        "inspect-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    inspect
        .assert()
        .failure()
        .stderr(predicate::str::contains("content mismatch"));
    Ok(())
}

#[test]
fn verify_bundle_accepts_generated_bundle_and_detects_mismatch() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--seed",
        "det-seed",
        "--label",
        "bundle-label",
        "--format",
        "jwk",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut verify = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));

    fs::write(bundle_dir.join("token.json"), "corrupt").test_context("mutate token fixture")?;

    let mut verify_bad = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify_bad.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify_bad
        .assert()
        .failure()
        .stderr(predicate::str::contains("content mismatch"));
    Ok(())
}

#[test]
fn verify_bundle_rejects_manifest_metadata_drift() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    manifest["artifacts"][0]["scanner_safe"] = Value::Bool(false);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).test_context("serialize manifest")?,
    )
    .test_context("mutate manifest")?;

    let mut verify = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("artifact metadata mismatch"));
    Ok(())
}

#[test]
fn verify_bundle_rejects_receipt_drift() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    fs::write(
        bundle_dir.join("receipts/materialization.json"),
        "{\"receipt\":\"materialization\",\"mutated\":true}\n",
    )
    .test_context("mutate receipt")?;

    let mut verify = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("receipt mismatch"));
    Ok(())
}

#[test]
fn verify_bundle_rejects_receipt_metadata_drift() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    manifest["receipts"][0]["description"] = Value::String("mutated receipt".to_string());
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).test_context("serialize manifest")?,
    )
    .test_context("mutate manifest")?;

    let mut verify = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("receipt metadata mismatch"));
    Ok(())
}

#[test]
fn verify_bundle_rejects_missing_receipt_metadata_on_current_manifest() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    manifest
        .as_object_mut()
        .test_context("manifest object")?
        .remove("receipts");
    let files = manifest["files"]
        .as_array_mut()
        .test_context("files array")?;
    let mut retained_files = Vec::new();
    for file in files.iter() {
        let path = file.as_str().test_context("file string")?;
        if !path.starts_with("receipts/") {
            retained_files.push(file.clone());
        }
    }
    *files = retained_files;
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).test_context("serialize manifest")?,
    )
    .test_context("write manifest")?;

    let mut verify = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("receipt metadata missing"));
    Ok(())
}

#[test]
fn verify_bundle_accepts_legacy_manifest_without_profile_metadata() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
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
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("read manifest")?)
            .test_context("manifest json")?;
    manifest
        .as_object_mut()
        .test_context("manifest object")?
        .remove("profile");
    manifest
        .as_object_mut()
        .test_context("manifest object")?
        .remove("artifacts");
    manifest
        .as_object_mut()
        .test_context("manifest object")?
        .remove("receipts");
    let files = manifest["files"]
        .as_array_mut()
        .test_context("files array")?;
    let mut retained_files = Vec::new();
    for file in files.iter() {
        let path = file.as_str().test_context("file string")?;
        if !path.starts_with("receipts/") {
            retained_files.push(file.clone());
        }
    }
    *files = retained_files;
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).test_context("serialize manifest")?,
    )
    .test_context("write legacy manifest")?;

    let mut verify = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));
    Ok(())
}

#[test]
fn export_k8s_and_vault_payloads_from_scanner_safe_bundle() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");
    let k8s_path = dir.path().join("secret.yaml");
    let vault_path = dir.path().join("kv-v2.json");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut k8s = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    k8s.args([
        "export",
        "k8s",
        "--bundle-dir",
        bundle_dir.to_str().test_context("utf-8")?,
        "--name",
        "uselesskey-fixtures",
        "--namespace",
        "tests",
        "--out",
        k8s_path.to_str().test_context("utf-8")?,
    ]);
    k8s.assert().success();

    let rendered_k8s = fs::read_to_string(&k8s_path).test_context("k8s payload")?;
    assert!(rendered_k8s.contains("kind: Secret"));
    assert!(rendered_k8s.contains("  name: uselesskey-fixtures"));
    assert!(rendered_k8s.contains("  namespace: tests"));
    assert!(rendered_k8s.contains("  token.json: "));

    let mut vault = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    vault.args([
        "export",
        "vault-kv-json",
        "--bundle-dir",
        bundle_dir.to_str().test_context("utf-8")?,
        "--out",
        vault_path.to_str().test_context("utf-8")?,
    ]);
    vault.assert().success();

    let vault_json: Value =
        serde_json::from_slice(&fs::read(&vault_path).test_context("vault payload")?)
            .test_context("vault json")?;
    assert_eq!(vault_json["metadata"]["source"], "uselesskey-cli");
    assert_eq!(vault_json["metadata"]["mode"], "one_shot_export");
    assert!(
        vault_json["data"]["token.json"]
            .as_str()
            .test_context("token payload")?
            .contains("uk_tset_")
    );
    Ok(())
}

fn decode_jwt_segment(token: &str, index: usize) -> TestResult<Value> {
    let segment = token
        .split('.')
        .nth(index)
        .test_context("jwt segment should exist")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .test_context("segment should be base64url")?;
    serde_json::from_slice(&bytes).test_context("segment should be json")
}

#[test]
fn inspect_reads_stdin_writes_json() -> TestResult<()> {
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args(["inspect", "--format", "pem"])
        .write_stdin("-----BEGIN PRIVATE KEY-----\nabc\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"private_key\""));
    Ok(())
}

#[test]
fn inspect_detects_jwks_json() -> TestResult<()> {
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args(["inspect", "--format", "jwk"])
        .write_stdin("{\"keys\":[{\"kty\":\"RSA\"}]}")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"jwks\""));
    Ok(())
}

#[test]
fn inspect_detects_jwk_json() -> TestResult<()> {
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args(["inspect", "--format", "jwk"])
        .write_stdin("{\"kty\":\"RSA\",\"kid\":\"fixture\"}")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"jwk\""));
    Ok(())
}

#[test]
fn inspect_leaves_non_key_json_unknown() -> TestResult<()> {
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args(["inspect", "--format", "jwk"])
        .write_stdin("{\"hello\":\"world\"}")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"unknown\""));
    Ok(())
}

#[test]
fn materialize_writes_deterministic_fixtures() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
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
    fs::write(&manifest_path, manifest).test_context("manifest should be written")?;

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "materialize",
        "--manifest",
        manifest_path.to_str().test_context("utf-8")?,
        "--out-dir",
        out_dir.to_str().test_context("utf-8")?,
    ])
    .assert()
    .success();

    let entropy = fs::read(out_dir.join("seed.bin")).test_context("materialized entropy")?;
    let jwt = fs::read_to_string(out_dir.join("session.jwt")).test_context("materialized jwt")?;
    assert_eq!(entropy.len(), 16);
    assert_eq!(jwt.split('.').count(), 3);
    Ok(())
}

#[test]
fn materialize_check_fails_on_mismatch() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
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
    fs::write(&manifest_path, manifest).test_context("manifest should be written")?;

    let mut write = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    write.args([
        "materialize",
        "--manifest",
        manifest_path.to_str().test_context("utf-8")?,
        "--out-dir",
        out_dir.to_str().test_context("utf-8")?,
    ]);
    write.assert().success();

    let actual = out_dir.join("seed.bin");
    fs::write(&actual, b"corrupt").test_context("mutate fixture")?;

    let mut check = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    check.args([
        "verify",
        "--manifest",
        manifest_path.to_str().test_context("utf-8")?,
        "--out-dir",
        out_dir.to_str().test_context("utf-8")?,
    ]);
    check
        .assert()
        .failure()
        .stderr(predicate::str::contains("content mismatch"));
    Ok(())
}

#[test]
fn materialize_can_emit_include_bytes_module() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
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
    fs::write(&manifest_path, manifest).test_context("manifest should be written")?;

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "materialize",
        "--manifest",
        manifest_path.to_str().test_context("utf-8")?,
        "--out-dir",
        out_dir.to_str().test_context("utf-8")?,
        "--emit-rs",
        module_path.to_str().test_context("utf-8")?,
    ]);
    cmd.assert().success();

    let emitted = fs::read_to_string(&module_path).test_context("emitted module")?;
    assert!(emitted.contains("pub const ENTROPY: &[u8] = include_bytes!"));
    Ok(())
}

fn run<I, S>(args: I) -> TestResult<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    let assert = cmd.args(args).assert().success();
    String::from_utf8(assert.get_output().stdout.clone()).test_context("utf8")
}
