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
    assert!(out.contains("Installed users generate, verify, inspect, and audit bundles"));
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
    assert!(out.contains("Verify: uselesskey verify-bundle target/uselesskey-webhook"));
    assert!(out.contains("Inspect: uselesskey inspect-bundle target/uselesskey-webhook"));
    assert!(out.contains(
        "Audit: uselesskey audit-bundle target/uselesskey-webhook --out target/uselesskey-webhook-audit"
    ));
    assert!(out.contains(
        "CI audit: uselesskey audit-bundle target/uselesskey-webhook --ci --expect-profile webhook --policy strict --out target/uselesskey-webhook-audit"
    ));
    assert!(
        out.contains("Proof/check path: cargo xtask claim-proof --claim webhook-contract-pack")
    );
    let verify = out.find("Verify:").test_context("Verify line")?;
    let inspect = out.find("Inspect:").test_context("Inspect line")?;
    let audit = out.find("Audit:").test_context("Audit line")?;
    let ci_audit = out.find("CI audit:").test_context("CI audit line")?;
    assert!(verify < inspect);
    assert!(inspect < audit);
    assert!(audit < ci_audit);
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
    assert!(out.contains("Audit: uselesskey audit-bundle target/uselesskey-webhook"));
    assert!(out.contains(
        "CI audit: uselesskey audit-bundle target/uselesskey-webhook --ci --expect-profile webhook --policy strict --out target/uselesskey-webhook-audit"
    ));
    let verify = out.find("Verify:").test_context("Verify line")?;
    let inspect = out.find("Inspect:").test_context("Inspect line")?;
    let audit = out.find("Audit:").test_context("Audit line")?;
    assert!(verify < inspect);
    assert!(inspect < audit);
    assert!(out.contains("Does not prove"));
    assert!(out.contains("provider compatibility"));
    assert!(!bundle_dir.exists());
    Ok(())
}

#[test]
fn top_level_help_routes_installed_users_to_self_check_and_audit() -> TestResult<()> {
    let out = run(["--help"])?;

    assert!(out.contains("Generate deterministic test fixtures"));
    assert!(out.contains("Start here:"));
    assert!(out.contains("uselesskey doctor"));
    assert!(out.contains("uselesskey profiles"));
    assert!(out.contains(
        "uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit"
    ));
    assert!(out.contains("Generate a deterministic fixture bundle"));
    assert!(out.contains("Check installed CLI readiness"));
    assert!(out.contains("Repo public-claim proof is separate from installed CLI setup."));
    Ok(())
}

#[test]
fn bundle_help_shows_installed_generate_verify_inspect_audit_loop() -> TestResult<()> {
    let out = run(["bundle", "--help"])?;

    assert!(out.contains("Generate a deterministic fixture bundle"));
    assert!(out.contains("uselesskey bundle --profile webhook --out target/uselesskey-webhook"));
    assert!(out.contains("uselesskey verify-bundle target/uselesskey-webhook"));
    assert!(out.contains("uselesskey inspect-bundle target/uselesskey-webhook"));
    assert!(out.contains(
        "uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit"
    ));
    assert!(out.contains("keep generated payloads under target/"));
    assert!(out.contains("Explain the profile"));
    Ok(())
}

#[test]
fn audit_bundle_help_explains_ci_receipts_and_boundaries() -> TestResult<()> {
    let out = run(["audit-bundle", "--help"])?;

    assert!(out.contains("Emit metadata-only bundle audit receipts"));
    assert!(out.contains("--path <BUNDLE_DIR>"));
    assert_help_contains_command(
        &out,
        "uselesskey audit-bundle target/uselesskey-webhook --out",
    );
    assert_help_contains_command(
        &out,
        "uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit",
    );
    assert_help_contains_command(
        &out,
        "uselesskey audit-bundle target/uselesskey-webhook --ci --expect-profile webhook --policy strict --out target/uselesskey-webhook-audit",
    );
    assert!(out.contains("--expect-profile <PROFILE>"));
    assert!(out.contains("--policy <POLICY>"));
    assert!(out.contains("uploadable metadata-only receipts"));
    assert_help_contains_text(&out, "stable audit failure classes");
    assert!(out.contains("not prove production security"));
    assert!(out.contains("provider compatibility"));
    assert!(out.contains("broader repo public"));
    Ok(())
}

fn assert_help_contains_command(out: &str, command: &str) {
    assert_help_contains_text(out, command);
}

fn assert_help_contains_text(out: &str, expected: &str) {
    let normalized_out = out.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized_expected = expected.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized_out.contains(&normalized_expected),
        "missing help text `{expected}` in:\n{out}"
    );
}

#[test]
fn doctor_help_stays_installed_user_scoped() -> TestResult<()> {
    let out = run(["doctor", "--help"])?;

    assert!(out.contains("Check installed CLI readiness and safe default output paths"));
    assert!(out.contains("uselesskey doctor --format json"));
    assert!(out.contains("Checks installed CLI concerns only"));
    assert!(out.contains("target write"));
    assert!(out.contains("known profiles"));
    assert!(!out.contains("cargo xtask"));
    assert!(!out.contains("claim-ledger"));
    assert!(!out.contains("release-evidence"));
    Ok(())
}

#[test]
fn doctor_text_reports_installed_cli_checks_only() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.current_dir(dir.path()).arg("doctor");
    let output = cmd.assert().success().get_output().stdout.clone();
    let report = String::from_utf8(output).test_context("doctor text")?;

    assert!(report.contains("uselesskey doctor"));
    assert!(report.contains("Status: pass"));
    assert!(report.contains("CLI version:"));
    assert!(report.contains("target-write-access: pass"));
    assert!(report.contains("output-path-safety: pass"));
    assert!(report.contains("known-profiles: pass"));
    assert!(report.contains("scanner-safe, tls, oidc, webhook, runtime"));
    assert!(report.contains("Next steps:"));
    assert!(report.contains("uselesskey profiles"));
    assert!(report.contains("uselesskey bundle --profile webhook --out target/uselesskey-webhook"));
    assert!(report.contains(
        "uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit"
    ));
    assert!(report.contains("installed CLI concerns only"));
    assert!(report.contains("repo-local workflows"));
    assert!(!report.contains("cargo xtask"));
    assert!(!report.contains("claim-ledger"));
    assert!(!report.contains("release-evidence"));
    assert!(
        !dir.path()
            .join("target/uselesskey-doctor/.write-probe")
            .exists()
    );
    Ok(())
}

#[test]
fn doctor_json_reports_known_profiles_and_boundaries() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.current_dir(dir.path())
        .args(["doctor", "--format", "json"]);
    let output = cmd.assert().success().get_output().stdout.clone();
    let report: Value = serde_json::from_slice(&output).test_context("doctor json")?;
    let stdout = String::from_utf8(output).test_context("doctor stdout")?;

    assert_eq!(report["version"], 1);
    assert_eq!(report["status"], "pass");
    assert_eq!(report["cli_version"], env!("CARGO_PKG_VERSION"));
    let profiles = report["known_profiles"]
        .as_array()
        .test_context("known profiles")?;
    for profile in ["scanner-safe", "tls", "oidc", "webhook", "runtime"] {
        assert!(
            profiles.iter().any(|value| value.as_str() == Some(profile)),
            "missing profile {profile}"
        );
    }
    let checks = report["checks"].as_array().test_context("checks")?;
    for check_name in [
        "cli-version",
        "current-directory",
        "target-write-access",
        "output-path-safety",
        "json-output",
        "known-profiles",
    ] {
        assert!(
            checks
                .iter()
                .any(|check| check["name"] == check_name && check["status"] == "pass"),
            "missing passing check {check_name}"
        );
    }
    let next_steps = report["next_steps"].as_array().test_context("next steps")?;
    for step in [
        "uselesskey profiles",
        "uselesskey bundle --profile webhook --out target/uselesskey-webhook",
        "uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit",
    ] {
        assert!(
            next_steps.iter().any(|value| value.as_str() == Some(step)),
            "missing next step {step}"
        );
    }
    assert!(stdout.contains("installed CLI concerns only"));
    assert!(!stdout.contains("cargo xtask"));
    assert!(!stdout.contains("claim-ledger"));
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
        bundle_dir
            .join("receipts/bundle-verification.json")
            .exists()
    );
    assert!(bundle_dir.join("receipts/scanner-safety.json").exists());
    assert!(bundle_dir.join("receipts/negative-coverage.json").exists());
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
    assert!(
        value["files"]
            .as_array()
            .test_context("array")?
            .iter()
            .any(|file| file.as_str() == Some("receipts/bundle-verification.json"))
    );
    assert!(
        value["files"]
            .as_array()
            .test_context("array")?
            .iter()
            .any(|file| file.as_str() == Some("receipts/scanner-safety.json"))
    );
    assert!(
        value["files"]
            .as_array()
            .test_context("array")?
            .iter()
            .any(|file| file.as_str() == Some("receipts/negative-coverage.json"))
    );
    let artifacts = value["artifacts"]
        .as_array()
        .test_context("artifacts array")?;
    assert_eq!(
        artifacts.len(),
        value["files"].as_array().test_context("array")?.len() - 5
    );
    let receipts = value["receipts"]
        .as_array()
        .test_context("receipts array")?;
    assert_eq!(receipts.len(), 5);
    assert!(receipts.iter().any(|receipt| {
        receipt["path"].as_str() == Some("receipts/materialization.json")
            && receipt["kind"].as_str() == Some("materialization")
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt["path"].as_str() == Some("receipts/audit-surface.json")
            && receipt["kind"].as_str() == Some("audit-surface")
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt["path"].as_str() == Some("receipts/bundle-verification.json")
            && receipt["kind"].as_str() == Some("bundle-verification")
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt["path"].as_str() == Some("receipts/scanner-safety.json")
            && receipt["kind"].as_str() == Some("scanner-safety")
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt["path"].as_str() == Some("receipts/negative-coverage.json")
            && receipt["kind"].as_str() == Some("negative-coverage")
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
fn bundle_profile_runtime_jwks_marks_public_key_artifacts_scanner_safe() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    cmd.args([
        "bundle",
        "--profile",
        "runtime",
        "--format",
        "jwks",
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

    let public_jwks_kinds = ["rsa", "ecdsa", "ed25519"];
    for kind in public_jwks_kinds {
        let artifact = artifacts
            .iter()
            .find(|a| a["kind"].as_str() == Some(kind) && a["format"].as_str() == Some("jwks"))
            .test_context(format!("{kind} jwks artifact"))?;
        assert_eq!(
            artifact["scanner_safe"], true,
            "{kind} JWKS only contains public components and must be scanner-safe",
        );
    }

    let hmac = artifacts
        .iter()
        .find(|a| a["kind"].as_str() == Some("hmac"))
        .test_context("hmac artifact")?;
    assert_eq!(
        hmac["scanner_safe"], false,
        "hmac JWKS includes the symmetric `k` secret",
    );

    let audit: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/audit-surface.json"))
            .test_context("read audit surface")?,
    )
    .test_context("audit json")?;
    assert_eq!(
        audit["runtime_material_count"], 2,
        "only hmac + token carry secret material in runtime+jwks bundles",
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
    assert_eq!(manifest["files"][8], "receipts/bundle-verification.json");
    assert_eq!(manifest["files"][9], "receipts/scanner-safety.json");
    assert_eq!(manifest["files"][10], "receipts/negative-coverage.json");

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

    let scanner_safety: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/scanner-safety.json"))
            .test_context("scanner-safety receipt")?,
    )
    .test_context("scanner-safety receipt json")?;
    assert_eq!(scanner_safety["receipt"], "scanner-safety");
    assert_eq!(scanner_safety["scanner_safe_count"], 6);
    assert_eq!(scanner_safety["runtime_material_count"], 0);

    let negative_coverage: Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("receipts/negative-coverage.json"))
            .test_context("negative coverage receipt")?,
    )
    .test_context("negative coverage receipt json")?;
    assert_eq!(negative_coverage["receipt"], "negative-coverage");
    assert_eq!(negative_coverage["negative_count"], 4);
    let coverage = negative_coverage["coverage"]
        .as_array()
        .test_context("coverage array")?;
    for class in [
        "jwks_duplicate_kid",
        "jwks_missing_kid",
        "jwt_alg_none",
        "jwt_bad_audience",
    ] {
        assert!(
            coverage
                .iter()
                .any(|entry| entry["failure_class"].as_str() == Some(class)),
            "missing negative coverage class {class}"
        );
    }

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
fn bundle_read_commands_accept_positional_bundle_dir_and_keep_flag_forms() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");
    let bundle_dir = bundle_dir.to_str().test_context("utf-8")?;

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args(["bundle", "--profile", "scanner-safe", "--out", bundle_dir]);
    bundle.assert().success();

    let mut verify_positional = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify_positional.args(["verify-bundle", bundle_dir]);
    verify_positional
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));

    let mut inspect_positional = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    inspect_positional.args(["inspect-bundle", bundle_dir]);
    inspect_positional
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle profile: scanner-safe"));

    let mut audit_positional = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit_positional.args(["audit-bundle", bundle_dir, "--summary"]);
    audit_positional
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle audit: pass"));

    let mut verify_flag = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    verify_flag.args(["verify-bundle", "--path", bundle_dir]);
    verify_flag
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));

    let mut inspect_alias = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    inspect_alias.args(["inspect-bundle", "--bundle-dir", bundle_dir]);
    inspect_alias
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle profile: scanner-safe"));

    Ok(())
}

#[test]
fn bundle_read_commands_reject_duplicate_bundle_dir_inputs() -> TestResult<()> {
    for command in ["verify-bundle", "inspect-bundle", "audit-bundle"] {
        let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
        cmd.args([command, "target/one", "--path", "target/two"]);
        cmd.assert().failure().stderr(predicate::str::contains(
            "the argument '[BUNDLE_DIR]' cannot be used with '--path <BUNDLE_DIR>'",
        ));
    }
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
        .stdout(predicate::str::contains(
            "Summary type: quick human bundle summary",
        ))
        .stdout(predicate::str::contains("Artifacts: 8"))
        .stdout(predicate::str::contains("Verified files: 13"))
        .stdout(predicate::str::contains("Scanner-safe: yes"))
        .stdout(predicate::str::contains("Private key material: no"))
        .stdout(predicate::str::contains("Symmetric secret material: no"))
        .stdout(predicate::str::contains("Runtime material artifacts: 0"))
        .stdout(predicate::str::contains("Verification: ok"))
        .stdout(predicate::str::contains(
            "Receipts: materialization, audit-surface, bundle-verification, scanner-safety, negative-coverage",
        ))
        .stdout(predicate::str::contains(
            "Durable audit receipt: uselesskey audit-bundle <bundle-dir> --out <audit-dir>",
        ))
        .stdout(predicate::str::contains(
            "Proof/check path: cargo xtask claim-proof --claim scanner-safe-fixtures",
        ))
        .stdout(predicate::str::contains("Generated files:"))
        .stdout(predicate::str::contains("rsa.jwk.json"))
        .stdout(predicate::str::contains("Artifact posture:"))
        .stdout(predicate::str::contains("scanner_safe=yes"))
        .stdout(predicate::str::contains(
            "Does not prove: every derived encoded export is safe to commit",
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
    assert!(summary.contains("Summary type: quick human bundle summary"));
    assert!(summary.contains("Scanner-safe: no"));
    assert!(summary.contains("Private key material: yes"));
    assert!(summary.contains("Symmetric secret material: yes"));
    assert!(summary.contains("Runtime material artifacts: 5"));
    assert!(summary.contains("Verification: ok"));
    assert!(
        summary.contains(
            "Durable audit receipt: uselesskey audit-bundle <bundle-dir> --out <audit-dir>"
        )
    );
    assert!(
        summary.contains("Proof/check path: uselesskey verify-bundle target/uselesskey-runtime")
    );
    assert!(summary.contains("Generated files:"));
    assert!(summary.contains("Artifact posture:"));
    assert!(summary.contains("scanner_safe=no"));
    assert!(summary.contains("Does not prove: a public contract-pack claim"));
    assert!(!summary.contains("BEGIN PRIVATE KEY"));
    assert!(!summary.contains("uk_test_"));
    Ok(())
}

#[test]
fn audit_bundle_writes_metadata_only_reviewer_receipts() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    let audit_dir = dir.path().join("webhook-audit");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--out",
        audit_dir.to_str().test_context("utf-8")?,
    ]);
    audit
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"pass\""));

    let audit_json: Value = serde_json::from_slice(
        &fs::read(audit_dir.join("bundle-audit.json")).test_context("audit json")?,
    )
    .test_context("audit json parse")?;
    assert_eq!(audit_json["status"], "pass");
    assert_eq!(audit_json["profile"], "webhook");
    assert_eq!(audit_json["artifact_count"], 7);
    assert_eq!(audit_json["runtime_material_count"], 6);
    assert_eq!(audit_json["scanner_safe_count"], 1);
    assert_eq!(
        audit_json["missing_files"]
            .as_array()
            .test_context("missing")?
            .len(),
        0
    );
    assert_eq!(
        audit_json["unexpected_files"]
            .as_array()
            .test_context("unexpected")?
            .len(),
        0
    );

    let audit_md =
        fs::read_to_string(audit_dir.join("bundle-audit.md")).test_context("audit markdown")?;
    assert!(audit_md.contains("Bundle Audit"));
    assert!(audit_md.contains("durable metadata-only reviewer/CI receipt"));
    assert!(audit_md.contains("Quick summary: uselesskey inspect-bundle <bundle-dir>"));
    assert!(audit_md.contains("raw generated fixture payloads are not copied"));
    assert!(audit_md.contains("requests/negative-wrong-secret.json"));
    assert!(
        audit_md.contains("audit-bundle is not standalone proof for broader repo public claims")
    );
    assert!(audit_md.contains("provider compatibility"));
    assert!(!audit_md.contains("whsec_"));
    assert!(!audit_md.contains("BEGIN PRIVATE KEY"));
    Ok(())
}

#[test]
fn audit_bundle_receipts_do_not_copy_runtime_payloads() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let profiles = ["webhook", "runtime", "tls", "oidc"];
    let mut runtime_payloads_checked = 0usize;

    for profile in profiles {
        let bundle_dir = dir.path().join(format!("{profile}-bundle"));
        let audit_dir = dir.path().join(format!("{profile}-audit"));

        let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
        bundle.args([
            "bundle",
            "--profile",
            profile,
            "--out",
            bundle_dir.to_str().test_context("utf-8")?,
        ]);
        bundle.assert().success();

        let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
        audit.args([
            "audit-bundle",
            "--path",
            bundle_dir.to_str().test_context("utf-8")?,
            "--out",
            audit_dir.to_str().test_context("utf-8")?,
        ]);
        audit.assert().success();

        assert_eq!(
            audit_receipt_files(&audit_dir)?,
            vec![
                "bundle-audit.json".to_string(),
                "bundle-audit.md".to_string()
            ]
        );

        let audit_json =
            fs::read(audit_dir.join("bundle-audit.json")).test_context("audit json")?;
        let audit_md = fs::read(audit_dir.join("bundle-audit.md")).test_context("audit md")?;
        let mut audit_bytes = audit_json.clone();
        audit_bytes.extend_from_slice(&audit_md);
        let audit_text = String::from_utf8_lossy(&audit_bytes);

        let manifest: Value = serde_json::from_slice(
            &fs::read(bundle_dir.join("manifest.json")).test_context("manifest")?,
        )
        .test_context("manifest json")?;
        let artifacts = manifest["artifacts"]
            .as_array()
            .test_context("manifest artifacts")?;
        for artifact in artifacts {
            if artifact["scanner_safe"].as_bool() != Some(false) {
                continue;
            }
            let relative = artifact["path"]
                .as_str()
                .test_context("artifact relative path")?;
            let payload = fs::read(bundle_dir.join(relative))
                .test_context(format!("runtime payload {profile}:{relative}"))?;
            if payload.len() < 32 {
                continue;
            }
            runtime_payloads_checked += 1;
            assert!(
                !contains_bytes(&audit_bytes, &payload),
                "audit receipt copied raw payload bytes for {profile}:{relative}"
            );
            if let Ok(payload_text) = String::from_utf8(payload) {
                let payload_text = payload_text.trim();
                if payload_text.len() >= 32 {
                    assert!(
                        !audit_text.contains(payload_text),
                        "audit receipt copied raw payload text for {profile}:{relative}"
                    );
                    let escaped_payload =
                        serde_json::to_string(payload_text).test_context("escape payload")?;
                    let escaped_payload = escaped_payload
                        .trim_start_matches('"')
                        .trim_end_matches('"');
                    assert!(
                        !audit_text.contains(escaped_payload),
                        "audit receipt copied escaped payload text for {profile}:{relative}"
                    );
                }
            }
        }
    }

    assert!(
        runtime_payloads_checked > 0,
        "test should inspect at least one runtime-material payload"
    );
    Ok(())
}

#[test]
fn audit_bundle_golden_json_preserves_schema_and_boundaries() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--format",
        "json",
    ])?;
    let audit: Value = serde_json::from_str(&out).test_context("audit json")?;
    let audit = normalize_snapshot_paths(audit, dir.path());

    assert_yaml_snapshot!("audit_bundle_webhook_json_golden", audit);
    Ok(())
}

#[test]
fn audit_bundle_golden_markdown_preserves_metadata_only_posture() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    let audit_dir = dir.path().join("webhook-audit");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--out",
        audit_dir.to_str().test_context("utf-8")?,
    ]);
    audit.assert().success();

    let audit_md =
        fs::read_to_string(audit_dir.join("bundle-audit.md")).test_context("audit markdown")?;
    let audit_md = normalize_snapshot_text(&audit_md, dir.path());

    assert_snapshot!("audit_bundle_webhook_markdown_golden", audit_md);
    Ok(())
}

#[test]
fn audit_bundle_json_reports_artifact_runtime_material_flags() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--format",
        "json",
    ])?;
    let audit: Value = serde_json::from_str(&out).test_context("audit json")?;
    let artifacts = audit["artifacts"]
        .as_array()
        .test_context("audit artifacts")?;
    let request = artifacts
        .iter()
        .find(|artifact| artifact["path"] == "requests/valid.json")
        .test_context("valid request artifact")?;
    assert_eq!(request["scanner_safe"], false);
    assert_eq!(request["runtime_material"], true);

    let evidence = artifacts
        .iter()
        .find(|artifact| artifact["path"] == "evidence/webhook-profile.md")
        .test_context("evidence artifact")?;
    assert_eq!(evidence["scanner_safe"], true);
    assert_eq!(evidence["runtime_material"], false);
    Ok(())
}

fn audit_receipt_files(audit_dir: &std::path::Path) -> TestResult<Vec<String>> {
    fn collect(
        root: &std::path::Path,
        dir: &std::path::Path,
        files: &mut Vec<String>,
    ) -> TestResult<()> {
        for entry in fs::read_dir(dir).test_context("audit dir")? {
            let entry = entry.test_context("audit dir entry")?;
            let path = entry.path();
            let metadata = entry.metadata().test_context("audit entry metadata")?;
            if metadata.is_dir() {
                collect(root, &path, files)?;
            } else if metadata.is_file() {
                files.push(
                    path.strip_prefix(root)
                        .map_err(|err| err.to_string())
                        .test_context("audit relative path")?
                        .display()
                        .to_string()
                        .replace('\\', "/"),
                );
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    collect(audit_dir, audit_dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn normalize_snapshot_paths(value: Value, temp_root: &std::path::Path) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| normalize_snapshot_paths(value, temp_root))
                .collect(),
        ),
        Value::Object(entries) => Value::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key, normalize_snapshot_paths(value, temp_root)))
                .collect(),
        ),
        Value::String(value) => Value::String(normalize_snapshot_text(&value, temp_root)),
        other => other,
    }
}

fn normalize_snapshot_text(value: &str, temp_root: &std::path::Path) -> String {
    let normalized = value.replace('\\', "/");
    let root = temp_root.to_string_lossy().replace('\\', "/");
    normalized.replace(&root, "<temp>")
}

#[test]
fn audit_bundle_ci_outputs_json_on_success() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ])?;
    let audit: Value = serde_json::from_str(&out).test_context("audit json")?;
    assert_eq!(audit["status"], "pass");
    assert_eq!(audit["profile"], "webhook");
    assert_eq!(audit["checks"][0]["failure_class"], "invalid_manifest");
    assert!(!out.contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_ci_accepts_strict_policy_and_expected_profile() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
        "--expect-profile",
        "webhook",
        "--policy",
        "strict",
    ])?;
    let audit: Value = serde_json::from_str(&out).test_context("audit json")?;
    assert_eq!(audit["status"], "pass");
    assert_eq!(audit["profile"], "webhook");
    assert!(!out.contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_ci_writes_metadata_only_receipts_when_out_is_set() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    let audit_dir = dir.path().join("webhook-audit");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
        "--expect-profile",
        "webhook",
        "--policy",
        "strict",
        "--out",
        audit_dir.to_str().test_context("utf-8")?,
    ])?;
    let audit: Value = serde_json::from_str(&out).test_context("audit json")?;
    assert_eq!(audit["status"], "pass");
    assert_eq!(audit["profile"], "webhook");
    assert_eq!(
        audit_receipt_files(&audit_dir)?,
        vec![
            "bundle-audit.json".to_string(),
            "bundle-audit.md".to_string()
        ]
    );

    let audit_json =
        fs::read(audit_dir.join("bundle-audit.json")).test_context("audit json receipt")?;
    let audit_md =
        fs::read(audit_dir.join("bundle-audit.md")).test_context("audit markdown receipt")?;
    let mut receipt_bytes = audit_json;
    receipt_bytes.extend_from_slice(&audit_md);
    let receipt_text = String::from_utf8_lossy(&receipt_bytes);
    assert!(!out.contains("whsec_"));
    assert!(!receipt_text.contains("whsec_"));
    assert!(!receipt_text.contains("BEGIN PRIVATE KEY"));
    Ok(())
}

#[test]
fn audit_bundle_ci_fails_on_expected_profile_mismatch() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
        "--expect-profile",
        "tls",
    ]);
    let assert = audit.assert().code(1).stderr(predicate::str::contains(
        "audit policy failed: profile_validation_failed",
    ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "webhook");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(
        audit["checks"][0]["failure_class"],
        "profile_validation_failed"
    );
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("expected profile `tls`, found `webhook`"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_ci_failure_writes_metadata_only_receipts_when_out_is_set() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    let audit_dir = dir.path().join("webhook-audit");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
        "--expect-profile",
        "tls",
        "--out",
        audit_dir.to_str().test_context("utf-8")?,
    ]);
    let assert = audit.assert().code(1).stderr(predicate::str::contains(
        "audit policy failed: profile_validation_failed",
    ));
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "webhook");
    assert_eq!(
        audit["checks"][0]["failure_class"],
        "profile_validation_failed"
    );
    assert_eq!(
        audit_receipt_files(&audit_dir)?,
        vec![
            "bundle-audit.json".to_string(),
            "bundle-audit.md".to_string()
        ]
    );

    let receipt_json =
        fs::read_to_string(audit_dir.join("bundle-audit.json")).test_context("audit json")?;
    let receipt_md =
        fs::read_to_string(audit_dir.join("bundle-audit.md")).test_context("audit markdown")?;
    let receipt: Value = serde_json::from_str(&receipt_json).test_context("receipt json")?;
    assert_eq!(receipt["status"], "fail");
    assert_eq!(
        receipt["checks"][0]["failure_class"],
        "profile_validation_failed"
    );
    assert!(receipt_md.contains("profile_validation_failed"));
    assert!(!stdout.contains("whsec_"));
    assert!(!receipt_json.contains("whsec_"));
    assert!(!receipt_md.contains("whsec_"));
    assert!(!receipt_json.contains("BEGIN PRIVATE KEY"));
    assert!(!receipt_md.contains("BEGIN PRIVATE KEY"));
    Ok(())
}

#[test]
fn audit_bundle_ci_failure_json_reports_missing_manifest() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("missing-manifest");
    fs::create_dir_all(&bundle_dir).test_context("bundle dir")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains("audit failed: missing_manifest"));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;

    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "missing_manifest");
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("manifest.json is missing"));
    assert!(detail.contains("Fix:"));
    assert_eq!(
        audit["artifacts"]
            .as_array()
            .test_context("artifacts")?
            .len(),
        0
    );
    assert_eq!(
        audit["receipts"].as_array().test_context("receipts")?.len(),
        0
    );
    assert!(
        audit["does_not_prove"]
            .as_array()
            .test_context("does_not_prove")?
            .iter()
            .any(|value| value == "downstream verifier correctness")
    );
    Ok(())
}

#[test]
fn audit_bundle_ci_build_failure_writes_metadata_only_receipts_when_out_is_set() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("missing-manifest");
    let audit_dir = dir.path().join("missing-manifest-audit");
    fs::create_dir_all(&bundle_dir).test_context("bundle dir")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
        "--out",
        audit_dir.to_str().test_context("utf-8")?,
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains("audit failed: missing_manifest"));
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["failure_class"], "missing_manifest");
    assert_eq!(
        audit_receipt_files(&audit_dir)?,
        vec![
            "bundle-audit.json".to_string(),
            "bundle-audit.md".to_string()
        ]
    );

    let receipt_json =
        fs::read_to_string(audit_dir.join("bundle-audit.json")).test_context("audit json")?;
    let receipt_md =
        fs::read_to_string(audit_dir.join("bundle-audit.md")).test_context("audit markdown")?;
    let receipt: Value = serde_json::from_str(&receipt_json).test_context("receipt json")?;
    assert_eq!(receipt["status"], "fail");
    assert_eq!(receipt["profile"], "unknown");
    assert_eq!(receipt["checks"][0]["failure_class"], "missing_manifest");
    assert!(receipt_md.contains("missing_manifest"));
    assert!(!stdout.contains("whsec_"));
    assert!(!receipt_json.contains("whsec_"));
    assert!(!receipt_md.contains("whsec_"));
    assert!(!receipt_json.contains("BEGIN PRIVATE KEY"));
    assert!(!receipt_md.contains("BEGIN PRIVATE KEY"));
    Ok(())
}

#[test]
fn audit_bundle_ci_failure_json_reports_unsupported_profile() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("manifest")?)
            .test_context("manifest json")?;
    manifest["profile"] = serde_json::json!("future-profile");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_context("manifest bytes")?;
    fs::write(&manifest_path, manifest_bytes).test_context("mutate manifest")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit.assert().code(1).stderr(predicate::str::contains(
        "audit failed: unsupported_profile",
    ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;

    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "unsupported_profile");
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("profile this uselesskey CLI cannot audit"));
    assert!(detail.contains("Fix:"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("uk_test_"));
    Ok(())
}

#[test]
fn audit_bundle_summary_outputs_compact_terminal_report() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--summary",
    ])?;

    assert!(out.contains("Bundle audit: pass"));
    assert!(out.contains("Profile: webhook"));
    assert!(out.contains("Artifacts: 7"));
    assert!(out.contains("Scanner-safe: 1"));
    assert!(out.contains("Runtime material: 6"));
    assert!(out.contains("Receipts: present"));
    assert!(out.contains("Boundaries: local consistency only"));
    assert!(!out.contains("requests/valid.json"));
    assert!(!out.contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_summary_with_out_writes_receipts_and_mentions_output_dir() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    let audit_dir = dir.path().join("webhook-audit");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--out",
        audit_dir.to_str().test_context("utf-8")?,
        "--summary",
    ])?;

    assert!(out.contains("Bundle audit: pass"));
    assert!(out.contains("Audit receipts:"));
    assert!(out.contains("webhook-audit"));
    assert!(audit_dir.join("bundle-audit.json").is_file());
    assert!(audit_dir.join("bundle-audit.md").is_file());
    Ok(())
}

#[test]
fn audit_bundle_summary_rejects_ci_mode() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--summary",
        "--ci",
    ]);
    audit
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
    Ok(())
}

#[test]
fn audit_bundle_json_stdout_reports_scanner_safe_bundle() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("scanner-safe");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "scanner-safe",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let out = run([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--format",
        "json",
    ])?;
    let audit: Value = serde_json::from_str(&out).test_context("audit json")?;
    assert_eq!(audit["status"], "pass");
    assert_eq!(audit["profile"], "scanner-safe");
    assert_eq!(audit["scanner_safe_count"], 8);
    assert_eq!(audit["runtime_material_count"], 0);
    assert!(out.contains("cargo xtask claim-proof --claim scanner-safe-fixtures"));
    assert!(!out.contains("BEGIN PRIVATE KEY"));
    Ok(())
}

#[test]
fn audit_bundle_ci_outputs_failure_json_and_exit_1() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("manifest")?)
            .test_context("manifest json")?;
    let files = manifest["files"]
        .as_array_mut()
        .test_context("manifest files")?;
    let first_file = files.first_mut().test_context("first manifest file")?;
    *first_file = serde_json::json!("../escape.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_context("manifest bytes")?;
    fs::write(&manifest_path, manifest_bytes).test_context("mutate manifest")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains("audit failed: path_escape"))
        .stderr(predicate::str::contains(
            "manifest.json lists an unsafe bundle path",
        ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Fix: regenerate the bundle"));
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "path_escape");
    let boundaries = audit["boundaries"]
        .as_array()
        .test_context("failure boundaries")?;
    assert!(boundaries.iter().any(|boundary| {
        boundary.as_str()
            == Some(
                "audit-bundle is not standalone proof for broader repo public claims; use cargo xtask claim-proof from a repo checkout",
            )
    }));
    assert!(boundaries.iter().any(|boundary| {
        boundary.as_str()
            == Some(
                "audit-bundle does not prove release readiness; use release-evidence for release proof",
            )
    }));
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("manifest.json lists an unsafe bundle path"));
    assert!(detail.contains("Detail: ../escape.json"));
    assert!(detail.contains("safe relative paths contained by the bundle"));
    assert_eq!(audit["manifest_version"], 0);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_reports_path_escape_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("manifest")?)
            .test_context("manifest json")?;
    let files = manifest["files"]
        .as_array_mut()
        .test_context("manifest files")?;
    let first_file = files.first_mut().test_context("first manifest file")?;
    *first_file = serde_json::json!("../escape.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_context("manifest bytes")?;
    fs::write(&manifest_path, manifest_bytes).test_context("mutate manifest")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--format",
        "json",
    ]);
    audit
        .assert()
        .failure()
        .stderr(predicate::str::contains("path_escape"));
    Ok(())
}

#[test]
fn audit_bundle_path_escape_diagnostic_escapes_control_characters() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("manifest")?)
            .test_context("manifest json")?;
    let files = manifest["files"]
        .as_array_mut()
        .test_context("manifest files")?;
    let first_file = files.first_mut().test_context("first manifest file")?;
    *first_file = serde_json::json!("receipts/audit-surface\n.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_context("manifest bytes")?;
    fs::write(&manifest_path, manifest_bytes).test_context("mutate manifest")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains("audit failed: path_escape"))
        .stderr(predicate::str::contains("receipts/audit-surface\\n.json"));
    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("receipts/audit-surface\n.json"));

    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("receipts/audit-surface\\n.json"));
    assert!(!detail.contains("receipts/audit-surface\n.json"));
    Ok(())
}

#[test]
fn audit_bundle_fails_on_unexpected_bundle_file() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();
    fs::write(bundle_dir.join("extra.json"), "{}").test_context("extra file")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--format",
        "json",
    ]);
    audit
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected_artifact"));
    Ok(())
}

#[test]
fn audit_bundle_ci_reports_unexpected_artifact_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    fs::write(bundle_dir.join("extra.json"), "{}").test_context("extra file")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "audit failed: unexpected_artifact",
        ))
        .stderr(predicate::str::contains(
            "the bundle contains files that are not listed in manifest.json",
        ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "unexpected_artifact");
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("extra.json"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_ci_reports_missing_artifact_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("manifest")?)
            .test_context("manifest json")?;
    let missing_file = manifest["files"]
        .as_array()
        .test_context("manifest files")?
        .first()
        .and_then(Value::as_str)
        .test_context("first manifest file")?;
    fs::remove_file(bundle_dir.join(missing_file)).test_context("remove manifest artifact")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains("audit failed: missing_artifact"))
        .stderr(predicate::str::contains(
            "manifest.json lists files that are absent",
        ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "missing_artifact");
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains(missing_file));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_reports_runtime_material_mismatch_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let receipt_path = bundle_dir.join("receipts/audit-surface.json");
    let mut receipt: Value =
        serde_json::from_slice(&fs::read(&receipt_path).test_context("audit receipt")?)
            .test_context("audit receipt json")?;
    receipt["runtime_material_count"] = serde_json::json!(0);
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).test_context("receipt bytes")?;
    fs::write(&receipt_path, receipt_bytes).test_context("mutate audit receipt")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--format",
        "json",
    ]);
    audit
        .assert()
        .failure()
        .stderr(predicate::str::contains("runtime_material_mismatch"));
    Ok(())
}

#[test]
fn audit_bundle_ci_reports_scanner_safe_mismatch_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let receipt_path = bundle_dir.join("receipts/audit-surface.json");
    let mut receipt: Value =
        serde_json::from_slice(&fs::read(&receipt_path).test_context("audit receipt")?)
            .test_context("audit receipt json")?;
    receipt["scanner_safe_count"] = serde_json::json!(999);
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).test_context("receipt bytes")?;
    fs::write(&receipt_path, receipt_bytes).test_context("mutate audit receipt")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "audit failed: scanner_safe_mismatch",
        ))
        .stderr(predicate::str::contains(
            "audit-surface scanner-safe metadata differs",
        ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "scanner_safe_mismatch");
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("scanner_safe_count"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_ci_reports_runtime_material_mismatch_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let receipt_path = bundle_dir.join("receipts/audit-surface.json");
    let mut receipt: Value =
        serde_json::from_slice(&fs::read(&receipt_path).test_context("audit receipt")?)
            .test_context("audit receipt json")?;
    receipt["runtime_material_count"] = serde_json::json!(0);
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).test_context("receipt bytes")?;
    fs::write(&receipt_path, receipt_bytes).test_context("mutate audit receipt")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "audit failed: runtime_material_mismatch",
        ))
        .stderr(predicate::str::contains(
            "audit-surface runtime-material metadata differs",
        ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(
        audit["checks"][0]["failure_class"],
        "runtime_material_mismatch"
    );
    let detail = audit["checks"][0]["detail"]
        .as_str()
        .test_context("failure detail")?;
    assert!(detail.contains("runtime_material_count"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_ci_reports_invalid_receipt_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let receipt_path = bundle_dir.join("receipts/audit-surface.json");
    fs::write(&receipt_path, "{not-json").test_context("mutate audit receipt")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains("audit failed: invalid_receipt"))
        .stderr(predicate::str::contains(
            "a bundle receipt could not be parsed",
        ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "invalid_receipt");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_ci_reports_missing_receipt_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("webhook");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--profile",
        "webhook",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("manifest")?)
            .test_context("manifest json")?;
    manifest["receipts"] = serde_json::json!([]);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_context("manifest bytes")?;
    fs::write(&manifest_path, manifest_bytes).test_context("mutate manifest")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--ci",
    ]);
    let assert = audit
        .assert()
        .code(1)
        .stderr(predicate::str::contains("audit failed: missing_receipt"))
        .stderr(predicate::str::contains(
            "a required bundle receipt is missing",
        ));
    let output = assert.get_output();
    let audit: Value = serde_json::from_slice(&output.stdout).test_context("audit failure json")?;
    assert_eq!(audit["status"], "fail");
    assert_eq!(audit["profile"], "unknown");
    assert_eq!(audit["checks"][0]["status"], "fail");
    assert_eq!(audit["checks"][0]["failure_class"], "missing_receipt");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("whsec_"));
    Ok(())
}

#[test]
fn audit_bundle_reports_unsupported_profile_class() -> TestResult<()> {
    let dir = tempdir().test_context("tempdir")?;
    let bundle_dir = dir.path().join("bundle");

    let mut bundle = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    bundle.args([
        "bundle",
        "--out",
        bundle_dir.to_str().test_context("utf-8")?,
    ]);
    bundle.assert().success();

    let manifest_path = bundle_dir.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_context("manifest")?)
            .test_context("manifest json")?;
    manifest["profile"] = serde_json::json!("future-profile");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_context("manifest bytes")?;
    fs::write(&manifest_path, manifest_bytes).test_context("mutate manifest")?;

    let mut audit = Command::cargo_bin("uselesskey").test_context("bin exists")?;
    audit.args([
        "audit-bundle",
        "--path",
        bundle_dir.to_str().test_context("utf-8")?,
        "--format",
        "json",
    ]);
    audit
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported_profile"));
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
fn bundle_verify_and_inspect_reject_path_escape_class() -> TestResult<()> {
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
    let files = manifest["files"]
        .as_array_mut()
        .test_context("manifest files")?;
    let first_file = files.first_mut().test_context("first manifest file")?;
    *first_file = serde_json::json!("../escape.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).test_context("serialize manifest")?,
    )
    .test_context("mutate manifest")?;

    for command in ["verify-bundle", "inspect-bundle"] {
        let mut cmd = Command::cargo_bin("uselesskey").test_context("bin exists")?;
        cmd.args([
            command,
            "--path",
            bundle_dir.to_str().test_context("utf-8")?,
        ]);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("path_escape"))
            .stderr(predicate::str::contains("../escape.json"));
    }
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
