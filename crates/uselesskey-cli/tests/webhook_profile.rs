//! Integration tests for `uselesskey bundle --profile webhook`.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;
use uselesskey_test_support::{TestResult, ensure_eq, require_ok, require_some};

const WEBHOOK_SEED: &str = "webhook-profile-integration-seed";
const WEBHOOK_LABEL: &str = "webhook-integration";

fn run_bundle(bundle_dir: &std::path::Path) -> TestResult<()> {
    let mut cmd = require_ok(Command::cargo_bin("uselesskey"), "bin exists")?;
    cmd.args([
        "bundle",
        "--profile",
        "webhook",
        "--seed",
        WEBHOOK_SEED,
        "--label",
        WEBHOOK_LABEL,
        "--out",
        require_some(bundle_dir.to_str(), "utf-8 path")?,
    ]);
    cmd.assert().success();
    Ok(())
}

#[test]
fn webhook_bundle_emits_expected_layout() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    run_bundle(&bundle_dir)?;

    for relative in [
        "requests/valid.json",
        "requests/negative-tampered-body.json",
        "requests/negative-wrong-secret.json",
        "requests/negative-stale-timestamp.json",
        "requests/negative-missing-signature.json",
        "requests/negative-malformed-signature.json",
        "evidence/webhook-profile.md",
        "receipts/materialization.json",
        "receipts/audit-surface.json",
        "manifest.json",
    ] {
        let path = bundle_dir.join(relative);
        assert!(
            path.exists(),
            "expected bundle file missing: {}",
            path.display()
        );
        let meta = require_ok(fs::metadata(&path), "stat fixture")?;
        assert!(meta.len() > 0, "fixture {relative} should not be empty");
    }

    let manifest = read_json(&bundle_dir.join("manifest.json"))?;
    ensure_eq!(manifest["profile"], "webhook");
    ensure_eq!(manifest["seed"], WEBHOOK_SEED);
    ensure_eq!(manifest["label"], WEBHOOK_LABEL);
    ensure_eq!(manifest["files"][0], "requests/valid.json");
    ensure_eq!(manifest["files"][6], "evidence/webhook-profile.md");

    let artifacts = require_some(manifest["artifacts"].as_array(), "artifacts array")?;
    ensure_eq!(artifacts.len(), 7);
    assert!(
        artifacts
            .iter()
            .all(|artifact| artifact["profile"] == "webhook")
    );
    assert!(
        artifacts
            .iter()
            .filter(|artifact| artifact["kind"] == "webhook" && artifact["scanner_safe"] == false)
            .count()
            >= 6
    );

    let audit = read_json(&bundle_dir.join("receipts/audit-surface.json"))?;
    ensure_eq!(audit["profile"], "webhook");
    ensure_eq!(audit["scanner_safe"], false);
    ensure_eq!(audit["runtime_material_count"], 6);
    Ok(())
}

#[test]
fn webhook_request_fixtures_record_stable_rejection_classes() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    run_bundle(&bundle_dir)?;

    for (relative, expected_result, rejection_class) in [
        ("requests/valid.json", "accept", "valid"),
        (
            "requests/negative-tampered-body.json",
            "reject",
            "tampered_body",
        ),
        (
            "requests/negative-wrong-secret.json",
            "reject",
            "wrong_secret",
        ),
        (
            "requests/negative-stale-timestamp.json",
            "reject",
            "stale_timestamp",
        ),
        (
            "requests/negative-missing-signature.json",
            "reject",
            "missing_signature",
        ),
        (
            "requests/negative-malformed-signature.json",
            "reject",
            "malformed_signature",
        ),
    ] {
        let fixture = read_json(&bundle_dir.join(relative))?;
        ensure_eq!(fixture["method"], "POST");
        ensure_eq!(fixture["path"], "/webhooks/uselesskey");
        ensure_eq!(fixture["expected_result"], expected_result);
        ensure_eq!(fixture["rejection_class"], rejection_class);
        ensure_eq!(fixture["profile"], "webhook");
        assert!(fixture["body"].is_string());
        assert!(fixture["headers"].is_object());
        assert!(fixture["verifier_secret"].is_string());
    }

    let missing = read_json(&bundle_dir.join("requests/negative-missing-signature.json"))?;
    assert!(missing["headers"].get("Stripe-Signature").is_none());

    let malformed = read_json(&bundle_dir.join("requests/negative-malformed-signature.json"))?;
    ensure_eq!(
        malformed["headers"]["Stripe-Signature"],
        format!(
            "t={},v1=not-a-hex-signature",
            require_some(malformed["timestamp"].as_i64(), "timestamp")?
        )
    );
    Ok(())
}

#[test]
fn webhook_bundle_is_deterministic_and_verifiable() -> TestResult<()> {
    let first = require_ok(tempdir(), "tempdir1")?;
    let second = require_ok(tempdir(), "tempdir2")?;
    let first_dir = first.path().join("webhook");
    let second_dir = second.path().join("webhook");

    run_bundle(&first_dir)?;
    run_bundle(&second_dir)?;

    for relative in [
        "requests/valid.json",
        "requests/negative-tampered-body.json",
        "requests/negative-wrong-secret.json",
        "requests/negative-stale-timestamp.json",
        "requests/negative-missing-signature.json",
        "requests/negative-malformed-signature.json",
        "evidence/webhook-profile.md",
        "receipts/materialization.json",
        "receipts/audit-surface.json",
        "manifest.json",
    ] {
        let a = require_ok(fs::read(first_dir.join(relative)), "read first")?;
        let b = require_ok(fs::read(second_dir.join(relative)), "read second")?;
        ensure_eq!(a, b);
    }

    let mut verify = require_ok(Command::cargo_bin("uselesskey"), "bin exists")?;
    verify.args([
        "verify-bundle",
        "--path",
        require_some(first_dir.to_str(), "utf-8 path")?,
    ]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));
    Ok(())
}

#[test]
fn webhook_evidence_markdown_lists_all_rejection_classes() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let bundle_dir = dir.path().join("webhook");
    run_bundle(&bundle_dir)?;

    let evidence = require_ok(
        fs::read_to_string(bundle_dir.join("evidence/webhook-profile.md")),
        "read evidence",
    )?;

    assert!(evidence.contains("# Webhook contract-pack profile evidence"));
    assert!(evidence.contains("uselesskey bundle --profile webhook"));
    assert!(evidence.contains("| File | Expected result | Rejection class |"));
    for rejection_class in [
        "valid",
        "tampered_body",
        "wrong_secret",
        "stale_timestamp",
        "missing_signature",
        "malformed_signature",
    ] {
        assert!(
            evidence.contains(rejection_class),
            "evidence must include {rejection_class}"
        );
    }
    assert!(evidence.contains("does not prove provider compatibility"));
    Ok(())
}

fn read_json(path: &std::path::Path) -> TestResult<Value> {
    let bytes = require_ok(fs::read(path), format!("read {}", path.display()))?;
    require_ok(
        serde_json::from_slice(&bytes),
        format!("parse {}", path.display()),
    )
}
