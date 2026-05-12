//! Integration tests for `uselesskey bundle --profile tls`.
//!
//! Covers the TLS contract-pack profile defined in
//! `docs/release/v0.8.0-tls-profile-design.md`:
//!   - the six certificate fixtures (valid leaf, valid chain, four negatives),
//!   - the deterministic receipts and evidence doc,
//!   - byte-identical determinism on a second invocation,
//!   - `verify-bundle` round-trip against the generated bundle.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

const TLS_SEED: &str = "tls-profile-integration-seed";
const TLS_LABEL: &str = "tls-integration";

fn run_bundle(bundle_dir: &std::path::Path) {
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    cmd.args([
        "bundle",
        "--profile",
        "tls",
        "--seed",
        TLS_SEED,
        "--label",
        TLS_LABEL,
        "--out",
        bundle_dir.to_str().expect("utf-8 path"),
    ]);
    cmd.assert().success();
}

#[test]
fn tls_bundle_emits_expected_layout() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("tls");
    run_bundle(&bundle_dir);

    // Six certificate fixtures, one evidence doc, two receipts, plus manifest.
    for relative in [
        "certs/valid-leaf.pem",
        "certs/valid-chain.pem",
        "certs/negative-expired-leaf.pem",
        "certs/negative-not-yet-valid.pem",
        "certs/negative-wrong-hostname.pem",
        "certs/negative-untrusted-root.pem",
        "evidence/tls-profile.md",
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
        let meta = fs::metadata(&path).expect("stat fixture");
        assert!(meta.len() > 0, "fixture {} should not be empty", relative);
    }

    // Manifest profile/label/seed metadata reflects the TLS dispatch.
    let manifest: Value =
        serde_json::from_slice(&fs::read(bundle_dir.join("manifest.json")).expect("read manifest"))
            .expect("manifest json");
    assert_eq!(manifest["profile"], "tls");
    assert_eq!(manifest["seed"], TLS_SEED);
    assert_eq!(manifest["label"], TLS_LABEL);
    let artifacts = manifest["artifacts"].as_array().expect("artifacts array");
    assert_eq!(artifacts.len(), 7); // 6 certs + 1 evidence doc
    assert!(
        artifacts
            .iter()
            .all(|artifact| artifact["profile"] == "tls" && artifact["scanner_safe"] == true)
    );
}

#[test]
fn tls_bundle_certificate_fixtures_parse_as_pem_certificates() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("tls");
    run_bundle(&bundle_dir);

    // Single-cert leaves: each negative leaf and the happy-path leaf must contain
    // exactly one BEGIN CERTIFICATE block.
    for single_cert in [
        "certs/valid-leaf.pem",
        "certs/negative-expired-leaf.pem",
        "certs/negative-not-yet-valid.pem",
        "certs/negative-wrong-hostname.pem",
        "certs/negative-untrusted-root.pem",
    ] {
        let text = fs::read_to_string(bundle_dir.join(single_cert)).expect("read cert");
        let begin_count = text.matches("-----BEGIN CERTIFICATE-----").count();
        let end_count = text.matches("-----END CERTIFICATE-----").count();
        assert_eq!(
            begin_count, 1,
            "{single_cert} should contain exactly one BEGIN CERTIFICATE block",
        );
        assert_eq!(
            end_count, 1,
            "{single_cert} should contain exactly one END CERTIFICATE block",
        );
    }

    // The full chain must include leaf + intermediate + root (3 certificates).
    let chain = fs::read_to_string(bundle_dir.join("certs/valid-chain.pem")).expect("read chain");
    let chain_count = chain.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(
        chain_count, 3,
        "valid-chain.pem should contain leaf + intermediate + root"
    );

    // Wrong-hostname leaf must reference the documented wrong hostname (not the
    // expected one) so callers can assert on it from PEM bytes alone.
    let wrong = fs::read_to_string(bundle_dir.join("certs/negative-wrong-hostname.pem"))
        .expect("read wrong-hostname");
    assert!(!wrong.is_empty(), "wrong-hostname leaf should be non-empty");

    // Untrusted-root leaf must differ from the valid leaf (different signing chain).
    let valid_leaf =
        fs::read_to_string(bundle_dir.join("certs/valid-leaf.pem")).expect("read valid leaf");
    let untrusted_leaf = fs::read_to_string(bundle_dir.join("certs/negative-untrusted-root.pem"))
        .expect("read untrusted leaf");
    assert_ne!(
        valid_leaf, untrusted_leaf,
        "untrusted-root leaf must differ from happy-path valid leaf"
    );
}

#[test]
fn tls_bundle_is_deterministic_across_runs() {
    let first = tempdir().expect("tempdir1");
    let second = tempdir().expect("tempdir2");
    let first_dir = first.path().join("tls");
    let second_dir = second.path().join("tls");

    run_bundle(&first_dir);
    run_bundle(&second_dir);

    for relative in [
        "certs/valid-leaf.pem",
        "certs/valid-chain.pem",
        "certs/negative-expired-leaf.pem",
        "certs/negative-not-yet-valid.pem",
        "certs/negative-wrong-hostname.pem",
        "certs/negative-untrusted-root.pem",
        "evidence/tls-profile.md",
        "receipts/materialization.json",
        "receipts/audit-surface.json",
        "manifest.json",
    ] {
        let a = fs::read(first_dir.join(relative)).expect("read first");
        let b = fs::read(second_dir.join(relative)).expect("read second");
        assert_eq!(
            a, b,
            "{relative} must be byte-identical across two bundle invocations \
             with the same seed",
        );
    }
}

#[test]
fn tls_evidence_markdown_lists_all_fixtures_with_failure_classes() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("tls");
    run_bundle(&bundle_dir);

    let evidence =
        fs::read_to_string(bundle_dir.join("evidence/tls-profile.md")).expect("read evidence doc");

    // Title and design pointer must be present so the doc is recognisable
    // even outside the bundle.
    assert!(
        evidence.contains("# TLS contract-pack profile evidence"),
        "evidence doc must carry its title heading"
    );
    assert!(
        evidence.contains("docs/release/v0.8.0-tls-profile-design.md"),
        "evidence doc must point at the design doc"
    );
    assert!(
        evidence.contains("uselesskey bundle --profile tls"),
        "evidence doc must name the command that produces the bundle"
    );

    // Hostname expectations are documented so verifiers know what to compare against.
    assert!(
        evidence.contains("Expected hostname:"),
        "evidence doc must declare the expected hostname"
    );
    assert!(
        evidence.contains("Hostname-mismatch wrong hostname:"),
        "evidence doc must declare the wrong hostname used by the negative fixture"
    );

    // The markdown table header must be present so the per-row entries are
    // actually structured rather than free text.
    assert!(
        evidence.contains("| File | Role | Failure class |"),
        "evidence doc must include the per-fixture table header"
    );

    // Each of the six certificate fixtures must be named by its relative path
    // so consumers can grep for the exact filename they care about.
    for fixture in [
        "`certs/valid-leaf.pem`",
        "`certs/valid-chain.pem`",
        "`certs/negative-expired-leaf.pem`",
        "`certs/negative-not-yet-valid.pem`",
        "`certs/negative-wrong-hostname.pem`",
        "`certs/negative-untrusted-root.pem`",
    ] {
        assert!(
            evidence.contains(fixture),
            "evidence doc must mention fixture path {fixture}"
        );
    }

    // Each negative fixture must announce its failure class so callers know
    // why a given fixture is expected to be rejected.
    for failure_class in [
        "expired",
        "not yet valid",
        "hostname mismatch",
        "unknown CA",
    ] {
        assert!(
            evidence.contains(failure_class),
            "evidence doc must name failure class {failure_class:?}"
        );
    }

    // Happy-path entries must be tagged as such so they aren't mistaken for
    // rejection cases.
    assert!(
        evidence.contains("(none - happy path)"),
        "evidence doc must mark happy-path fixtures with no failure class"
    );
}

#[test]
fn tls_bundle_round_trips_through_verify_bundle() {
    let dir = tempdir().expect("tempdir");
    let bundle_dir = dir.path().join("tls");
    run_bundle(&bundle_dir);

    let mut verify = Command::cargo_bin("uselesskey").expect("bin exists");
    verify.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8 path"),
    ]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));

    // Corrupt one of the negative leaves and confirm verify-bundle detects drift.
    fs::write(
        bundle_dir.join("certs/negative-expired-leaf.pem"),
        "not a certificate\n",
    )
    .expect("mutate negative leaf");

    let mut verify_bad = Command::cargo_bin("uselesskey").expect("bin exists");
    verify_bad.args([
        "verify-bundle",
        "--path",
        bundle_dir.to_str().expect("utf-8 path"),
    ]);
    verify_bad
        .assert()
        .failure()
        .stderr(predicate::str::contains("content mismatch"));
}
