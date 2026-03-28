use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn bin() -> Command {
    Command::cargo_bin("uselesskey").expect("binary exists")
}

#[test]
fn golden_rsa_pem_output() {
    let output = bin()
        .args([
            "generate",
            "rsa",
            "--seed",
            "cli-golden",
            "--label",
            "issuer",
            "--format",
            "pem",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let pem = String::from_utf8(output).expect("utf8 output");
    insta::assert_snapshot!("generate_rsa_pem", pem);
}

#[test]
fn deterministic_repeatability() {
    let run = || {
        bin()
            .args([
                "generate",
                "jwks",
                "--seed",
                "cli-repeat",
                "--label",
                "issuer",
                "--format",
                "jwks",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };

    assert_eq!(run(), run(), "same seed/label should be stable");
}

#[test]
fn invalid_kind_format_combo_errors() {
    bin()
        .args([
            "generate",
            "token",
            "--seed",
            "cli-bad",
            "--label",
            "svc",
            "--format",
            "der",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported kind/format combination"));
}

#[test]
fn bundle_manifest_schema() {
    let stdout = bin()
        .args([
            "bundle",
            "--seed",
            "cli-bundle",
            "--label",
            "svc",
            "--format",
            "json-manifest",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let manifest: Value = serde_json::from_slice(&stdout).expect("valid json");
    assert_eq!(manifest["seed"], "cli-bundle");
    assert_eq!(manifest["label"], "svc");
    let entries = manifest["entries"].as_array().expect("entries array");
    assert!(entries.len() >= 4, "bundle should include multiple artifacts");
    for entry in entries {
        assert!(entry["name"].is_string());
        assert!(entry["kind"].is_string());
        assert!(entry["format"].is_string());
        assert!(entry["bytes"].is_u64());
    }
}

#[test]
fn inspect_accepts_stdin_and_outputs_json() {
    let mut cmd = bin();
    cmd.args(["inspect", "--format", "json-manifest"])
        .write_stdin("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected\": \"pem\""));
}
