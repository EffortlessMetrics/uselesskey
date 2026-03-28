use std::fs;

use assert_cmd::Command;
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
    assert!(output1.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn generate_jwk_outputs_json() {
    let out = run([
        "generate", "jwk", "--seed", "det-seed", "--label", "issuer", "--format", "jwk",
    ]);
    let value: Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(value["kty"], "RSA");
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
    assert_eq!(value["seed"], "det-seed");
    assert_eq!(value["label"], "bundle-label");
    assert!(value["files"].as_array().expect("array").len() >= 8);
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

fn run<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut cmd = Command::cargo_bin("uselesskey").expect("bin exists");
    let assert = cmd.args(args).assert().success();
    String::from_utf8(assert.get_output().stdout.clone()).expect("utf8")
}
