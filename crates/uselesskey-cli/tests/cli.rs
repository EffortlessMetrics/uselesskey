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
