use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

fn bin_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_uselesskey-cli") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_uselesskey_cli") {
        return PathBuf::from(path);
    }

    let exe = std::env::current_exe().expect("current_exe");
    let target_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target dir")
        .to_path_buf();
    target_dir.join("uselesskey-cli")
}

#[test]
fn golden_cli_output_jwk() {
    let output = Command::new(bin_path())
        .args([
            "generate",
            "jwk",
            "--seed",
            "ci-seed",
            "--label",
            "issuer",
            "--format",
            "jwk",
        ])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("utf8 output");
    insta::assert_snapshot!("generate_jwk", text);
}

#[test]
fn deterministic_repeatability() {
    let run = || {
        Command::new(bin_path())
            .args([
                "generate",
                "rsa",
                "--seed",
                "repeat-seed",
                "--label",
                "svc",
                "--format",
                "jwk",
            ])
            .output()
            .expect("run cli")
            .stdout
    };

    let a = run();
    let b = run();
    assert_eq!(a, b);
}

#[test]
fn bad_arg_bad_format() {
    let output = Command::new(bin_path())
        .args([
            "generate",
            "token",
            "--seed",
            "x",
            "--label",
            "svc",
            "--format",
            "der",
        ])
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let err = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(err.contains("token supports jwk/jwks/json-manifest output only"));
}

#[test]
fn bundle_manifest_schema() {
    let tmp = tempdir().expect("temp dir");
    let output = Command::new(bin_path())
        .args([
            "bundle",
            "--seed",
            "bundle-seed",
            "--label",
            "svc",
            "--format",
            "json-manifest",
            "--artifact",
            "rsa",
            "--artifact",
            "jwks",
        ])
        .output()
        .expect("run cli");

    assert!(output.status.success());
    let manifest: Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(manifest["schema_version"], "v1");
    assert_eq!(manifest["seed"], "bundle-seed");
    assert_eq!(manifest["label"], "svc");
    assert_eq!(manifest["artifacts"].as_array().expect("array").len(), 2);

    let out_dir = tmp.path().join("bundle");
    let output2 = Command::new(bin_path())
        .args([
            "bundle",
            "--seed",
            "bundle-seed",
            "--label",
            "svc",
            "--format",
            "bundle-dir",
            "--out",
            out_dir.to_str().expect("path str"),
            "--artifact",
            "rsa",
        ])
        .output()
        .expect("run bundle-dir");
    assert!(output2.status.success());
    assert!(out_dir.join("manifest.json").exists());
}
