use std::fs;
use std::path::PathBuf;
use std::process::Command;


fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_uselesskey-cli"))
}

#[test]
fn golden_generate_rsa_jwk_output() {
    let output = cli()
        .args([
            "generate",
            "rsa",
            "--seed",
            "golden-seed",
            "--label",
            "issuer",
            "--format",
            "jwk",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let digest = blake3::hash(stdout.as_bytes()).to_hex().to_string();
    assert_eq!(digest, "b23ed589da8c151659521b3e1e5cc0b5d9b95e0019e04b4d9e6eff8a19fe66de");
}

#[test]
fn deterministic_repeatability_generate_token() {
    let a = cli()
        .args([
            "generate",
            "token",
            "--seed",
            "repeatable-seed",
            "--label",
            "svc",
            "--format",
            "pem",
        ])
        .output()
        .unwrap();
    assert!(a.status.success());

    let b = cli()
        .args([
            "generate",
            "token",
            "--seed",
            "repeatable-seed",
            "--label",
            "svc",
            "--format",
            "pem",
        ])
        .output()
        .unwrap();
    assert!(b.status.success());

    assert_eq!(a.stdout, b.stdout);
}

#[test]
fn bad_format_for_kind_returns_error() {
    let output = cli()
        .args([
            "generate",
            "token",
            "--seed",
            "bad-format-seed",
            "--label",
            "svc",
            "--format",
            "der",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("not supported for token"));
}

#[test]
fn bundle_manifest_schema_and_files() {
    let mut dir = std::env::temp_dir();
    dir.push(format!("uselesskey-cli-test-{}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }

    let output = cli()
        .args([
            "bundle",
            "--seed",
            "bundle-seed",
            "--label",
            "svc",
            "--format",
            "bundle-dir",
            "--out",
        ])
        .arg(&dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let manifest_path: PathBuf = dir.join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&manifest).unwrap();

    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["seed_source"], "bundle-seed");
    assert_eq!(json["label"], "svc");
    assert!(json["files"].as_array().unwrap().len() >= 5);

    for required in [
        "rsa-private.pem",
        "ecdsa-private.pem",
        "ed25519-private.pem",
        "jwks.json",
        "token.txt",
    ] {
        assert!(dir.join(required).exists(), "missing {required}");
    }

    fs::remove_dir_all(&dir).unwrap();
}
