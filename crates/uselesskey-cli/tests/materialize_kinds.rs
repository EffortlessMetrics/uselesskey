//! Coverage for `materialize_manifest_to_dir` kinds and label-normalization
//! edge cases that the binary-level tests don't exercise directly.
//!
//! These tests go through the public manifest API so they remain stable
//! against private helper refactors.

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use tempfile::tempdir;
use uselesskey_cli::{
    MaterializeFixtureSpec, MaterializeKind, MaterializeManifest, emit_include_bytes_module,
    materialize_manifest_to_dir,
};
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok};

fn manifest_with(fixtures: Vec<MaterializeFixtureSpec>) -> MaterializeManifest {
    MaterializeManifest {
        version: Some(1),
        fixtures,
    }
}

#[test]
fn pem_block_shape_emits_block_with_normalized_label() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let out = dir.path().to_path_buf();

    let manifest = manifest_with(vec![MaterializeFixtureSpec {
        id: Some("pem-key".to_string()),
        out: PathBuf::from("issuer.pem"),
        kind: MaterializeKind::PemBlockShape,
        seed: "pem-block-seed".to_string(),
        label: Some("acme key".to_string()), // space + lowercase → "ACME_KEY"
        len: Some(96),
    }]);

    let summary = require_ok(
        materialize_manifest_to_dir(&manifest, &out, false),
        "materialize",
    )?;
    ensure_eq!(summary.count, 1);

    let pem = require_ok(
        fs::read_to_string(out.join("issuer.pem")),
        "read materialized pem",
    )?;
    ensure!(
        pem.starts_with("-----BEGIN ACME_KEY-----\n"),
        "PEM should start with normalized BEGIN line, got: {pem}"
    );
    ensure!(
        pem.contains("-----END ACME_KEY-----\n"),
        "PEM should contain matching END line, got: {pem}"
    );

    // The body lines between BEGIN/END should be valid base64.
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    require_ok(
        BASE64_STD.decode(body.as_bytes()),
        "PEM body must be base64",
    )?;
    Ok(())
}

#[test]
fn pem_block_shape_label_with_only_special_chars_falls_back_to_secret() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let out = dir.path().to_path_buf();

    let manifest = manifest_with(vec![MaterializeFixtureSpec {
        id: Some("blank-label".to_string()),
        out: PathBuf::from("blank.pem"),
        kind: MaterializeKind::PemBlockShape,
        seed: "blank-pem-seed".to_string(),
        label: Some("@@@".to_string()), // all non-alnum chars normalize to "___", non-empty
        len: Some(32),
    }]);

    require_ok(
        materialize_manifest_to_dir(&manifest, &out, false),
        "materialize",
    )?;

    let pem = require_ok(fs::read_to_string(out.join("blank.pem")), "read pem")?;
    ensure!(
        pem.starts_with("-----BEGIN ___-----\n"),
        "non-alnum label should normalize to underscores, got: {pem}"
    );
    Ok(())
}

#[test]
fn pem_block_shape_empty_label_falls_back_to_secret() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let out = dir.path().to_path_buf();

    let manifest = manifest_with(vec![MaterializeFixtureSpec {
        id: Some("empty-label".to_string()),
        // No `label`, and `out` has no usable file stem → fallback_label is
        // called and returns "fixture", which normalize_pem_label keeps as
        // "FIXTURE" (non-empty).
        out: PathBuf::from("named.pem"),
        kind: MaterializeKind::PemBlockShape,
        seed: "empty-label-seed".to_string(),
        label: None,
        len: Some(32),
    }]);

    require_ok(
        materialize_manifest_to_dir(&manifest, &out, false),
        "materialize",
    )?;

    let pem = require_ok(fs::read_to_string(out.join("named.pem")), "read pem")?;
    ensure!(
        pem.starts_with("-----BEGIN NAMED-----\n"),
        "label from file stem `named.pem` should normalize to NAMED, got: {pem}"
    );
    Ok(())
}

#[test]
fn token_api_key_kind_emits_non_empty_token_value() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let out = dir.path().to_path_buf();

    let manifest = manifest_with(vec![MaterializeFixtureSpec {
        id: Some("svc-token".to_string()),
        out: PathBuf::from("svc.token"),
        kind: MaterializeKind::TokenApiKey,
        seed: "api-key-seed".to_string(),
        label: Some("svc-token".to_string()),
        len: None,
    }]);

    require_ok(
        materialize_manifest_to_dir(&manifest, &out, false),
        "materialize",
    )?;

    let token = require_ok(fs::read_to_string(out.join("svc.token")), "read token")?;
    ensure!(!token.is_empty(), "api-key token must be non-empty");
    ensure!(
        !token.contains('.'),
        "api-key token should not look like a JWT (no dots), got: {token}"
    );
    Ok(())
}

#[test]
fn token_api_key_is_deterministic_across_runs() -> TestResult<()> {
    let dir_a = require_ok(tempdir(), "tempdir-a")?;
    let dir_b = require_ok(tempdir(), "tempdir-b")?;

    let spec = MaterializeFixtureSpec {
        id: Some("svc-token".to_string()),
        out: PathBuf::from("svc.token"),
        kind: MaterializeKind::TokenApiKey,
        seed: "api-key-determinism".to_string(),
        label: Some("svc".to_string()),
        len: None,
    };
    let manifest = manifest_with(vec![spec]);

    require_ok(
        materialize_manifest_to_dir(&manifest, dir_a.path(), false),
        "materialize a",
    )?;
    require_ok(
        materialize_manifest_to_dir(&manifest, dir_b.path(), false),
        "materialize b",
    )?;

    let a = require_ok(fs::read_to_string(dir_a.path().join("svc.token")), "read a")?;
    let b = require_ok(fs::read_to_string(dir_b.path().join("svc.token")), "read b")?;
    ensure_eq!(a, b);
    Ok(())
}

#[test]
fn ssh_public_key_shape_with_only_disallowed_label_falls_back_to_fixture() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let out = dir.path().to_path_buf();

    let manifest = manifest_with(vec![MaterializeFixtureSpec {
        id: Some("ssh-empty".to_string()),
        out: PathBuf::from("id_ed25519.pub"),
        kind: MaterializeKind::SshPublicKeyShape,
        seed: "ssh-shape-seed".to_string(),
        // Only `@` chars — every char normalizes to `-`, producing a non-empty
        // comment of dashes, so we use the empty-string label case via the
        // out-stem fallback to get an "id_ed25519" comment.
        label: None,
        len: None,
    }]);

    require_ok(
        materialize_manifest_to_dir(&manifest, &out, false),
        "materialize",
    )?;

    let content = require_ok(fs::read_to_string(out.join("id_ed25519.pub")), "read ssh")?;
    ensure!(
        content.starts_with("ssh-ed25519 "),
        "ssh public key shape should start with algorithm marker, got: {content}"
    );
    ensure!(
        content.trim_end().ends_with(" id_ed25519"),
        "label-less spec should use sanitized file stem `id_ed25519` as comment, got: {content}"
    );
    Ok(())
}

#[test]
fn entropy_bytes_kind_uses_default_length_when_unset() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let out = dir.path().to_path_buf();

    let manifest = manifest_with(vec![MaterializeFixtureSpec {
        id: Some("entropy-default-len".to_string()),
        out: PathBuf::from("default.bin"),
        kind: MaterializeKind::EntropyBytes,
        seed: "default-len-seed".to_string(),
        label: None,
        len: None, // default is 32 bytes
    }]);

    require_ok(
        materialize_manifest_to_dir(&manifest, &out, false),
        "materialize",
    )?;

    let bytes = require_ok(fs::read(out.join("default.bin")), "read entropy")?;
    ensure_eq!(bytes.len(), 32, "entropy default length should be 32 bytes");
    Ok(())
}

#[test]
fn materialize_to_dir_with_empty_manifest_errors() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let manifest = manifest_with(Vec::new());

    let result = materialize_manifest_to_dir(&manifest, dir.path(), false);
    match result {
        Err(uselesskey_cli::MaterializeError::InvalidManifest(msg)) => {
            ensure!(
                msg.contains("no fixtures"),
                "empty manifest error should mention 'no fixtures', got: {msg}"
            );
            Ok(())
        }
        other => Err(uselesskey_test_support::TestError(format!(
            "expected InvalidManifest error, got {other:?}"
        ))),
    }
}

#[test]
fn emit_include_bytes_module_with_empty_manifest_errors() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let manifest = manifest_with(Vec::new());
    let module = dir.path().join("fixtures.rs");

    let result = emit_include_bytes_module(&manifest, dir.path(), &module);
    match result {
        Err(uselesskey_cli::MaterializeError::InvalidManifest(msg)) => {
            ensure!(
                msg.contains("empty"),
                "empty manifest emit error should mention 'empty', got: {msg}"
            );
            Ok(())
        }
        other => Err(uselesskey_test_support::TestError(format!(
            "expected InvalidManifest error, got {other:?}"
        ))),
    }
}

#[test]
fn emit_include_bytes_module_rejects_duplicate_const_names() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let module = dir.path().join("fixtures.rs");

    // Two fixtures whose `id` values normalize to the same upper-snake constant
    // name (`KEY_A`), forcing the duplicate-name path.
    let manifest = manifest_with(vec![
        MaterializeFixtureSpec {
            id: Some("key-a".to_string()),
            out: PathBuf::from("key_a.bin"),
            kind: MaterializeKind::EntropyBytes,
            seed: "dup-emit-seed".to_string(),
            label: None,
            len: Some(8),
        },
        MaterializeFixtureSpec {
            id: Some("key.a".to_string()),
            out: PathBuf::from("key_a_other.bin"),
            kind: MaterializeKind::EntropyBytes,
            seed: "dup-emit-seed".to_string(),
            label: None,
            len: Some(8),
        },
    ]);

    let result = emit_include_bytes_module(&manifest, dir.path(), &module);
    match result {
        Err(uselesskey_cli::MaterializeError::InvalidManifest(msg)) => {
            ensure!(
                msg.contains("duplicate") && msg.contains("KEY_A"),
                "duplicate constant error should name the conflicting symbol, got: {msg}"
            );
            Ok(())
        }
        other => Err(uselesskey_test_support::TestError(format!(
            "expected InvalidManifest duplicate error, got {other:?}"
        ))),
    }
}

#[test]
fn emit_include_bytes_module_prefixes_underscore_for_digit_leading_id() -> TestResult<()> {
    let dir = require_ok(tempdir(), "tempdir")?;
    let out_dir = dir.path().join("out");
    let module = dir.path().join("fixtures.rs");

    let manifest = manifest_with(vec![MaterializeFixtureSpec {
        // Digit-leading id should produce a leading underscore constant.
        id: Some("2fa-secret".to_string()),
        out: PathBuf::from("two-fa.bin"),
        kind: MaterializeKind::EntropyBytes,
        seed: "digit-prefix-seed".to_string(),
        label: None,
        len: Some(8),
    }]);

    require_ok(
        emit_include_bytes_module(&manifest, &out_dir, &module),
        "emit module",
    )?;

    let emitted = require_ok(fs::read_to_string(&module), "read emitted module")?;
    ensure!(
        emitted.contains("pub const _2FA_SECRET: &[u8]"),
        "digit-leading id should prefix `_` to the emitted constant, got:\n{emitted}"
    );
    Ok(())
}
