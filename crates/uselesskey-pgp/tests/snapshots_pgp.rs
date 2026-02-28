//! Insta snapshot tests for PGP key fixtures.
//!
//! These tests capture the *structure* of PGP armor outputs while redacting
//! actual cryptographic material so snapshots remain stable and leak-free.

use uselesskey_core::{Factory, Seed};
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

fn factory() -> Factory {
    Factory::deterministic(Seed::from_env_value("snapshot-pgp-seed-v1").unwrap())
}

/// Replace base64 body lines in an armored PGP block with "[REDACTED]",
/// preserving header/footer markers and any armor headers (e.g. "Version:").
fn redact_armor_body(armor: &str) -> String {
    armor
        .lines()
        .map(|line| {
            if line.starts_with("-----") || line.contains(':') || line.is_empty() {
                line.to_string()
            } else {
                "[REDACTED]".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Ed25519 armor structure
// ---------------------------------------------------------------------------

#[test]
fn snapshot_ed25519_private_armor_structure() {
    let fx = factory();
    let key = fx.pgp("snapshot-ed25519", PgpSpec::ed25519());
    let redacted = redact_armor_body(key.private_key_armored());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_ed25519_public_armor_structure() {
    let fx = factory();
    let key = fx.pgp("snapshot-ed25519", PgpSpec::ed25519());
    let redacted = redact_armor_body(key.public_key_armored());
    insta::assert_snapshot!(redacted);
}

// ---------------------------------------------------------------------------
// RSA 2048 armor structure
// ---------------------------------------------------------------------------

#[test]
fn snapshot_rsa2048_private_armor_structure() {
    let fx = factory();
    let key = fx.pgp("snapshot-rsa2048", PgpSpec::rsa_2048());
    let redacted = redact_armor_body(key.private_key_armored());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_rsa2048_public_armor_structure() {
    let fx = factory();
    let key = fx.pgp("snapshot-rsa2048", PgpSpec::rsa_2048());
    let redacted = redact_armor_body(key.public_key_armored());
    insta::assert_snapshot!(redacted);
}

// ---------------------------------------------------------------------------
// Fingerprint format
// ---------------------------------------------------------------------------

#[test]
fn snapshot_ed25519_fingerprint_format() {
    let fx = factory();
    let key = fx.pgp("snapshot-ed25519", PgpSpec::ed25519());
    let fp = key.fingerprint();
    // V4 fingerprints are 40 hex characters
    insta::assert_yaml_snapshot!(
        "ed25519-fingerprint-format",
        serde_json::json!({
            "length": fp.len(),
            "all_hex": fp.chars().all(|c| c.is_ascii_hexdigit()),
        })
    );
}

#[test]
fn snapshot_rsa2048_fingerprint_format() {
    let fx = factory();
    let key = fx.pgp("snapshot-rsa2048", PgpSpec::rsa_2048());
    let fp = key.fingerprint();
    insta::assert_yaml_snapshot!(
        "rsa2048-fingerprint-format",
        serde_json::json!({
            "length": fp.len(),
            "all_hex": fp.chars().all(|c| c.is_ascii_hexdigit()),
        })
    );
}

// ---------------------------------------------------------------------------
// Metadata snapshots (user_id, spec, fingerprint format)
// ---------------------------------------------------------------------------

#[test]
fn snapshot_ed25519_metadata() {
    let fx = factory();
    let key = fx.pgp("snapshot-ed25519", PgpSpec::ed25519());
    insta::assert_yaml_snapshot!(
        "ed25519-metadata",
        serde_json::json!({
            "spec": key.spec().kind_name(),
            "user_id": key.user_id(),
            "fingerprint_len": key.fingerprint().len(),
        })
    );
}

#[test]
fn snapshot_rsa2048_metadata() {
    let fx = factory();
    let key = fx.pgp("snapshot-rsa2048", PgpSpec::rsa_2048());
    insta::assert_yaml_snapshot!(
        "rsa2048-metadata",
        serde_json::json!({
            "spec": key.spec().kind_name(),
            "user_id": key.user_id(),
            "fingerprint_len": key.fingerprint().len(),
        })
    );
}
