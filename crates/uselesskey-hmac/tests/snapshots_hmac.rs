//! Insta snapshot tests for uselesskey-hmac.
//!
//! These tests snapshot HMAC secret shapes and metadata to detect
//! unintended changes in deterministic HMAC generation.

mod testutil;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use testutil::fx;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

#[derive(Serialize)]
struct HmacSnapshot {
    label: &'static str,
    alg: &'static str,
    secret_len: usize,
    secret_b64: String,
}

#[test]
fn snapshot_hmac_hs256_shape() {
    let fx = fx();
    let secret = fx.hmac("snapshot-hs256", HmacSpec::hs256());

    let result = HmacSnapshot {
        label: "snapshot-hs256",
        alg: "HS256",
        secret_len: secret.secret_bytes().len(),
        secret_b64: STANDARD.encode(secret.secret_bytes()),
    };

    insta::assert_yaml_snapshot!("hmac_hs256_shape", result, {
        ".secret_b64" => "[REDACTED]",
    });
}

#[test]
fn snapshot_hmac_hs384_shape() {
    let fx = fx();
    let secret = fx.hmac("snapshot-hs384", HmacSpec::hs384());

    let result = HmacSnapshot {
        label: "snapshot-hs384",
        alg: "HS384",
        secret_len: secret.secret_bytes().len(),
        secret_b64: STANDARD.encode(secret.secret_bytes()),
    };

    insta::assert_yaml_snapshot!("hmac_hs384_shape", result, {
        ".secret_b64" => "[REDACTED]",
    });
}

#[test]
fn snapshot_hmac_hs512_shape() {
    let fx = fx();
    let secret = fx.hmac("snapshot-hs512", HmacSpec::hs512());

    let result = HmacSnapshot {
        label: "snapshot-hs512",
        alg: "HS512",
        secret_len: secret.secret_bytes().len(),
        secret_b64: STANDARD.encode(secret.secret_bytes()),
    };

    insta::assert_yaml_snapshot!("hmac_hs512_shape", result, {
        ".secret_b64" => "[REDACTED]",
    });
}

#[test]
fn snapshot_hmac_all_specs() {
    let fx = fx();

    #[derive(Serialize)]
    struct HmacSpecInfo {
        alg: &'static str,
        byte_len: usize,
        actual_secret_len: usize,
    }

    let specs: Vec<HmacSpecInfo> = [
        ("HS256", HmacSpec::hs256()),
        ("HS384", HmacSpec::hs384()),
        ("HS512", HmacSpec::hs512()),
    ]
    .into_iter()
    .map(|(alg, spec)| {
        let secret = fx.hmac("spec-test", spec.clone());
        HmacSpecInfo {
            alg,
            byte_len: spec.byte_len(),
            actual_secret_len: secret.secret_bytes().len(),
        }
    })
    .collect();

    insta::assert_yaml_snapshot!("hmac_all_specs", specs);
}
