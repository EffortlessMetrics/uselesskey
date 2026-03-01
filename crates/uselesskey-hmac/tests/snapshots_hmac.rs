//! Insta snapshot tests for uselesskey-hmac.
//!
//! These tests snapshot HMAC secret metadata to detect
//! unintended changes in deterministic HMAC key generation.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

#[derive(Serialize)]
struct HmacSnapshot {
    label: &'static str,
    algorithm: &'static str,
    secret_len: usize,
}

#[test]
fn snapshot_hmac_hs256() {
    let fx = fx();
    let key = fx.hmac("snapshot-hs256", HmacSpec::hs256());

    let result = HmacSnapshot {
        label: "snapshot-hs256",
        algorithm: "HS256",
        secret_len: key.secret_bytes().len(),
    };

    insta::assert_yaml_snapshot!("hmac_hs256_shape", result);
}

#[test]
fn snapshot_hmac_hs384() {
    let fx = fx();
    let key = fx.hmac("snapshot-hs384", HmacSpec::hs384());

    let result = HmacSnapshot {
        label: "snapshot-hs384",
        algorithm: "HS384",
        secret_len: key.secret_bytes().len(),
    };

    insta::assert_yaml_snapshot!("hmac_hs384_shape", result);
}

#[test]
fn snapshot_hmac_hs512() {
    let fx = fx();
    let key = fx.hmac("snapshot-hs512", HmacSpec::hs512());

    let result = HmacSnapshot {
        label: "snapshot-hs512",
        algorithm: "HS512",
        secret_len: key.secret_bytes().len(),
    };

    insta::assert_yaml_snapshot!("hmac_hs512_shape", result);
}

#[test]
fn snapshot_hmac_secret_sizes() {
    #[derive(Serialize)]
    struct HmacSizeInfo {
        algorithm: &'static str,
        expected_bytes: usize,
        actual_bytes: usize,
    }

    let fx = fx();
    let sizes: Vec<HmacSizeInfo> = vec![
        {
            let k = fx.hmac("sizes-hs256", HmacSpec::hs256());
            HmacSizeInfo {
                algorithm: "HS256",
                expected_bytes: 32,
                actual_bytes: k.secret_bytes().len(),
            }
        },
        {
            let k = fx.hmac("sizes-hs384", HmacSpec::hs384());
            HmacSizeInfo {
                algorithm: "HS384",
                expected_bytes: 48,
                actual_bytes: k.secret_bytes().len(),
            }
        },
        {
            let k = fx.hmac("sizes-hs512", HmacSpec::hs512());
            HmacSizeInfo {
                algorithm: "HS512",
                expected_bytes: 64,
                actual_bytes: k.secret_bytes().len(),
            }
        },
    ];

    insta::assert_yaml_snapshot!("hmac_secret_sizes", sizes);
}
