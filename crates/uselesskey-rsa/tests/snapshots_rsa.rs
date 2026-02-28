//! Insta snapshot tests for RSA key fixtures.
//!
//! These tests capture the *structure* of PEM and JWK outputs while redacting
//! actual cryptographic material so snapshots remain stable and leak-free.

use serde_json::Value;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

fn factory() -> Factory {
    let seed = Seed::from_env_value("snapshot-rsa-seed-v1").expect("test seed");
    Factory::deterministic(seed)
}

/// Replace base64 body lines in a PEM string with "[REDACTED]", preserving headers.
fn redact_pem(pem: &str) -> String {
    pem.lines()
        .map(|line| {
            if line.starts_with("-----") {
                line.to_string()
            } else {
                "[REDACTED]".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Redact large base64 crypto values in a JWK JSON value, keeping structural fields.
fn redact_jwk(mut v: Value) -> Value {
    let crypto_fields = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];
    if let Some(obj) = v.as_object_mut() {
        for field in &crypto_fields {
            if obj.contains_key(*field) {
                obj.insert((*field).to_string(), Value::String("[REDACTED]".into()));
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------
// PEM structure snapshots
// ---------------------------------------------------------------------------

#[test]
fn snapshot_rs256_private_pem_structure() {
    let fx = factory();
    let kp = fx.rsa("snapshot-rs256", RsaSpec::rs256());
    let redacted = redact_pem(kp.private_key_pkcs8_pem());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_rs256_public_pem_structure() {
    let fx = factory();
    let kp = fx.rsa("snapshot-rs256", RsaSpec::rs256());
    let redacted = redact_pem(kp.public_key_spki_pem());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_rs384_private_pem_structure() {
    let fx = factory();
    let kp = fx.rsa("snapshot-rs384", RsaSpec::new(3072));
    let redacted = redact_pem(kp.private_key_pkcs8_pem());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_rs512_private_pem_structure() {
    let fx = factory();
    let kp = fx.rsa("snapshot-rs512", RsaSpec::new(4096));
    let redacted = redact_pem(kp.private_key_pkcs8_pem());
    insta::assert_snapshot!(redacted);
}

// ---------------------------------------------------------------------------
// JWK structure snapshots (require "jwk" feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
mod jwk_snapshots {
    use super::*;

    #[test]
    fn snapshot_rs256_public_jwk_structure() {
        let fx = factory();
        let kp = fx.rsa("snapshot-rs256", RsaSpec::rs256());
        let jwk = redact_jwk(kp.public_jwk_json());
        insta::assert_yaml_snapshot!(jwk);
    }

    #[test]
    fn snapshot_rs256_private_jwk_structure() {
        let fx = factory();
        let kp = fx.rsa("snapshot-rs256", RsaSpec::rs256());
        let jwk = redact_jwk(kp.private_key_jwk_json());
        insta::assert_yaml_snapshot!(jwk);
    }

    #[test]
    fn snapshot_rs384_public_jwk_structure() {
        let fx = factory();
        let kp = fx.rsa("snapshot-rs384", RsaSpec::new(3072));
        let jwk = redact_jwk(kp.public_jwk_json());
        insta::assert_yaml_snapshot!(jwk);
    }

    #[test]
    fn snapshot_rs512_public_jwk_structure() {
        let fx = factory();
        let kp = fx.rsa("snapshot-rs512", RsaSpec::new(4096));
        let jwk = redact_jwk(kp.public_jwk_json());
        insta::assert_yaml_snapshot!(jwk);
    }

    // -----------------------------------------------------------------------
    // Key metadata snapshots
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_rs256_metadata() {
        let fx = factory();
        let kp = fx.rsa("snapshot-rs256", RsaSpec::rs256());
        let kid = kp.kid();
        let jwk = kp.public_jwk_json();
        let alg = jwk["alg"].as_str().unwrap();
        let kty = jwk["kty"].as_str().unwrap();
        let use_ = jwk["use"].as_str().unwrap();
        insta::assert_yaml_snapshot!(
            "rs256-metadata",
            serde_json::json!({
                "kid": kid,
                "alg": alg,
                "kty": kty,
                "use": use_,
            })
        );
    }

    #[test]
    fn snapshot_rs384_metadata() {
        let fx = factory();
        let kp = fx.rsa("snapshot-rs384", RsaSpec::new(3072));
        let kid = kp.kid();
        let jwk = kp.public_jwk_json();
        let alg = jwk["alg"].as_str().unwrap();
        let kty = jwk["kty"].as_str().unwrap();
        let use_ = jwk["use"].as_str().unwrap();
        insta::assert_yaml_snapshot!(
            "rs384-metadata",
            serde_json::json!({
                "kid": kid,
                "alg": alg,
                "kty": kty,
                "use": use_,
            })
        );
    }

    #[test]
    fn snapshot_rs512_metadata() {
        let fx = factory();
        let kp = fx.rsa("snapshot-rs512", RsaSpec::new(4096));
        let kid = kp.kid();
        let jwk = kp.public_jwk_json();
        let alg = jwk["alg"].as_str().unwrap();
        let kty = jwk["kty"].as_str().unwrap();
        let use_ = jwk["use"].as_str().unwrap();
        insta::assert_yaml_snapshot!(
            "rs512-metadata",
            serde_json::json!({
                "kid": kid,
                "alg": alg,
                "kty": kty,
                "use": use_,
            })
        );
    }
}
