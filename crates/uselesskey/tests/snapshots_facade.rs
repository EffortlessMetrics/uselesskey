//! Insta snapshot tests exercising the **facade** (`uselesskey`) re-exports.
//!
//! Each key type is generated through the public facade API and snapshotted
//! with crypto material redacted so snapshots stay stable and leak-free.

mod testutil;

use testutil::fx;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn redact_jwk(val: &serde_json::Value, crypto_fields: &[&str]) -> serde_json::Value {
    let mut map = val.as_object().unwrap().clone();
    for key in crypto_fields {
        if map.contains_key(*key) {
            map.insert(
                (*key).to_string(),
                serde_json::Value::String("[REDACTED]".into()),
            );
        }
    }
    serde_json::Value::Object(map)
}

// ===========================================================================
// RSA
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_snapshots {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[test]
    fn snapshots_rsa_private_pem_structure() {
        let kp = fx().rsa("facade-rsa", RsaSpec::rs256());
        insta::assert_snapshot!(redact_pem(kp.private_key_pkcs8_pem()));
    }

    #[test]
    fn snapshots_rsa_public_pem_structure() {
        let kp = fx().rsa("facade-rsa", RsaSpec::rs256());
        insta::assert_snapshot!(redact_pem(kp.public_key_spki_pem()));
    }

    #[test]
    fn snapshots_rsa_der_lengths() {
        let fx = fx();
        let rs256 = fx.rsa("facade-rsa", RsaSpec::rs256());

        let info = serde_json::json!({
            "private_der_len": rs256.private_key_pkcs8_der().len(),
            "public_der_len": rs256.public_key_spki_der().len(),
        });
        insta::assert_yaml_snapshot!("rsa_der_lengths", info);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn snapshots_rsa_public_jwk_structure() {
        let kp = fx().rsa("facade-rsa", RsaSpec::rs256());
        let jwk = kp.public_jwk_json();
        let redacted = redact_jwk(&jwk, &["n", "e", "kid"]);
        insta::assert_yaml_snapshot!(redacted);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn snapshots_rsa_private_jwk_structure() {
        let kp = fx().rsa("facade-rsa", RsaSpec::rs256());
        let jwk = kp.private_key_jwk_json();
        let redacted = redact_jwk(&jwk, &["n", "e", "d", "p", "q", "dp", "dq", "qi", "kid"]);
        insta::assert_yaml_snapshot!(redacted);
    }
}

// ===========================================================================
// ECDSA
// ===========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_snapshots {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn snapshots_ecdsa_es256_private_pem_structure() {
        let kp = fx().ecdsa("facade-ecdsa", EcdsaSpec::es256());
        insta::assert_snapshot!(redact_pem(kp.private_key_pkcs8_pem()));
    }

    #[test]
    fn snapshots_ecdsa_es256_public_pem_structure() {
        let kp = fx().ecdsa("facade-ecdsa", EcdsaSpec::es256());
        insta::assert_snapshot!(redact_pem(kp.public_key_spki_pem()));
    }

    #[test]
    fn snapshots_ecdsa_es384_private_pem_structure() {
        let kp = fx().ecdsa("facade-ecdsa", EcdsaSpec::es384());
        insta::assert_snapshot!(redact_pem(kp.private_key_pkcs8_pem()));
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn snapshots_ecdsa_es256_public_jwk_structure() {
        let kp = fx().ecdsa("facade-ecdsa", EcdsaSpec::es256());
        let jwk = kp.public_jwk().to_value();
        let redacted = redact_jwk(&jwk, &["x", "y", "kid"]);
        insta::assert_yaml_snapshot!(redacted);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn snapshots_ecdsa_es256_private_jwk_structure() {
        let kp = fx().ecdsa("facade-ecdsa", EcdsaSpec::es256());
        let jwk = kp.private_key_jwk().to_value();
        let redacted = redact_jwk(&jwk, &["x", "y", "d", "kid"]);
        insta::assert_yaml_snapshot!(redacted);
    }
}

// ===========================================================================
// Ed25519
// ===========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_snapshots {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn snapshots_ed25519_private_pem_structure() {
        let kp = fx().ed25519("facade-ed25519", Ed25519Spec::new());
        insta::assert_snapshot!(redact_pem(kp.private_key_pkcs8_pem()));
    }

    #[test]
    fn snapshots_ed25519_public_pem_structure() {
        let kp = fx().ed25519("facade-ed25519", Ed25519Spec::new());
        insta::assert_snapshot!(redact_pem(kp.public_key_spki_pem()));
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn snapshots_ed25519_public_jwk_structure() {
        let kp = fx().ed25519("facade-ed25519", Ed25519Spec::new());
        let jwk = kp.public_jwk().to_value();
        let redacted = redact_jwk(&jwk, &["x", "kid"]);
        insta::assert_yaml_snapshot!(redacted);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn snapshots_ed25519_private_jwk_structure() {
        let kp = fx().ed25519("facade-ed25519", Ed25519Spec::new());
        let jwk = kp.private_key_jwk().to_value();
        let redacted = redact_jwk(&jwk, &["x", "d", "kid"]);
        insta::assert_yaml_snapshot!(redacted);
    }
}

// ===========================================================================
// HMAC
// ===========================================================================

#[cfg(feature = "hmac")]
mod hmac_snapshots {
    use super::*;
    use uselesskey::{HmacFactoryExt, HmacSpec};

    #[test]
    fn snapshots_hmac_byte_lengths() {
        let fx = fx();
        let hs256 = fx.hmac("facade-hmac", HmacSpec::hs256());
        let hs384 = fx.hmac("facade-hmac", HmacSpec::hs384());
        let hs512 = fx.hmac("facade-hmac", HmacSpec::hs512());

        let info = serde_json::json!({
            "hs256_len": hs256.secret_bytes().len(),
            "hs384_len": hs384.secret_bytes().len(),
            "hs512_len": hs512.secret_bytes().len(),
        });
        insta::assert_yaml_snapshot!("hmac_byte_lengths", info);
    }

    #[cfg(feature = "jwk")]
    #[test]
    fn snapshots_hmac_hs256_jwk_structure() {
        let secret = fx().hmac("facade-hmac", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();

        insta::with_settings!({
            description => "HS256 JWK via facade — redact secret, keep shape",
        }, {
            insta::assert_yaml_snapshot!("hmac_hs256_jwk", jwk, {
                ".k" => "[secret]",
                ".kid" => "[kid]",
            });
        });
    }
}

// ===========================================================================
// Token
// ===========================================================================

#[cfg(feature = "token")]
mod token_snapshots {
    use super::*;
    use uselesskey::{TokenFactoryExt, TokenSpec};

    #[test]
    fn snapshots_token_api_key_shape() {
        let token = fx().token("facade-token", TokenSpec::api_key());
        let value = token.value();

        let info = serde_json::json!({
            "prefix": &value[.."uk_test_".len()],
            "suffix_len": value["uk_test_".len()..].len(),
            "total_len": value.len(),
        });
        insta::assert_yaml_snapshot!("token_api_key_shape", info);
    }

    #[test]
    fn snapshots_token_bearer_shape() {
        let token = fx().token("facade-token", TokenSpec::bearer());
        let value = token.value();

        let info = serde_json::json!({
            "len": value.len(),
            "auth_header_prefix": &token.authorization_header()[..7],
        });
        insta::assert_yaml_snapshot!("token_bearer_shape", info);
    }
}

// ===========================================================================
// PGP
// ===========================================================================

#[cfg(feature = "pgp")]
mod pgp_snapshots {
    use super::*;
    use uselesskey::{PgpFactoryExt, PgpSpec};

    fn redact_armor(armor: &str) -> String {
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

    #[test]
    fn snapshots_pgp_ed25519_private_armor_structure() {
        let kp = fx().pgp("facade-pgp", PgpSpec::ed25519());
        insta::assert_snapshot!(redact_armor(kp.private_key_armored()));
    }

    #[test]
    fn snapshots_pgp_ed25519_public_armor_structure() {
        let kp = fx().pgp("facade-pgp", PgpSpec::ed25519());
        insta::assert_snapshot!(redact_armor(kp.public_key_armored()));
    }

    #[test]
    fn snapshots_pgp_metadata() {
        let kp = fx().pgp("facade-pgp", PgpSpec::ed25519());
        insta::assert_yaml_snapshot!(
            "pgp_ed25519_metadata",
            serde_json::json!({
                "spec": kp.spec().kind_name(),
                "user_id": kp.user_id(),
                "fingerprint_len": kp.fingerprint().len(),
            })
        );
    }
}

// ===========================================================================
// Cross-type determinism
// ===========================================================================

#[test]
fn snapshots_determinism_across_types() {
    let fx1 = fx();
    let fx2 = fx();

    let mut checks = serde_json::Map::new();

    #[cfg(feature = "rsa")]
    {
        use uselesskey::{RsaFactoryExt, RsaSpec};
        let a = fx1.rsa("det-check", RsaSpec::rs256());
        let b = fx2.rsa("det-check", RsaSpec::rs256());
        checks.insert(
            "rsa_stable".into(),
            serde_json::Value::Bool(a.private_key_pkcs8_pem() == b.private_key_pkcs8_pem()),
        );
    }

    #[cfg(feature = "ecdsa")]
    {
        use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
        let a = fx1.ecdsa("det-check", EcdsaSpec::es256());
        let b = fx2.ecdsa("det-check", EcdsaSpec::es256());
        checks.insert(
            "ecdsa_stable".into(),
            serde_json::Value::Bool(a.private_key_pkcs8_pem() == b.private_key_pkcs8_pem()),
        );
    }

    #[cfg(feature = "ed25519")]
    {
        use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
        let a = fx1.ed25519("det-check", Ed25519Spec::new());
        let b = fx2.ed25519("det-check", Ed25519Spec::new());
        checks.insert(
            "ed25519_stable".into(),
            serde_json::Value::Bool(a.private_key_pkcs8_pem() == b.private_key_pkcs8_pem()),
        );
    }

    #[cfg(feature = "hmac")]
    {
        use uselesskey::{HmacFactoryExt, HmacSpec};
        let a = fx1.hmac("det-check", HmacSpec::hs256());
        let b = fx2.hmac("det-check", HmacSpec::hs256());
        checks.insert(
            "hmac_stable".into(),
            serde_json::Value::Bool(a.secret_bytes() == b.secret_bytes()),
        );
    }

    #[cfg(feature = "token")]
    {
        use uselesskey::{TokenFactoryExt, TokenSpec};
        let a = fx1.token("det-check", TokenSpec::api_key());
        let b = fx2.token("det-check", TokenSpec::api_key());
        checks.insert(
            "token_stable".into(),
            serde_json::Value::Bool(a.value() == b.value()),
        );
    }

    #[cfg(feature = "pgp")]
    {
        use uselesskey::{PgpFactoryExt, PgpSpec};
        let a = fx1.pgp("det-check", PgpSpec::ed25519());
        let b = fx2.pgp("det-check", PgpSpec::ed25519());
        checks.insert(
            "pgp_stable".into(),
            serde_json::Value::Bool(a.private_key_armored() == b.private_key_armored()),
        );
    }

    insta::assert_yaml_snapshot!(
        "determinism_across_types",
        serde_json::Value::Object(checks)
    );
}
