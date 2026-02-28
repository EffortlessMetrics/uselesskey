use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

fn redact_pem_body(pem: &str) -> String {
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

fn factory() -> Factory {
    Factory::deterministic(Seed::from_env_value("snapshot-ecdsa").unwrap())
}

#[test]
fn snapshot_es256_private_pem_structure() {
    let fx = factory();
    let key = fx.ecdsa("issuer", EcdsaSpec::es256());
    let redacted = redact_pem_body(key.private_key_pkcs8_pem());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_es256_public_pem_structure() {
    let fx = factory();
    let key = fx.ecdsa("issuer", EcdsaSpec::es256());
    let redacted = redact_pem_body(key.public_key_spki_pem());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_es384_private_pem_structure() {
    let fx = factory();
    let key = fx.ecdsa("issuer", EcdsaSpec::es384());
    let redacted = redact_pem_body(key.private_key_pkcs8_pem());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_es384_public_pem_structure() {
    let fx = factory();
    let key = fx.ecdsa("issuer", EcdsaSpec::es384());
    let redacted = redact_pem_body(key.public_key_spki_pem());
    insta::assert_snapshot!(redacted);
}

#[cfg(feature = "jwk")]
mod jwk_snapshots {
    use super::*;

    fn redact_jwk(val: &serde_json::Value) -> serde_json::Value {
        let mut map = val.as_object().unwrap().clone();
        for key in ["x", "y", "d", "kid"] {
            if map.contains_key(key) {
                map.insert(
                    key.to_string(),
                    serde_json::Value::String("[REDACTED]".into()),
                );
            }
        }
        serde_json::Value::Object(map)
    }

    #[test]
    fn snapshot_es256_public_jwk_structure() {
        let fx = factory();
        let key = fx.ecdsa("issuer", EcdsaSpec::es256());
        let jwk = key.public_jwk().to_value();
        let redacted = redact_jwk(&jwk);
        insta::assert_yaml_snapshot!(redacted);
    }

    #[test]
    fn snapshot_es256_private_jwk_structure() {
        let fx = factory();
        let key = fx.ecdsa("issuer", EcdsaSpec::es256());
        let jwk = key.private_key_jwk().to_value();
        let redacted = redact_jwk(&jwk);
        insta::assert_yaml_snapshot!(redacted);
    }

    #[test]
    fn snapshot_es384_public_jwk_structure() {
        let fx = factory();
        let key = fx.ecdsa("issuer", EcdsaSpec::es384());
        let jwk = key.public_jwk().to_value();
        let redacted = redact_jwk(&jwk);
        insta::assert_yaml_snapshot!(redacted);
    }

    #[test]
    fn snapshot_es384_private_jwk_structure() {
        let fx = factory();
        let key = fx.ecdsa("issuer", EcdsaSpec::es384());
        let jwk = key.private_key_jwk().to_value();
        let redacted = redact_jwk(&jwk);
        insta::assert_yaml_snapshot!(redacted);
    }
}
