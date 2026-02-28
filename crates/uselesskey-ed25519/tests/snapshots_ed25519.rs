use uselesskey_core::{Factory, Seed};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

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
    Factory::deterministic(Seed::from_env_value("snapshot-ed25519").unwrap())
}

#[test]
fn snapshot_ed25519_private_pem_structure() {
    let fx = factory();
    let key = fx.ed25519("issuer", Ed25519Spec::new());
    let redacted = redact_pem_body(key.private_key_pkcs8_pem());
    insta::assert_snapshot!(redacted);
}

#[test]
fn snapshot_ed25519_public_pem_structure() {
    let fx = factory();
    let key = fx.ed25519("issuer", Ed25519Spec::new());
    let redacted = redact_pem_body(key.public_key_spki_pem());
    insta::assert_snapshot!(redacted);
}

#[cfg(feature = "jwk")]
mod jwk_snapshots {
    use super::*;

    fn redact_jwk(val: &serde_json::Value) -> serde_json::Value {
        let mut map = val.as_object().unwrap().clone();
        for key in ["x", "d", "kid"] {
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
    fn snapshot_ed25519_public_jwk_structure() {
        let fx = factory();
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwk = key.public_jwk().to_value();
        let redacted = redact_jwk(&jwk);
        insta::assert_yaml_snapshot!(redacted);
    }

    #[test]
    fn snapshot_ed25519_private_jwk_structure() {
        let fx = factory();
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwk = key.private_key_jwk().to_value();
        let redacted = redact_jwk(&jwk);
        insta::assert_yaml_snapshot!(redacted);
    }
}
