use std::collections::BTreeSet;

use serde_json::Value;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JwksValidationError {
    MissingKeys,
    EmptyKeys,
    MissingKid,
    DuplicateKid,
    WrongKty,
    UnsupportedAlg,
    MissingMaterial,
}

pub fn validate_oidc_jwks(jwks: &Value) -> Result<(), JwksValidationError> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(JwksValidationError::MissingKeys)?;
    if keys.is_empty() {
        return Err(JwksValidationError::EmptyKeys);
    }

    let mut kids = BTreeSet::new();
    for key in keys {
        let kid = key
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.is_empty())
            .ok_or(JwksValidationError::MissingKid)?;
        if !kids.insert(kid.to_string()) {
            return Err(JwksValidationError::DuplicateKid);
        }

        if key.get("kty").and_then(Value::as_str) != Some("RSA") {
            return Err(JwksValidationError::WrongKty);
        }
        if key.get("alg").and_then(Value::as_str) != Some("RS256") {
            return Err(JwksValidationError::UnsupportedAlg);
        }
        if key.get("n").and_then(Value::as_str).is_none()
            || key.get("e").and_then(Value::as_str).is_none()
        {
            return Err(JwksValidationError::MissingMaterial);
        }
    }

    Ok(())
}
