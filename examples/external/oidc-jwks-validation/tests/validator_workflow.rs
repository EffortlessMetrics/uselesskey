use serde_json::json;
use uselesskey::jwk::{NegativeJwk, NegativeJwks};
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
use uselesskey_external_oidc_jwks_validation::{JwksValidationError, validate_oidc_jwks};

fn issuer() -> uselesskey::RsaKeyPair {
    let fx = Factory::deterministic_from_str("external-oidc-jwks");
    fx.rsa("issuer", RsaSpec::rs256())
}

#[test]
fn accepts_valid_jwks() {
    let jwks = issuer().public_jwks().to_value();

    assert_eq!(validate_oidc_jwks(&jwks), Ok(()));
}

#[test]
fn rejects_duplicate_kid() {
    let jwks = issuer()
        .public_jwks()
        .negative_value(NegativeJwks::DuplicateKid);

    assert_eq!(
        validate_oidc_jwks(&jwks),
        Err(JwksValidationError::DuplicateKid)
    );
}

#[test]
fn rejects_wrong_kty() {
    let key = issuer().public_jwk().negative_value(NegativeJwk::WrongKty);
    let jwks = json!({ "keys": [key] });

    assert_eq!(
        validate_oidc_jwks(&jwks),
        Err(JwksValidationError::WrongKty)
    );
}

#[test]
fn rejects_unsupported_alg() {
    let key = issuer()
        .public_jwk()
        .negative_value(NegativeJwk::UnsupportedAlg);
    let jwks = json!({ "keys": [key] });

    assert_eq!(
        validate_oidc_jwks(&jwks),
        Err(JwksValidationError::UnsupportedAlg)
    );
}

#[test]
fn rejects_missing_kid() {
    let jwks = issuer()
        .public_jwks()
        .negative_value(NegativeJwks::MissingKid);

    assert_eq!(
        validate_oidc_jwks(&jwks),
        Err(JwksValidationError::MissingKid)
    );
}
