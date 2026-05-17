use uselesskey::jwk::NegativeJwks;
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

#[test]
fn oidc_jwks_fixtures_cover_valid_and_negative_key_sets() {
    let fx = Factory::deterministic_from_str("external-oidc-jwks");
    let issuer = fx.rsa("issuer", RsaSpec::rs256());
    let jwks = issuer.public_jwks();
    let valid = jwks.to_value();

    let keys = valid["keys"].as_array();
    assert_eq!(keys.map(Vec::len), Some(1));
    assert_eq!(valid["keys"][0]["kty"], "RSA");
    assert!(valid["keys"][0]["kid"].as_str().is_some_and(|kid| !kid.is_empty()));

    let duplicate_kid = jwks.negative_value(NegativeJwks::DuplicateKid);
    let duplicate_keys = duplicate_kid["keys"].as_array();
    assert_eq!(duplicate_keys.map(Vec::len), Some(2));
    assert_eq!(duplicate_kid["keys"][0]["kid"], duplicate_kid["keys"][1]["kid"]);

    let missing_kid = jwks.negative_value(NegativeJwks::MissingKid);
    assert!(missing_kid["keys"][0].get("kid").is_none());
}
