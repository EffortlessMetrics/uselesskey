use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_jose_openid::JoseOpenIdKeyExt;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    preferred_username: String,
}

fn relaxed_validation(algorithm: Algorithm) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.required_spec_claims = std::collections::HashSet::new();
    validation
}

#[test]
fn integration_flow_matches_jose_verification() {
    let fx = Factory::random();
    let key = fx.ecdsa("tenant-a", EcdsaSpec::es384());

    let claims = Claims {
        preferred_username: "demo-user".into(),
    };

    let token =
        encode(&Header::new(Algorithm::ES384), &claims, &key.encoding_key()).expect("sign token");

    let decoded = decode::<Claims>(
        &token,
        &key.decoding_key(),
        &relaxed_validation(Algorithm::ES384),
    )
    .expect("verify token");

    assert_eq!(decoded.claims.preferred_username, "demo-user");
}
