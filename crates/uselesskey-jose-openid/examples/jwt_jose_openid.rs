use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_jose_openid::JoseOpenIdKeyExt;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
}

fn main() {
    let fx = Factory::random();
    let key = fx.ecdsa("uselesskey-demo", EcdsaSpec::es256());

    let claims = Claims {
        iss: "example-issuer".into(),
        aud: "example-client".into(),
    };

    let token = encode(&Header::new(Algorithm::ES256), &claims, &key.encoding_key())
        .expect("token should be signed");

    let claims = decode::<Claims>(
        &token,
        &key.decoding_key(),
        &Validation::new(Algorithm::ES256),
    )
    .expect("token should be verified")
    .claims;

    println!("issuer={}", claims.iss);
}
