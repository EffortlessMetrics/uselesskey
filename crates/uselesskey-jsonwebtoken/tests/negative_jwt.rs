//! Negative fixture JWT tests.
//!
//! Verifies that negative fixtures (mismatched keys) fail JWT
//! signature validation when used via the jsonwebtoken adapter.

mod testutil;

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use testutil::fx;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn test_claims() -> Claims {
    Claims {
        sub: "negative-fixture-test".into(),
        exp: 2_000_000_000,
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_negative {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn mismatched_ecdsa_key_rejects_jwt_es256() {
        let fx = fx();
        let kp = fx.ecdsa("jwt-neg-mm-256", EcdsaSpec::es256());

        let token = encode(
            &Header::new(Algorithm::ES256),
            &test_claims(),
            &kp.encoding_key(),
        )
        .unwrap();

        let mm_der = kp.mismatched_public_key_spki_der();
        let mm_key = DecodingKey::from_ec_der(&mm_der);

        let result = decode::<Claims>(&token, &mm_key, &Validation::new(Algorithm::ES256));
        assert!(result.is_err(), "Mismatched ECDSA key should reject JWT");
    }

    #[test]
    fn mismatched_ecdsa_key_rejects_jwt_es384() {
        let fx = fx();
        let kp = fx.ecdsa("jwt-neg-mm-384", EcdsaSpec::es384());

        let token = encode(
            &Header::new(Algorithm::ES384),
            &test_claims(),
            &kp.encoding_key(),
        )
        .unwrap();

        let mm_der = kp.mismatched_public_key_spki_der();
        let mm_key = DecodingKey::from_ec_der(&mm_der);

        let result = decode::<Claims>(&token, &mm_key, &Validation::new(Algorithm::ES384));
        assert!(result.is_err(), "Mismatched ECDSA key should reject JWT");
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_negative {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn mismatched_ed25519_key_rejects_jwt() {
        let fx = fx();
        let kp = fx.ed25519("jwt-neg-mm-ed", Ed25519Spec::new());

        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &test_claims(),
            &kp.encoding_key(),
        )
        .unwrap();

        let mm_der = kp.mismatched_public_key_spki_der();
        let mm_key = DecodingKey::from_ed_der(&mm_der);

        let result = decode::<Claims>(&token, &mm_key, &Validation::new(Algorithm::EdDSA));
        assert!(result.is_err(), "Mismatched Ed25519 key should reject JWT");
    }
}
