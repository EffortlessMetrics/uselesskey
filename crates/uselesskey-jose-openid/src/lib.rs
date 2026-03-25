#![forbid(unsafe_code)]

//! JOSE/OpenID conversion traits for `uselesskey` key fixtures.
//!
//! This crate exposes narrowly-scoped helpers that convert fixture key/secret
//! objects into `jsonwebtoken` key material used by JOSE-style integrations.

use jsonwebtoken::{DecodingKey, EncodingKey};

/// Conversion surface for fixtures in JOSE/OpenID-friendly key representations.
pub trait JoseOpenIdKeyExt {
    /// Convert this fixture into a JOSE encoding key.
    fn encoding_key(&self) -> EncodingKey;

    /// Convert this fixture into a JOSE decoding key.
    fn decoding_key(&self) -> DecodingKey;
}

#[cfg(feature = "rsa")]
impl JoseOpenIdKeyExt for uselesskey_rsa::RsaKeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from RSA PKCS8")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_rsa_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from RSA SPKI")
    }
}

#[cfg(feature = "ecdsa")]
impl JoseOpenIdKeyExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ec_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from ECDSA PKCS8")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ec_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from ECDSA SPKI")
    }
}

#[cfg(feature = "ed25519")]
impl JoseOpenIdKeyExt for uselesskey_ed25519::Ed25519KeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ed_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from Ed25519 PKCS8")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ed_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from Ed25519 SPKI")
    }
}

#[cfg(feature = "hmac")]
impl JoseOpenIdKeyExt for uselesskey_hmac::HmacSecret {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(self.secret_bytes())
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.secret_bytes())
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_core::Factory;

    use super::JoseOpenIdKeyExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        scope: String,
    }

    fn relaxed_validation(algorithm: Algorithm) -> Validation {
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = false;
        validation.required_spec_claims = std::collections::HashSet::new();
        validation
    }

    #[test]
    fn rsa_sign_and_verify() {
        let fx = Factory::random();
        let keypair = fx.rsa("jwt-rsa", RsaSpec::rs256());

        let claims = TestClaims {
            sub: "alice".into(),
            scope: "openid profile email".into(),
        };

        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &keypair.encoding_key(),
        )
        .expect("sign token with RS256 fixture");

        let decoded = decode::<TestClaims>(
            &token,
            &keypair.decoding_key(),
            &relaxed_validation(Algorithm::RS256),
        )
        .expect("decode token with RS256 fixture");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn cross_algorithm_fail_on_mismatch() {
        let fx = Factory::random();
        let rsa = fx.rsa("iss-a", RsaSpec::rs256());
        let ecdsa = fx.ecdsa("iss-b", EcdsaSpec::es256());
        let claims = TestClaims {
            sub: "alice".into(),
            scope: "openid".into(),
        };

        let token = encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &ecdsa.encoding_key(),
        )
        .expect("sign token with ES256 fixture");

        let bad = decode::<TestClaims>(
            &token,
            &rsa.decoding_key(),
            &Validation::new(Algorithm::RS256),
        );
        assert!(bad.is_err(), "cross-family verification should fail");
    }

    #[cfg(feature = "hmac")]
    #[test]
    fn hmac_roundtrip() {
        use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

        let fx = Factory::random();
        let secret = fx.hmac("secret", HmacSpec::hs256());

        let claims = TestClaims {
            sub: "service".into(),
            scope: "read write".into(),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &secret.encoding_key(),
        )
        .expect("sign token with HS256 fixture");

        let decoded = decode::<TestClaims>(
            &token,
            &secret.decoding_key(),
            &relaxed_validation(Algorithm::HS256),
        )
        .expect("decode token with HS256 fixture");

        assert_eq!(decoded.claims, claims);

        let _ = secret.encoding_key();
        let _ = secret.decoding_key();
    }
}
