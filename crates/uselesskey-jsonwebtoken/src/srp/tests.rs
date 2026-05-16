use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-jsonwebtoken-inline-test-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}

#[cfg(feature = "rsa")]
mod rsa_tests {
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_core::Factory;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    use crate::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_rsa_sign_and_verify() {
        let fx = super::fx();
        let keypair = fx.rsa("test-issuer", RsaSpec::rs256());

        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_rsa_deterministic_keys_work() {
        use uselesskey_core::Seed;

        let seed = Seed::from_env_value("test-seed").unwrap();
        let fx = Factory::deterministic(seed);
        let keypair = fx.rsa("deterministic-issuer", RsaSpec::rs256());

        let claims = TestClaims {
            sub: "det-user".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_tests {
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_core::Factory;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    use crate::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_ecdsa_es256_sign_and_verify() {
        let fx = Factory::random();
        let keypair = fx.ecdsa("test-issuer", EcdsaSpec::es256());

        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::ES256);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_ecdsa_es384_sign_and_verify() {
        let fx = Factory::random();
        let keypair = fx.ecdsa("test-issuer", EcdsaSpec::es384());

        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::ES384);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::ES384);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_tests {
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_core::Factory;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    use crate::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let fx = Factory::random();
        let keypair = fx.ed25519("test-issuer", Ed25519Spec::new());

        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::EdDSA);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }
}

#[cfg(feature = "ecdsa")]
mod cross_key_tests {
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_core::Factory;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    use crate::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_cross_key_decode_fails() {
        let fx = Factory::random();
        let key_a = fx.ecdsa("issuer-a", EcdsaSpec::es256());
        let key_b = fx.ecdsa("issuer-b", EcdsaSpec::es256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 2_000_000_000,
        };

        let token = encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &key_a.encoding_key(),
        )
        .unwrap();

        let result = decode::<TestClaims>(
            &token,
            &key_b.decoding_key(),
            &Validation::new(Algorithm::ES256),
        );
        assert!(result.is_err(), "decoding with wrong key should fail");
    }
}

#[cfg(feature = "hmac")]
mod hmac_tests {
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_core::Factory;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    use crate::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    #[test]
    fn test_hmac_hs256_sign_and_verify() {
        let fx = Factory::random();
        let secret = fx.hmac("test-secret", HmacSpec::hs256());

        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<TestClaims>(&token, &secret.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_hmac_hs384_sign_and_verify() {
        let fx = Factory::random();
        let secret = fx.hmac("test-secret", HmacSpec::hs384());

        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::HS384);
        let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::HS384);
        let decoded = decode::<TestClaims>(&token, &secret.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_hmac_hs512_sign_and_verify() {
        let fx = Factory::random();
        let secret = fx.hmac("test-secret", HmacSpec::hs512());

        let claims = TestClaims {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
        };

        let header = Header::new(Algorithm::HS512);
        let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::HS512);
        let decoded = decode::<TestClaims>(&token, &secret.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }
}
