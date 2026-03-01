//! Extended JWT adapter integration tests.
//!
//! Tests cover:
//! - All RSA algorithms (RS256, RS384, RS512, PS256, PS384, PS512)
//! - ECDSA algorithms (ES256, ES384)
//! - Ed25519 algorithm (EdDSA)
//! - Token creation and verification round-trips with complex claims
//! - Negative cases (wrong key for verification, algorithm family mismatch)

mod testutil;

use jsonwebtoken::{Algorithm, Header, Validation, decode, encode, errors::ErrorKind};
use serde::{Deserialize, Serialize};
use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_jsonwebtoken::JwtKeyExt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Vec<String>>,
}

impl Claims {
    fn standard() -> Self {
        Self {
            sub: "user-42".to_string(),
            exp: 2_000_000_000,
            iat: 1_700_000_000,
            iss: "uselesskey-test".to_string(),
            aud: "test-api".to_string(),
            scope: None,
            roles: None,
        }
    }

    fn with_scope(mut self, scope: &str) -> Self {
        self.scope = Some(scope.to_string());
        self
    }

    fn with_roles(mut self, roles: Vec<&str>) -> Self {
        self.roles = Some(roles.into_iter().map(String::from).collect());
        self
    }
}

fn sign_and_verify(
    alg: Algorithm,
    enc: &jsonwebtoken::EncodingKey,
    dec: &jsonwebtoken::DecodingKey,
) {
    let claims = Claims::standard();
    let header = Header::new(alg);
    let token = encode(&header, &claims, enc)
        .unwrap_or_else(|e| panic!("Failed to encode with {alg:?}: {e:?}"));

    let mut validation = Validation::new(alg);
    validation.set_audience(&["test-api"]);
    let decoded = decode::<Claims>(&token, dec, &validation)
        .unwrap_or_else(|e| panic!("Failed to decode with {alg:?}: {e:?}"));

    assert_eq!(decoded.claims, claims, "Claims mismatch for {alg:?}");
}

// =========================================================================
// RSA: All algorithms
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_all_algorithms {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rs256_round_trip() {
        let kp = fx().rsa("jwt-rs256", RsaSpec::rs256());
        sign_and_verify(Algorithm::RS256, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn rs384_round_trip() {
        let kp = fx().rsa("jwt-rs384", RsaSpec::rs256());
        sign_and_verify(Algorithm::RS384, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn rs512_round_trip() {
        let kp = fx().rsa("jwt-rs512", RsaSpec::rs256());
        sign_and_verify(Algorithm::RS512, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn ps256_round_trip() {
        let kp = fx().rsa("jwt-ps256", RsaSpec::rs256());
        sign_and_verify(Algorithm::PS256, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn ps384_round_trip() {
        let kp = fx().rsa("jwt-ps384", RsaSpec::rs256());
        sign_and_verify(Algorithm::PS384, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn ps512_round_trip() {
        let kp = fx().rsa("jwt-ps512", RsaSpec::rs256());
        sign_and_verify(Algorithm::PS512, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn rs256_with_4096_bit_key() {
        let kp = fx().rsa("jwt-4096", RsaSpec::new(4096));
        sign_and_verify(Algorithm::RS256, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn rsa_complex_claims_round_trip() {
        let kp = fx().rsa("jwt-rsa-complex", RsaSpec::rs256());
        let claims = Claims::standard()
            .with_scope("read write admin")
            .with_roles(vec!["admin", "editor", "viewer"]);

        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["test-api"]);
        let decoded = decode::<Claims>(&token, &kp.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims.scope, Some("read write admin".to_string()));
        assert_eq!(
            decoded.claims.roles,
            Some(vec![
                "admin".to_string(),
                "editor".to_string(),
                "viewer".to_string()
            ])
        );
    }

    #[test]
    fn rsa_sign_rs256_verify_with_rs384_fails() {
        let kp = fx().rsa("jwt-rsa-alg-mismatch", RsaSpec::rs256());
        let claims = Claims::standard();

        let token = encode(&Header::new(Algorithm::RS256), &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::RS384);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &kp.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidAlgorithm),
            "Expected InvalidAlgorithm"
        );
    }

    #[test]
    fn rsa_sign_rs256_verify_with_ps256_fails() {
        let kp = fx().rsa("jwt-rsa-rs-ps-mismatch", RsaSpec::rs256());
        let claims = Claims::standard();

        let token = encode(&Header::new(Algorithm::RS256), &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::PS256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &kp.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidAlgorithm),
            "Expected InvalidAlgorithm"
        );
    }

    #[test]
    fn rsa_two_different_keys_fail_cross_verify() {
        let fx = fx();
        let kp_a = fx.rsa("jwt-rsa-a", RsaSpec::rs256());
        let kp_b = fx.rsa("jwt-rsa-b", RsaSpec::rs256());

        let claims = Claims::standard();
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &kp_a.encoding_key(),
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &kp_b.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidSignature),
            "Expected InvalidSignature"
        );
    }

    #[test]
    fn rsa_deterministic_tokens_are_identical() {
        let seed = Seed::from_env_value("jwt-ext-det-rsa").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("jwt-det", RsaSpec::rs256());
        let kp2 = fx2.rsa("jwt-det", RsaSpec::rs256());

        let claims = Claims::standard();
        let header = Header::new(Algorithm::RS256);

        let t1 = encode(&header, &claims, &kp1.encoding_key()).unwrap();
        let t2 = encode(&header, &claims, &kp2.encoding_key()).unwrap();

        assert_eq!(t1, t2, "Deterministic keys should produce identical tokens");
    }
}

// =========================================================================
// ECDSA: All algorithms
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_all_algorithms {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn es256_round_trip() {
        let kp = fx().ecdsa("jwt-es256", EcdsaSpec::es256());
        sign_and_verify(Algorithm::ES256, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn es384_round_trip() {
        let kp = fx().ecdsa("jwt-es384", EcdsaSpec::es384());
        sign_and_verify(Algorithm::ES384, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn ecdsa_complex_claims_round_trip() {
        let kp = fx().ecdsa("jwt-ec-complex", EcdsaSpec::es256());
        let claims = Claims::standard()
            .with_scope("openid profile email")
            .with_roles(vec!["user"]);

        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["test-api"]);
        let decoded = decode::<Claims>(&token, &kp.decoding_key(), &validation).unwrap();

        assert_eq!(
            decoded.claims.scope,
            Some("openid profile email".to_string())
        );
        assert_eq!(decoded.claims.roles, Some(vec!["user".to_string()]));
    }

    #[test]
    fn es256_verify_with_es384_fails() {
        let kp = fx().ecdsa("jwt-ec-alg-mismatch", EcdsaSpec::es256());
        let claims = Claims::standard();

        let token = encode(&Header::new(Algorithm::ES256), &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::ES384);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &kp.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidAlgorithm),
            "Expected InvalidAlgorithm"
        );
    }

    #[test]
    fn es256_cross_key_fails() {
        let fx = fx();
        let kp_a = fx.ecdsa("jwt-ec-a", EcdsaSpec::es256());
        let kp_b = fx.ecdsa("jwt-ec-b", EcdsaSpec::es256());

        let claims = Claims::standard();
        let token = encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &kp_a.encoding_key(),
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &kp_b.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidSignature),
            "Expected InvalidSignature"
        );
    }

    #[test]
    fn ecdsa_deterministic_keys_produce_same_tokens() {
        let seed = Seed::from_env_value("jwt-ext-det-ec").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("jwt-det-ec", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("jwt-det-ec", EcdsaSpec::es256());

        // ECDSA signatures are non-deterministic (random k), so just verify cross-decode
        let claims = Claims::standard();
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &kp1.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["test-api"]);
        let decoded = decode::<Claims>(&token, &kp2.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }
}

// =========================================================================
// Ed25519: EdDSA algorithm
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_algorithm {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn eddsa_round_trip() {
        let kp = fx().ed25519("jwt-eddsa", Ed25519Spec::new());
        sign_and_verify(Algorithm::EdDSA, &kp.encoding_key(), &kp.decoding_key());
    }

    #[test]
    fn eddsa_complex_claims_round_trip() {
        let kp = fx().ed25519("jwt-ed-complex", Ed25519Spec::new());
        let claims = Claims::standard()
            .with_scope("admin:all")
            .with_roles(vec!["superadmin", "auditor"]);

        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["test-api"]);
        let decoded = decode::<Claims>(&token, &kp.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims.scope, Some("admin:all".to_string()));
        assert_eq!(
            decoded.claims.roles,
            Some(vec!["superadmin".to_string(), "auditor".to_string()])
        );
    }

    #[test]
    fn eddsa_cross_key_fails() {
        let fx = fx();
        let kp_a = fx.ed25519("jwt-ed-a", Ed25519Spec::new());
        let kp_b = fx.ed25519("jwt-ed-b", Ed25519Spec::new());

        let claims = Claims::standard();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &kp_a.encoding_key(),
        )
        .unwrap();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &kp_b.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidSignature),
            "Expected InvalidSignature"
        );
    }

    #[test]
    fn eddsa_verify_with_wrong_algorithm_fails() {
        let kp = fx().ed25519("jwt-ed-wrong-alg", Ed25519Spec::new());
        let claims = Claims::standard();

        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &kp.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidAlgorithm),
            "Expected InvalidAlgorithm"
        );
    }

    #[test]
    fn eddsa_deterministic_cross_decode() {
        let seed = Seed::from_env_value("jwt-ext-det-ed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("jwt-det-ed", Ed25519Spec::new());
        let kp2 = fx2.ed25519("jwt-det-ed", Ed25519Spec::new());

        let claims = Claims::standard();
        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &kp1.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["test-api"]);
        let decoded = decode::<Claims>(&token, &kp2.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }
}

// =========================================================================
// HMAC: All algorithms
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_all_algorithms {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    #[test]
    fn hs256_round_trip() {
        let s = fx().hmac("jwt-hs256", HmacSpec::hs256());
        sign_and_verify(Algorithm::HS256, &s.encoding_key(), &s.decoding_key());
    }

    #[test]
    fn hs384_round_trip() {
        let s = fx().hmac("jwt-hs384", HmacSpec::hs384());
        sign_and_verify(Algorithm::HS384, &s.encoding_key(), &s.decoding_key());
    }

    #[test]
    fn hs512_round_trip() {
        let s = fx().hmac("jwt-hs512", HmacSpec::hs512());
        sign_and_verify(Algorithm::HS512, &s.encoding_key(), &s.decoding_key());
    }

    #[test]
    fn hmac_complex_claims_round_trip() {
        let s = fx().hmac("jwt-hmac-complex", HmacSpec::hs256());
        let claims = Claims::standard()
            .with_scope("api:read api:write")
            .with_roles(vec!["service-account"]);

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &s.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["test-api"]);
        let decoded = decode::<Claims>(&token, &s.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn hmac_cross_secret_fails() {
        let fx = fx();
        let s_a = fx.hmac("jwt-hmac-a", HmacSpec::hs256());
        let s_b = fx.hmac("jwt-hmac-b", HmacSpec::hs256());

        let claims = Claims::standard();
        let token = encode(&Header::new(Algorithm::HS256), &claims, &s_a.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &s_b.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::InvalidSignature),
            "Expected InvalidSignature"
        );
    }
}

// =========================================================================
// Cross-algorithm family negative tests
// =========================================================================

#[cfg(all(feature = "rsa", feature = "ecdsa"))]
mod cross_family_rsa_ecdsa {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_token_rejected_by_ecdsa_key() {
        let fx = fx();
        let rsa = fx.rsa("jwt-cross-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("jwt-cross-ec", EcdsaSpec::es256());

        let claims = Claims::standard();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &rsa.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &ec.decoding_key(), &validation);

        assert!(result.is_err(), "RSA token with ECDSA key should fail");
    }

    #[test]
    fn ecdsa_token_rejected_by_rsa_key() {
        let fx = fx();
        let ec = fx.ecdsa("jwt-cross-ec2", EcdsaSpec::es256());
        let rsa = fx.rsa("jwt-cross-rsa2", RsaSpec::rs256());

        let claims = Claims::standard();
        let token = encode(&Header::new(Algorithm::ES256), &claims, &ec.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &rsa.decoding_key(), &validation);

        assert!(result.is_err(), "ECDSA token with RSA key should fail");
    }
}

#[cfg(all(feature = "rsa", feature = "ed25519"))]
mod cross_family_rsa_ed25519 {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_token_rejected_by_ed25519_key() {
        let fx = fx();
        let rsa = fx.rsa("jwt-cross-rsa-ed-1", RsaSpec::rs256());
        let ed = fx.ed25519("jwt-cross-ed-rsa-1", Ed25519Spec::new());

        let claims = Claims::standard();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &rsa.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &ed.decoding_key(), &validation);

        assert!(result.is_err(), "RSA token with Ed25519 key should fail");
    }

    #[test]
    fn ed25519_token_rejected_by_rsa_key() {
        let fx = fx();
        let ed = fx.ed25519("jwt-cross-ed-rsa-2", Ed25519Spec::new());
        let rsa = fx.rsa("jwt-cross-rsa-ed-2", RsaSpec::rs256());

        let claims = Claims::standard();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &ed.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &rsa.decoding_key(), &validation);

        assert!(result.is_err(), "Ed25519 token with RSA key should fail");
    }
}

#[cfg(all(feature = "ecdsa", feature = "ed25519"))]
mod cross_family_ecdsa_ed25519 {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ecdsa_token_rejected_by_ed25519_key() {
        let fx = fx();
        let ec = fx.ecdsa("jwt-cross-ec-ed-1", EcdsaSpec::es256());
        let ed = fx.ed25519("jwt-cross-ed-ec-1", Ed25519Spec::new());

        let claims = Claims::standard();
        let token = encode(&Header::new(Algorithm::ES256), &claims, &ec.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &ed.decoding_key(), &validation);

        assert!(result.is_err(), "ECDSA token with Ed25519 key should fail");
    }

    #[test]
    fn ed25519_token_rejected_by_ecdsa_key() {
        let fx = fx();
        let ed = fx.ed25519("jwt-cross-ed-ec-2", Ed25519Spec::new());
        let ec = fx.ecdsa("jwt-cross-ec-ed-2", EcdsaSpec::es256());

        let claims = Claims::standard();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &ed.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["test-api"]);
        let result = decode::<Claims>(&token, &ec.decoding_key(), &validation);

        assert!(result.is_err(), "Ed25519 token with ECDSA key should fail");
    }
}

// =========================================================================
// Token structure validation
// =========================================================================

#[cfg(feature = "rsa")]
mod token_structure {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn jwt_has_three_dot_separated_parts() {
        let kp = fx().rsa("jwt-structure", RsaSpec::rs256());
        let claims = Claims::standard();

        let token = encode(&Header::new(Algorithm::RS256), &claims, &kp.encoding_key()).unwrap();
        let parts: Vec<&str> = token.split('.').collect();

        assert_eq!(
            parts.len(),
            3,
            "JWT should have exactly 3 dot-separated parts"
        );
        assert!(!parts[0].is_empty(), "Header should be non-empty");
        assert!(!parts[1].is_empty(), "Payload should be non-empty");
        assert!(!parts[2].is_empty(), "Signature should be non-empty");
    }

    #[test]
    fn expired_token_rejected() {
        let kp = fx().rsa("jwt-expired", RsaSpec::rs256());
        let claims = Claims {
            exp: 1_000_000_000, // 2001 — expired
            ..Claims::standard()
        };

        let token = encode(&Header::new(Algorithm::RS256), &claims, &kp.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["test-api"]);
        validation.validate_exp = true;
        let result = decode::<Claims>(&token, &kp.decoding_key(), &validation);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err().kind(), ErrorKind::ExpiredSignature),
            "Expected ExpiredSignature"
        );
    }

    #[test]
    fn malformed_tokens_rejected() {
        let kp = fx().rsa("jwt-malformed", RsaSpec::rs256());
        let validation = Validation::new(Algorithm::RS256);

        for bad in [
            "",
            "x",
            "a.b",
            "a.b.c.d",
            "not-base64.not-base64.not-base64",
        ] {
            let result = decode::<Claims>(bad, &kp.decoding_key(), &validation);
            assert!(
                result.is_err(),
                "Malformed token '{bad}' should be rejected"
            );
        }
    }
}
