//! Error path and boundary condition tests for uselesskey-jsonwebtoken.

mod testutil;

use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uselesskey_core::Factory;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestClaims {
    sub: String,
    exp: usize,
}

// =========================================================================
// RSA: cross-key verification fails
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_errors {
    use super::*;
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_verify_with_wrong_key_fails() {
        let fx = Factory::random();
        let key_a = fx.rsa("issuer-a", RsaSpec::rs256());
        let key_b = fx.rsa("issuer-b", RsaSpec::rs256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 2_000_000_000,
        };

        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &key_a.encoding_key(),
        )
        .unwrap();

        let result = decode::<TestClaims>(
            &token,
            &key_b.decoding_key(),
            &Validation::new(Algorithm::RS256),
        );
        assert!(
            result.is_err(),
            "verifying RS256 token with wrong key should fail"
        );
    }

    #[test]
    fn rsa_expired_token_rejected() {
        let fx = Factory::random();
        let kp = fx.rsa("exp-test", RsaSpec::rs256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 1, // Unix epoch + 1 second = long expired
        };

        let token = encode(&Header::new(Algorithm::RS256), &claims, &kp.encoding_key()).unwrap();

        let result = decode::<TestClaims>(
            &token,
            &kp.decoding_key(),
            &Validation::new(Algorithm::RS256),
        );
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn rsa_tampered_token_rejected() {
        let fx = Factory::random();
        let kp = fx.rsa("tamper-test", RsaSpec::rs256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 2_000_000_000,
        };

        let mut token =
            encode(&Header::new(Algorithm::RS256), &claims, &kp.encoding_key()).unwrap();

        // Tamper with the token by modifying a character in the payload
        if let Some(pos) = token.find('.') {
            let next_pos = token[pos + 1..].find('.').map(|p| p + pos + 1);
            if let Some(mid) = next_pos {
                let mid_point = (pos + 1 + mid) / 2;
                let replacement = if &token[mid_point..mid_point + 1] == "A" {
                    "B"
                } else {
                    "A"
                };
                token.replace_range(mid_point..mid_point + 1, replacement);
            }
        }

        let result = decode::<TestClaims>(
            &token,
            &kp.decoding_key(),
            &Validation::new(Algorithm::RS256),
        );
        assert!(result.is_err(), "tampered token should be rejected");
    }

    #[test]
    fn rsa_garbage_token_string_rejected() {
        let fx = Factory::random();
        let kp = fx.rsa("garbage-test", RsaSpec::rs256());

        let result = decode::<TestClaims>(
            "not.a.jwt",
            &kp.decoding_key(),
            &Validation::new(Algorithm::RS256),
        );
        assert!(result.is_err(), "garbage token should be rejected");
    }

    #[test]
    fn rsa_empty_token_rejected() {
        let fx = Factory::random();
        let kp = fx.rsa("empty-test", RsaSpec::rs256());

        let result =
            decode::<TestClaims>("", &kp.decoding_key(), &Validation::new(Algorithm::RS256));
        assert!(result.is_err(), "empty token should be rejected");
    }
}

// =========================================================================
// ECDSA: cross-key and algorithm mismatch
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_errors {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn ecdsa_verify_with_wrong_key_fails() {
        let fx = Factory::random();
        let key_a = fx.ecdsa("ec-a", EcdsaSpec::es256());
        let key_b = fx.ecdsa("ec-b", EcdsaSpec::es256());

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
        assert!(result.is_err(), "verifying with wrong EC key should fail");
    }

    #[test]
    fn ecdsa_expired_token_rejected() {
        let fx = Factory::random();
        let kp = fx.ecdsa("ec-exp", EcdsaSpec::es256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 1,
        };

        let token = encode(&Header::new(Algorithm::ES256), &claims, &kp.encoding_key()).unwrap();

        let result = decode::<TestClaims>(
            &token,
            &kp.decoding_key(),
            &Validation::new(Algorithm::ES256),
        );
        assert!(result.is_err(), "expired EC token should be rejected");
    }

    #[test]
    fn es256_token_rejected_by_es384_validation() {
        let fx = Factory::random();
        let es256 = fx.ecdsa("curve-mismatch", EcdsaSpec::es256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 2_000_000_000,
        };

        let token = encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &es256.encoding_key(),
        )
        .unwrap();

        // Try to decode with ES384 validation - should fail
        let result = decode::<TestClaims>(
            &token,
            &es256.decoding_key(),
            &Validation::new(Algorithm::ES384),
        );
        assert!(
            result.is_err(),
            "ES256 token verified with ES384 should fail"
        );
    }
}

// =========================================================================
// HMAC: cross-secret verification
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_errors {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn hmac_verify_with_wrong_secret_fails() {
        let fx = Factory::random();
        let sec_a = fx.hmac("hmac-a", HmacSpec::hs256());
        let sec_b = fx.hmac("hmac-b", HmacSpec::hs256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 2_000_000_000,
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &sec_a.encoding_key(),
        )
        .unwrap();

        let result = decode::<TestClaims>(
            &token,
            &sec_b.decoding_key(),
            &Validation::new(Algorithm::HS256),
        );
        assert!(
            result.is_err(),
            "verifying with wrong HMAC secret should fail"
        );
    }

    #[test]
    fn hmac_expired_token_rejected() {
        let fx = Factory::random();
        let sec = fx.hmac("hmac-exp", HmacSpec::hs256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 1,
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &sec.encoding_key()).unwrap();

        let result = decode::<TestClaims>(
            &token,
            &sec.decoding_key(),
            &Validation::new(Algorithm::HS256),
        );
        assert!(result.is_err(), "expired HMAC token should be rejected");
    }

    #[test]
    fn hs256_token_rejected_by_hs512_validation() {
        let fx = Factory::random();
        let sec = fx.hmac("hs-mismatch", HmacSpec::hs256());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 2_000_000_000,
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &sec.encoding_key()).unwrap();

        let result = decode::<TestClaims>(
            &token,
            &sec.decoding_key(),
            &Validation::new(Algorithm::HS512),
        );
        assert!(
            result.is_err(),
            "HS256 token verified with HS512 should fail"
        );
    }
}

// =========================================================================
// Ed25519: cross-key
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_errors {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn ed25519_verify_with_wrong_key_fails() {
        let fx = Factory::random();
        let key_a = fx.ed25519("ed-a", Ed25519Spec::new());
        let key_b = fx.ed25519("ed-b", Ed25519Spec::new());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 2_000_000_000,
        };

        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &key_a.encoding_key(),
        )
        .unwrap();

        let result = decode::<TestClaims>(
            &token,
            &key_b.decoding_key(),
            &Validation::new(Algorithm::EdDSA),
        );
        assert!(
            result.is_err(),
            "verifying with wrong Ed25519 key should fail"
        );
    }

    #[test]
    fn ed25519_expired_token_rejected() {
        let fx = Factory::random();
        let kp = fx.ed25519("ed-exp", Ed25519Spec::new());

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: 1,
        };

        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &kp.encoding_key()).unwrap();

        let result = decode::<TestClaims>(
            &token,
            &kp.decoding_key(),
            &Validation::new(Algorithm::EdDSA),
        );
        assert!(result.is_err(), "expired Ed25519 token should be rejected");
    }
}
