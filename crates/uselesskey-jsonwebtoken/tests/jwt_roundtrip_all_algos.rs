//! Systematic JWT round-trip tests for every algorithm type.
//!
//! Tests cover:
//! - Parameterized sign/verify round-trips across all 9 JWT algorithms
//! - Token payload tampering detection
//! - Mismatched key variant rejects signatures
//! - Cross-factory deterministic verification (sign factory1, verify factory2)
//! - Multiple tokens from the same key remain independently verifiable

mod testutil;

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode, errors::ErrorKind};
use serde::{Deserialize, Serialize};
use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_jsonwebtoken::JwtKeyExt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
}

fn claims() -> Claims {
    Claims {
        sub: "roundtrip-user".into(),
        exp: 2_000_000_000,
    }
}

// =========================================================================
// Parameterized round-trips: every RSA algorithm with one key
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_all_schemes {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    /// RSA keys can sign with any RS*/PS* algorithm.
    #[test]
    fn all_rsa_algorithms_round_trip() {
        let kp = fx().rsa("all-rsa-algos", RsaSpec::rs256());

        for alg in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            let token = encode(&Header::new(alg), &claims(), &kp.encoding_key())
                .unwrap_or_else(|e| panic!("encode {alg:?} failed: {e:?}"));

            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &Validation::new(alg))
                .unwrap_or_else(|e| panic!("decode {alg:?} failed: {e:?}"));

            assert_eq!(decoded.claims, claims(), "claims mismatch for {alg:?}");
        }
    }

    /// Tokens signed under different RSA algorithms are not interchangeable.
    #[test]
    fn rs256_token_rejected_as_ps256() {
        let kp = fx().rsa("rsa-scheme-mismatch", RsaSpec::rs256());
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims(),
            &kp.encoding_key(),
        )
        .unwrap();

        let result = decode::<Claims>(
            &token,
            &kp.decoding_key(),
            &Validation::new(Algorithm::PS256),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidAlgorithm
        ));
    }
}

// =========================================================================
// Token payload tampering detection
// =========================================================================

#[cfg(feature = "hmac")]
mod payload_tampering {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    /// Modify the base64-encoded payload section of a JWT; verification must fail.
    #[test]
    fn tampered_payload_rejected() {
        let secret = fx().hmac("tamper-detect", HmacSpec::hs256());
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &secret.encoding_key(),
        )
        .unwrap();

        // JWT = header.payload.signature — replace one char in the payload
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let mut payload_bytes: Vec<u8> = parts[1].bytes().collect();
        // Flip one byte (safe because base64url uses ASCII)
        if let Some(b) = payload_bytes.first_mut() {
            *b = if *b == b'A' { b'B' } else { b'A' };
        }
        let tampered_payload = String::from_utf8(payload_bytes).unwrap();
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = decode::<Claims>(
            &tampered_token,
            &secret.decoding_key(),
            &Validation::new(Algorithm::HS256),
        );
        assert!(result.is_err(), "tampered payload must be rejected");
    }

    /// Modify the signature section of a JWT; verification must fail.
    #[test]
    fn tampered_signature_rejected() {
        let secret = fx().hmac("sig-tamper", HmacSpec::hs256());
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &secret.encoding_key(),
        )
        .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        let mut sig_bytes: Vec<u8> = parts[2].bytes().collect();
        if let Some(b) = sig_bytes.last_mut() {
            *b = if *b == b'A' { b'B' } else { b'A' };
        }
        let tampered_sig = String::from_utf8(sig_bytes).unwrap();
        let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

        let result = decode::<Claims>(
            &tampered_token,
            &secret.decoding_key(),
            &Validation::new(Algorithm::HS256),
        );
        assert!(result.is_err(), "tampered signature must be rejected");
    }
}

// =========================================================================
// Mismatched key variant rejects signatures
// =========================================================================

#[cfg(feature = "rsa")]
mod mismatch_variant {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    /// The fixture's `mismatched_public_key_spki_der()` should reject a valid token.
    #[test]
    fn mismatched_public_key_rejects_token() {
        let kp = fx().rsa("mismatch-jwt", RsaSpec::rs256());
        let token = encode(
            &Header::new(Algorithm::RS256),
            &claims(),
            &kp.encoding_key(),
        )
        .unwrap();

        let bad_pub = DecodingKey::from_rsa_der(&kp.mismatched_public_key_spki_der());
        let result = decode::<Claims>(&token, &bad_pub, &Validation::new(Algorithm::RS256));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidSignature
        ));
    }
}

// =========================================================================
// Cross-factory deterministic verification
// =========================================================================

#[cfg(feature = "ed25519")]
mod cross_factory_deterministic {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    /// Sign with factory1, verify with factory2 using the same seed.
    #[test]
    fn sign_factory1_verify_factory2() {
        let seed = Seed::from_env_value("jwt-cross-factory-ed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("cross-fac", Ed25519Spec::new());
        let kp2 = fx2.ed25519("cross-fac", Ed25519Spec::new());

        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims(),
            &kp1.encoding_key(),
        )
        .unwrap();
        let decoded = decode::<Claims>(
            &token,
            &kp2.decoding_key(),
            &Validation::new(Algorithm::EdDSA),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims());
    }
}

#[cfg(feature = "hmac")]
mod cross_factory_hmac {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    #[test]
    fn hmac_sign_factory1_verify_factory2() {
        let seed = Seed::from_env_value("jwt-cross-factory-hmac").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let s1 = fx1.hmac("cross-fac-hmac", HmacSpec::hs512());
        let s2 = fx2.hmac("cross-fac-hmac", HmacSpec::hs512());

        let token = encode(
            &Header::new(Algorithm::HS512),
            &claims(),
            &s1.encoding_key(),
        )
        .unwrap();
        let decoded = decode::<Claims>(
            &token,
            &s2.decoding_key(),
            &Validation::new(Algorithm::HS512),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims());
    }
}

// =========================================================================
// Multiple tokens from same key are independently verifiable
// =========================================================================

#[cfg(feature = "ecdsa")]
mod multi_token {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn multiple_tokens_all_verify() {
        let kp = fx().ecdsa("multi-tok", EcdsaSpec::es256());

        let tokens: Vec<String> = (0..5)
            .map(|i| {
                let c = Claims {
                    sub: format!("user-{i}"),
                    exp: 2_000_000_000,
                };
                encode(&Header::new(Algorithm::ES256), &c, &kp.encoding_key()).unwrap()
            })
            .collect();

        for (i, tok) in tokens.iter().enumerate() {
            let decoded =
                decode::<Claims>(tok, &kp.decoding_key(), &Validation::new(Algorithm::ES256))
                    .unwrap();
            assert_eq!(decoded.claims.sub, format!("user-{i}"));
        }
    }
}
