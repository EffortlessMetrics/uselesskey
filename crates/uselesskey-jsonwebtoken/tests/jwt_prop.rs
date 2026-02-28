#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uselesskey_core::{Factory, Seed};
use uselesskey_jsonwebtoken::JwtKeyExt;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
}

fn claims() -> Claims {
    Claims {
        sub: "prop-user".to_string(),
        exp: 2_000_000_000,
    }
}

// =========================================================================
// ECDSA (fast — used as primary sign/verify roundtrip target)
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_prop {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip: any seed produces a working ES256 keypair.
        #[test]
        fn es256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-jwt", EcdsaSpec::es256());

            let claims = claims();
            let header = Header::new(Algorithm::ES256);
            let token = encode(&header, &claims, &kp.encoding_key())
                .expect("encoding should succeed");

            let validation = Validation::new(Algorithm::ES256);
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &validation)
                .expect("decoding should succeed");

            prop_assert_eq!(decoded.claims, claims);
        }

        /// Sign/verify roundtrip for ES384.
        #[test]
        fn es384_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-jwt", EcdsaSpec::es384());

            let claims = claims();
            let header = Header::new(Algorithm::ES384);
            let token = encode(&header, &claims, &kp.encoding_key())
                .expect("encoding should succeed");

            let validation = Validation::new(Algorithm::ES384);
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &validation)
                .expect("decoding should succeed");

            prop_assert_eq!(decoded.claims, claims);
        }

        /// Different seeds produce different ECDSA keys.
        #[test]
        fn different_seeds_produce_different_ecdsa_keys(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed1 != seed2);

            let fx1 = Factory::deterministic(Seed::new(seed1));
            let fx2 = Factory::deterministic(Seed::new(seed2));
            let k1 = fx1.ecdsa("prop-jwt", EcdsaSpec::es256());
            let k2 = fx2.ecdsa("prop-jwt", EcdsaSpec::es256());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }

        /// Cross-key verification fails: token signed with key A cannot be verified with key B.
        #[test]
        fn cross_key_verification_fails(
            seed in any::<[u8; 32]>(),
            label1 in "[a-zA-Z0-9]{1,16}",
            label2 in "[a-zA-Z0-9]{1,16}",
        ) {
            prop_assume!(label1 != label2);

            let fx = Factory::deterministic(Seed::new(seed));
            let key_a = fx.ecdsa(&label1, EcdsaSpec::es256());
            let key_b = fx.ecdsa(&label2, EcdsaSpec::es256());

            let claims = claims();
            let header = Header::new(Algorithm::ES256);
            let token = encode(&header, &claims, &key_a.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::ES256);
            let result = decode::<Claims>(&token, &key_b.decoding_key(), &validation);

            prop_assert!(result.is_err(), "decoding with wrong key should fail");
        }
    }
}

// =========================================================================
// Ed25519
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_prop {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for EdDSA.
        #[test]
        fn ed25519_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-jwt", Ed25519Spec::new());

            let claims = claims();
            let header = Header::new(Algorithm::EdDSA);
            let token = encode(&header, &claims, &kp.encoding_key())
                .expect("encoding should succeed");

            let validation = Validation::new(Algorithm::EdDSA);
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &validation)
                .expect("decoding should succeed");

            prop_assert_eq!(decoded.claims, claims);
        }

        /// Different seeds produce different Ed25519 keys.
        #[test]
        fn different_seeds_produce_different_ed25519_keys(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed1 != seed2);

            let fx1 = Factory::deterministic(Seed::new(seed1));
            let fx2 = Factory::deterministic(Seed::new(seed2));
            let k1 = fx1.ed25519("prop-jwt", Ed25519Spec::new());
            let k2 = fx2.ed25519("prop-jwt", Ed25519Spec::new());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }
    }
}

// =========================================================================
// HMAC
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_prop {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for HS256.
        #[test]
        fn hs256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let secret = fx.hmac("prop-jwt", HmacSpec::hs256());

            let claims = claims();
            let header = Header::new(Algorithm::HS256);
            let token = encode(&header, &claims, &secret.encoding_key())
                .expect("encoding should succeed");

            let validation = Validation::new(Algorithm::HS256);
            let decoded = decode::<Claims>(&token, &secret.decoding_key(), &validation)
                .expect("decoding should succeed");

            prop_assert_eq!(decoded.claims, claims);
        }

        /// Sign/verify roundtrip for HS384.
        #[test]
        fn hs384_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let secret = fx.hmac("prop-jwt", HmacSpec::hs384());

            let claims = claims();
            let header = Header::new(Algorithm::HS384);
            let token = encode(&header, &claims, &secret.encoding_key())
                .expect("encoding should succeed");

            let validation = Validation::new(Algorithm::HS384);
            let decoded = decode::<Claims>(&token, &secret.decoding_key(), &validation)
                .expect("decoding should succeed");

            prop_assert_eq!(decoded.claims, claims);
        }

        /// Sign/verify roundtrip for HS512.
        #[test]
        fn hs512_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let secret = fx.hmac("prop-jwt", HmacSpec::hs512());

            let claims = claims();
            let header = Header::new(Algorithm::HS512);
            let token = encode(&header, &claims, &secret.encoding_key())
                .expect("encoding should succeed");

            let validation = Validation::new(Algorithm::HS512);
            let decoded = decode::<Claims>(&token, &secret.decoding_key(), &validation)
                .expect("decoding should succeed");

            prop_assert_eq!(decoded.claims, claims);
        }

        /// Different seeds produce different HMAC secrets.
        #[test]
        fn different_seeds_produce_different_hmac_secrets(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed1 != seed2);

            let fx1 = Factory::deterministic(Seed::new(seed1));
            let fx2 = Factory::deterministic(Seed::new(seed2));
            let s1 = fx1.hmac("prop-jwt", HmacSpec::hs256());
            let s2 = fx2.hmac("prop-jwt", HmacSpec::hs256());

            prop_assert_ne!(
                s1.secret_bytes(),
                s2.secret_bytes(),
                "different seeds should produce different secrets"
            );
        }
    }
}

// =========================================================================
// RSA (slow — keep case count low)
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_prop {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for RS256 (2048-bit).
        #[test]
        fn rs256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-jwt", RsaSpec::rs256());

            let claims = claims();
            let header = Header::new(Algorithm::RS256);
            let token = encode(&header, &claims, &kp.encoding_key())
                .expect("encoding should succeed");

            let validation = Validation::new(Algorithm::RS256);
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &validation)
                .expect("decoding should succeed");

            prop_assert_eq!(decoded.claims, claims);
        }

        /// Different seeds produce different RSA keys.
        #[test]
        fn different_seeds_produce_different_rsa_keys(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed1 != seed2);

            let fx1 = Factory::deterministic(Seed::new(seed1));
            let fx2 = Factory::deterministic(Seed::new(seed2));
            let k1 = fx1.rsa("prop-jwt", RsaSpec::rs256());
            let k2 = fx2.rsa("prop-jwt", RsaSpec::rs256());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }
    }
}
