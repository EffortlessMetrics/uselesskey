//! Property-based tests for uselesskey-jsonwebtoken adapter.
//!
//! Covers:
//! - JWT roundtrip: sign → verify for all algorithm types
//! - Determinism: same seed produces same adapter keys
//! - Distinctness: different seeds/labels produce different tokens

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA property-based tests
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_props {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    proptest! {
        // RSA keygen is very expensive; keep case count minimal.
        #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

        /// JWT roundtrip: sign with encoding_key, verify with decoding_key.
        #[test]
        fn rsa_jwt_roundtrip(sub in "[a-z]{1,20}") {
            let fx = Factory::random();
            let kp = fx.rsa("prop-jwt-rsa", RsaSpec::rs256());

            let claims = Claims { sub: sub.clone(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::RS256), &claims, &kp.encoding_key()).unwrap();
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &Validation::new(Algorithm::RS256)).unwrap();
            prop_assert_eq!(decoded.claims.sub, sub);
        }

        /// Deterministic factories produce identical encoding/decoding behaviour.
        #[test]
        fn rsa_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.rsa("prop-det-rsa", RsaSpec::rs256());
            let kp2 = fx2.rsa("prop-det-rsa", RsaSpec::rs256());

            let claims = Claims { sub: "det".into(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::RS256), &claims, &kp1.encoding_key()).unwrap();
            // Token signed by kp1 must verify with kp2's decoding key.
            let decoded = decode::<Claims>(&token, &kp2.decoding_key(), &Validation::new(Algorithm::RS256)).unwrap();
            prop_assert_eq!(decoded.claims.sub, "det");
        }

        /// Different seeds produce keys that cannot cross-verify.
        #[test]
        fn rsa_different_seeds_distinct(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.rsa("prop-rsa", RsaSpec::rs256());
            let kp_b = fx_b.rsa("prop-rsa", RsaSpec::rs256());

            let claims = Claims { sub: "x".into(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::RS256), &claims, &kp_a.encoding_key()).unwrap();
            let result = decode::<Claims>(&token, &kp_b.decoding_key(), &Validation::new(Algorithm::RS256));
            prop_assert!(result.is_err(), "Different seeds should not cross-verify");
        }
    }
}

// =========================================================================
// ECDSA property-based tests
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_props {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

        /// ES256 JWT roundtrip.
        #[test]
        fn es256_jwt_roundtrip(sub in "[a-z]{1,20}") {
            let fx = Factory::random();
            let kp = fx.ecdsa("prop-jwt-ec256", EcdsaSpec::es256());

            let claims = Claims { sub: sub.clone(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::ES256), &claims, &kp.encoding_key()).unwrap();
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &Validation::new(Algorithm::ES256)).unwrap();
            prop_assert_eq!(decoded.claims.sub, sub);
        }

        /// ES384 JWT roundtrip.
        #[test]
        fn es384_jwt_roundtrip(sub in "[a-z]{1,20}") {
            let fx = Factory::random();
            let kp = fx.ecdsa("prop-jwt-ec384", EcdsaSpec::es384());

            let claims = Claims { sub: sub.clone(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::ES384), &claims, &kp.encoding_key()).unwrap();
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &Validation::new(Algorithm::ES384)).unwrap();
            prop_assert_eq!(decoded.claims.sub, sub);
        }

        /// Deterministic ECDSA keys produce identical JWT behaviour.
        #[test]
        fn ecdsa_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ecdsa("prop-det-ec", EcdsaSpec::es256());
            let kp2 = fx2.ecdsa("prop-det-ec", EcdsaSpec::es256());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Deterministic ECDSA keys should be identical"
            );
        }

        /// Different seeds yield different ECDSA keys.
        #[test]
        fn ecdsa_different_seeds_distinct(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.ecdsa("prop-ec", EcdsaSpec::es256());
            let kp_b = fx_b.ecdsa("prop-ec", EcdsaSpec::es256());

            prop_assert_ne!(
                kp_a.private_key_pkcs8_der(),
                kp_b.private_key_pkcs8_der(),
                "Different seeds should produce different ECDSA keys"
            );
        }
    }
}

// =========================================================================
// Ed25519 property-based tests
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_props {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Ed25519 JWT roundtrip.
        #[test]
        fn ed25519_jwt_roundtrip(sub in "[a-z]{1,20}") {
            let fx = Factory::random();
            let kp = fx.ed25519("prop-jwt-ed", Ed25519Spec::new());

            let claims = Claims { sub: sub.clone(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::EdDSA), &claims, &kp.encoding_key()).unwrap();
            let decoded = decode::<Claims>(&token, &kp.decoding_key(), &Validation::new(Algorithm::EdDSA)).unwrap();
            prop_assert_eq!(decoded.claims.sub, sub);
        }

        /// Deterministic Ed25519 keys are identical across factories.
        #[test]
        fn ed25519_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ed25519("prop-det-ed", Ed25519Spec::new());
            let kp2 = fx2.ed25519("prop-det-ed", Ed25519Spec::new());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Deterministic Ed25519 keys should be identical"
            );
        }

        /// Different seeds yield different Ed25519 keys.
        #[test]
        fn ed25519_different_seeds_distinct(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.ed25519("prop-ed", Ed25519Spec::new());
            let kp_b = fx_b.ed25519("prop-ed", Ed25519Spec::new());

            prop_assert_ne!(
                kp_a.private_key_pkcs8_der(),
                kp_b.private_key_pkcs8_der(),
                "Different seeds should produce different Ed25519 keys"
            );
        }
    }
}

// =========================================================================
// HMAC property-based tests
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_props {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// HS256 JWT roundtrip.
        #[test]
        fn hs256_jwt_roundtrip(sub in "[a-z]{1,20}") {
            let fx = Factory::random();
            let secret = fx.hmac("prop-jwt-hs256", HmacSpec::hs256());

            let claims = Claims { sub: sub.clone(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::HS256), &claims, &secret.encoding_key()).unwrap();
            let decoded = decode::<Claims>(&token, &secret.decoding_key(), &Validation::new(Algorithm::HS256)).unwrap();
            prop_assert_eq!(decoded.claims.sub, sub);
        }

        /// HS384 JWT roundtrip.
        #[test]
        fn hs384_jwt_roundtrip(sub in "[a-z]{1,20}") {
            let fx = Factory::random();
            let secret = fx.hmac("prop-jwt-hs384", HmacSpec::hs384());

            let claims = Claims { sub: sub.clone(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::HS384), &claims, &secret.encoding_key()).unwrap();
            let decoded = decode::<Claims>(&token, &secret.decoding_key(), &Validation::new(Algorithm::HS384)).unwrap();
            prop_assert_eq!(decoded.claims.sub, sub);
        }

        /// HS512 JWT roundtrip.
        #[test]
        fn hs512_jwt_roundtrip(sub in "[a-z]{1,20}") {
            let fx = Factory::random();
            let secret = fx.hmac("prop-jwt-hs512", HmacSpec::hs512());

            let claims = Claims { sub: sub.clone(), exp: 2_000_000_000 };
            let token = encode(&Header::new(Algorithm::HS512), &claims, &secret.encoding_key()).unwrap();
            let decoded = decode::<Claims>(&token, &secret.decoding_key(), &Validation::new(Algorithm::HS512)).unwrap();
            prop_assert_eq!(decoded.claims.sub, sub);
        }

        /// Deterministic HMAC secrets are identical across factories.
        #[test]
        fn hmac_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let s1 = fx1.hmac("prop-det-hmac", HmacSpec::hs256());
            let s2 = fx2.hmac("prop-det-hmac", HmacSpec::hs256());

            prop_assert_eq!(
                s1.secret_bytes(),
                s2.secret_bytes(),
                "Deterministic HMAC secrets should be identical"
            );
        }

        /// Different seeds produce different HMAC secrets.
        #[test]
        fn hmac_different_seeds_distinct(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let s_a = fx_a.hmac("prop-hmac", HmacSpec::hs256());
            let s_b = fx_b.hmac("prop-hmac", HmacSpec::hs256());

            prop_assert_ne!(
                s_a.secret_bytes(),
                s_b.secret_bytes(),
                "Different seeds should produce different HMAC secrets"
            );
        }
    }
}
