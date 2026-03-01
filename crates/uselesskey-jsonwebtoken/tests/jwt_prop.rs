//! Property tests for the uselesskey-jsonwebtoken adapter.
//!
//! Covers:
//! - Determinism: same seed → identical encoding/decoding key behaviour
//! - Debug safety: no key material leakage in Debug output
//! - Label divergence: different labels → different keys
//! - Sign/verify roundtrip for all supported algorithm families

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

fn claims(sub: &str) -> Claims {
    Claims {
        sub: sub.to_string(),
        exp: 2_000_000_000,
    }
}

// =============================================================================
// ECDSA property tests (fast — used for most properties)
// =============================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_props {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Same seed + label → tokens signed by one factory verify with the other.
        #[test]
        fn deterministic_ecdsa_roundtrip(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let k1 = fx1.ecdsa("jwt-prop", EcdsaSpec::es256());
            let k2 = fx2.ecdsa("jwt-prop", EcdsaSpec::es256());

            let token = encode(
                &Header::new(Algorithm::ES256),
                &claims("prop-user"),
                &k1.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &k2.decoding_key(),
                &Validation::new(Algorithm::ES256),
            );
            prop_assert!(decoded.is_ok(), "deterministic keys must cross-verify");
            prop_assert_eq!(decoded.unwrap().claims.sub, "prop-user");
        }

        /// ES256 sign/verify roundtrip succeeds for arbitrary seeds.
        #[test]
        fn es256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-es256", EcdsaSpec::es256());

            let token = encode(
                &Header::new(Algorithm::ES256),
                &claims("u"),
                &kp.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &kp.decoding_key(),
                &Validation::new(Algorithm::ES256),
            );
            prop_assert!(decoded.is_ok(), "ES256 roundtrip must succeed");
        }

        /// ES384 sign/verify roundtrip succeeds for arbitrary seeds.
        #[test]
        fn es384_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-es384", EcdsaSpec::es384());

            let token = encode(
                &Header::new(Algorithm::ES384),
                &claims("u"),
                &kp.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &kp.decoding_key(),
                &Validation::new(Algorithm::ES384),
            );
            prop_assert!(decoded.is_ok(), "ES384 roundtrip must succeed");
        }

        /// Different labels → token signed with one key fails to verify with the other.
        #[test]
        fn ecdsa_label_divergence(
            seed in any::<[u8; 32]>(),
            label1 in "[a-zA-Z0-9]{1,16}",
            label2 in "[a-zA-Z0-9]{1,16}",
        ) {
            prop_assume!(label1 != label2);

            let fx = Factory::deterministic(Seed::new(seed));
            let k1 = fx.ecdsa(&label1, EcdsaSpec::es256());
            let k2 = fx.ecdsa(&label2, EcdsaSpec::es256());

            let token = encode(
                &Header::new(Algorithm::ES256),
                &claims("u"),
                &k1.encoding_key(),
            ).unwrap();

            let result = decode::<Claims>(
                &token,
                &k2.decoding_key(),
                &Validation::new(Algorithm::ES256),
            );
            prop_assert!(result.is_err(), "different labels must produce different keys");
        }

        /// Debug output of EcdsaKeyPair never contains PEM markers or base64 key material.
        #[test]
        fn ecdsa_debug_safety(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("debug-prop", EcdsaSpec::es256());

            let dbg = format!("{:?}", kp);
            prop_assert!(!dbg.contains("BEGIN"), "Debug must not leak PEM header");
            prop_assert!(!dbg.contains("PRIVATE"), "Debug must not leak PRIVATE marker");
        }
    }
}

// =============================================================================
// Ed25519 property tests (fast)
// =============================================================================

#[cfg(feature = "ed25519")]
mod ed25519_props {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// EdDSA sign/verify roundtrip for arbitrary seeds.
        #[test]
        fn ed25519_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-ed", Ed25519Spec::new());

            let token = encode(
                &Header::new(Algorithm::EdDSA),
                &claims("u"),
                &kp.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &kp.decoding_key(),
                &Validation::new(Algorithm::EdDSA),
            );
            prop_assert!(decoded.is_ok(), "EdDSA roundtrip must succeed");
        }

        /// Deterministic Ed25519 keys cross-verify.
        #[test]
        fn deterministic_ed25519_roundtrip(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let k1 = fx1.ed25519("jwt-prop-ed", Ed25519Spec::new());
            let k2 = fx2.ed25519("jwt-prop-ed", Ed25519Spec::new());

            let token = encode(
                &Header::new(Algorithm::EdDSA),
                &claims("u"),
                &k1.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &k2.decoding_key(),
                &Validation::new(Algorithm::EdDSA),
            );
            prop_assert!(decoded.is_ok(), "deterministic Ed25519 keys must cross-verify");
        }

        /// Debug output of Ed25519KeyPair never contains PEM markers.
        #[test]
        fn ed25519_debug_safety(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("debug-prop", Ed25519Spec::new());

            let dbg = format!("{:?}", kp);
            prop_assert!(!dbg.contains("BEGIN"), "Debug must not leak PEM header");
            prop_assert!(!dbg.contains("PRIVATE"), "Debug must not leak PRIVATE marker");
        }
    }
}

// =============================================================================
// HMAC property tests (very fast)
// =============================================================================

#[cfg(feature = "hmac")]
mod hmac_props {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// HS256 sign/verify roundtrip for arbitrary seeds.
        #[test]
        fn hs256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let secret = fx.hmac("prop-hs256", HmacSpec::hs256());

            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims("u"),
                &secret.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &secret.decoding_key(),
                &Validation::new(Algorithm::HS256),
            );
            prop_assert!(decoded.is_ok(), "HS256 roundtrip must succeed");
        }

        /// HS384 sign/verify roundtrip for arbitrary seeds.
        #[test]
        fn hs384_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let secret = fx.hmac("prop-hs384", HmacSpec::hs384());

            let token = encode(
                &Header::new(Algorithm::HS384),
                &claims("u"),
                &secret.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &secret.decoding_key(),
                &Validation::new(Algorithm::HS384),
            );
            prop_assert!(decoded.is_ok(), "HS384 roundtrip must succeed");
        }

        /// HS512 sign/verify roundtrip for arbitrary seeds.
        #[test]
        fn hs512_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let secret = fx.hmac("prop-hs512", HmacSpec::hs512());

            let token = encode(
                &Header::new(Algorithm::HS512),
                &claims("u"),
                &secret.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &secret.decoding_key(),
                &Validation::new(Algorithm::HS512),
            );
            prop_assert!(decoded.is_ok(), "HS512 roundtrip must succeed");
        }

        /// Deterministic HMAC tokens are byte-identical.
        #[test]
        fn deterministic_hmac_tokens_identical(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let s1 = fx1.hmac("jwt-prop-hmac", HmacSpec::hs256());
            let s2 = fx2.hmac("jwt-prop-hmac", HmacSpec::hs256());

            let c = claims("det-user");
            let t1 = encode(&Header::new(Algorithm::HS256), &c, &s1.encoding_key()).unwrap();
            let t2 = encode(&Header::new(Algorithm::HS256), &c, &s2.encoding_key()).unwrap();

            prop_assert_eq!(t1, t2, "deterministic HMAC tokens must be byte-identical");
        }

        /// Different HMAC labels → verification fails across secrets.
        #[test]
        fn hmac_label_divergence(
            seed in any::<[u8; 32]>(),
            label1 in "[a-zA-Z0-9]{1,16}",
            label2 in "[a-zA-Z0-9]{1,16}",
        ) {
            prop_assume!(label1 != label2);

            let fx = Factory::deterministic(Seed::new(seed));
            let s1 = fx.hmac(&label1, HmacSpec::hs256());
            let s2 = fx.hmac(&label2, HmacSpec::hs256());

            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims("u"),
                &s1.encoding_key(),
            ).unwrap();

            let result = decode::<Claims>(
                &token,
                &s2.decoding_key(),
                &Validation::new(Algorithm::HS256),
            );
            prop_assert!(result.is_err(), "different labels must produce different secrets");
        }

        /// Debug output of HmacSecret never contains raw secret bytes.
        #[test]
        fn hmac_debug_safety(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let secret = fx.hmac("debug-prop", HmacSpec::hs256());

            let dbg = format!("{:?}", secret);

            // Convert secret bytes to hex and verify absence.
            let hex: String = secret.secret_bytes().iter().map(|b| format!("{:02x}", b)).collect();
            prop_assert!(
                !dbg.contains(&hex),
                "Debug output must NOT contain hex-encoded secret bytes"
            );
        }
    }
}

// =============================================================================
// RSA property tests (slower — fewer cases)
// =============================================================================

#[cfg(feature = "rsa")]
mod rsa_props {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

        /// RS256 sign/verify roundtrip for arbitrary seeds.
        #[test]
        fn rs256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-rs256", RsaSpec::rs256());

            let token = encode(
                &Header::new(Algorithm::RS256),
                &claims("u"),
                &kp.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &kp.decoding_key(),
                &Validation::new(Algorithm::RS256),
            );
            prop_assert!(decoded.is_ok(), "RS256 roundtrip must succeed");
        }

        /// Deterministic RSA keys cross-verify.
        #[test]
        fn deterministic_rsa_roundtrip(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let k1 = fx1.rsa("jwt-prop-rsa", RsaSpec::rs256());
            let k2 = fx2.rsa("jwt-prop-rsa", RsaSpec::rs256());

            let token = encode(
                &Header::new(Algorithm::RS256),
                &claims("prop-user"),
                &k1.encoding_key(),
            ).unwrap();

            let decoded = decode::<Claims>(
                &token,
                &k2.decoding_key(),
                &Validation::new(Algorithm::RS256),
            );
            prop_assert!(decoded.is_ok(), "deterministic RSA keys must cross-verify");
            prop_assert_eq!(decoded.unwrap().claims.sub, "prop-user");
        }

        /// Debug output of RsaKeyPair never contains PEM markers.
        #[test]
        fn rsa_debug_safety(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("debug-prop", RsaSpec::rs256());

            let dbg = format!("{:?}", kp);
            prop_assert!(!dbg.contains("BEGIN"), "Debug must not leak PEM header");
            prop_assert!(!dbg.contains("PRIVATE"), "Debug must not leak PRIVATE marker");
        }
    }
}
