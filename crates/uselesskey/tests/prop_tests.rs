//! Property-based tests for the uselesskey facade.
//!
//! Verifies core determinism contract under random seeds.

use proptest::prelude::*;
use uselesskey::prelude::*;

// =========================================================================
// RSA property tests (low case count — keygen is expensive)
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_props {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_rsa_reproduces(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.rsa("prop-rsa", RsaSpec::rs256());
            let kp2 = fx2.rsa("prop-rsa", RsaSpec::rs256());

            prop_assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
        }

        #[test]
        fn rsa_pem_well_formed(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-pem", RsaSpec::rs256());

            let pem = kp.private_key_pkcs8_pem();
            prop_assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
            prop_assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
            prop_assert!(!kp.private_key_pkcs8_der().is_empty());
        }
    }
}

// =========================================================================
// ECDSA property tests
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_props {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 20, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_ecdsa_reproduces(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ecdsa("prop-ec", EcdsaSpec::es256());
            let kp2 = fx2.ecdsa("prop-ec", EcdsaSpec::es256());

            prop_assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
        }

        #[test]
        fn ecdsa_different_seeds_different_keys(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);
            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.ecdsa("prop-ec", EcdsaSpec::es256());
            let kp_b = fx_b.ecdsa("prop-ec", EcdsaSpec::es256());

            prop_assert_ne!(kp_a.private_key_pkcs8_der(), kp_b.private_key_pkcs8_der());
        }
    }
}

// =========================================================================
// Ed25519 property tests
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_props {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 30, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_ed25519_reproduces(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ed25519("prop-ed", Ed25519Spec::new());
            let kp2 = fx2.ed25519("prop-ed", Ed25519Spec::new());

            prop_assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
        }
    }
}

// =========================================================================
// HMAC property tests
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_props {
    use super::*;
    use uselesskey::{HmacFactoryExt, HmacSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 30, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_hmac_reproduces(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let s1 = fx1.hmac("prop-hmac", HmacSpec::hs256());
            let s2 = fx2.hmac("prop-hmac", HmacSpec::hs256());

            prop_assert_eq!(s1.secret_bytes(), s2.secret_bytes());
        }

        #[test]
        fn hmac_secret_length_matches_spec(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));

            let s256 = fx.hmac("len-256", HmacSpec::hs256());
            let s384 = fx.hmac("len-384", HmacSpec::hs384());
            let s512 = fx.hmac("len-512", HmacSpec::hs512());

            prop_assert_eq!(s256.secret_bytes().len(), HmacSpec::hs256().byte_len());
            prop_assert_eq!(s384.secret_bytes().len(), HmacSpec::hs384().byte_len());
            prop_assert_eq!(s512.secret_bytes().len(), HmacSpec::hs512().byte_len());
        }
    }
}

// =========================================================================
// Token property tests
// =========================================================================

#[cfg(feature = "token")]
mod token_props {
    use super::*;
    use uselesskey::{TokenFactoryExt, TokenSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 30, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_token_reproduces(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let t1 = fx1.token("prop-token", TokenSpec::api_key());
            let t2 = fx2.token("prop-token", TokenSpec::api_key());

            prop_assert_eq!(t1.value(), t2.value());
        }

        #[test]
        fn token_has_expected_prefix(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let t = fx.token("prefix-test", TokenSpec::api_key());
            prop_assert!(t.value().starts_with("uk_test_"));
        }
    }
}

// =========================================================================
// Negative fixture property tests
// =========================================================================

mod negative_props {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 30, ..ProptestConfig::default() })]

        #[test]
        fn corrupt_pem_never_returns_original(seed in any::<[u8; 32]>()) {
            let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBg==\n-----END PRIVATE KEY-----\n";

            let bad_header = corrupt_pem(pem, CorruptPem::BadHeader);
            let bad_footer = corrupt_pem(pem, CorruptPem::BadFooter);
            let bad_base64 = corrupt_pem(pem, CorruptPem::BadBase64);

            // Suppress unused variable warning
            let _ = seed;

            prop_assert_ne!(bad_header, pem);
            prop_assert_ne!(bad_footer, pem);
            prop_assert_ne!(bad_base64, pem);
        }
    }
}
