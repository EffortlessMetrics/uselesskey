//! Property-based tests for uselesskey-rustls adapter.
//!
//! Covers:
//! - Roundtrip: fixture → rustls type → DER bytes match
//! - Determinism: same seed produces same rustls keys
//! - Distinctness: different seeds produce different keys
//! - All key types produce valid rustls conversions

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// X.509 self-signed property-based tests
// =========================================================================

#[cfg(feature = "x509")]
mod x509_self_signed_props {
    use super::*;
    use uselesskey_rustls::{RustlsCertExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{X509FactoryExt, X509Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

        /// Self-signed cert → rustls private key DER matches original.
        #[test]
        fn self_signed_private_key_matches(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let cert = fx.x509_self_signed("prop-ss", X509Spec::self_signed("prop.example.com"));

            let key = cert.private_key_der_rustls();
            prop_assert_eq!(
                key.secret_der(),
                cert.private_key_pkcs8_der(),
                "rustls private key DER should match original"
            );
        }

        /// Self-signed cert → rustls certificate DER matches original.
        #[test]
        fn self_signed_cert_matches(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let cert = fx.x509_self_signed("prop-ss", X509Spec::self_signed("prop.example.com"));

            let cert_der = cert.certificate_der_rustls();
            prop_assert_eq!(
                cert_der.as_ref(),
                cert.cert_der(),
                "rustls certificate DER should match original"
            );
        }

        /// Deterministic self-signed certs produce identical rustls conversions.
        #[test]
        fn self_signed_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let c1 = fx1.x509_self_signed("prop-det", X509Spec::self_signed("prop.example.com"));
            let c2 = fx2.x509_self_signed("prop-det", X509Spec::self_signed("prop.example.com"));

            let k1 = c1.private_key_der_rustls();
            let k2 = c2.private_key_der_rustls();
            prop_assert_eq!(
                k1.secret_der(),
                k2.secret_der(),
                "Deterministic certs should produce identical private keys"
            );

            let cd1 = c1.certificate_der_rustls();
            let cd2 = c2.certificate_der_rustls();
            prop_assert_eq!(
                cd1.as_ref(),
                cd2.as_ref(),
                "Deterministic certs should produce identical certificates"
            );
        }

        /// Different seeds produce different self-signed certs.
        #[test]
        fn self_signed_different_seeds(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let c_a = fx_a.x509_self_signed("prop-ss", X509Spec::self_signed("prop.example.com"));
            let c_b = fx_b.x509_self_signed("prop-ss", X509Spec::self_signed("prop.example.com"));

            let cd_a = c_a.certificate_der_rustls();
            let cd_b = c_b.certificate_der_rustls();
            prop_assert_ne!(
                cd_a.as_ref(),
                cd_b.as_ref(),
                "Different seeds should produce different certificates"
            );
        }
    }
}

// =========================================================================
// X.509 chain property-based tests
// =========================================================================

#[cfg(feature = "x509")]
mod x509_chain_props {
    use super::*;
    use uselesskey_rustls::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

        /// Chain → rustls conversions preserve the original DER bytes.
        #[test]
        fn chain_der_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let chain = fx.x509_chain("prop-chain", ChainSpec::new("prop.example.com"));

            let key = chain.private_key_der_rustls();
            prop_assert_eq!(
                key.secret_der(),
                chain.leaf_private_key_pkcs8_der(),
                "Chain private key should match"
            );

            let leaf_cert = chain.certificate_der_rustls();
            prop_assert_eq!(
                leaf_cert.as_ref(),
                chain.leaf_cert_der(),
                "Chain leaf cert should match"
            );

            let chain_certs = chain.chain_der_rustls();
            prop_assert_eq!(chain_certs.len(), 2, "Chain should have leaf + intermediate");
            prop_assert_eq!(chain_certs[0].as_ref(), chain.leaf_cert_der());
            prop_assert_eq!(chain_certs[1].as_ref(), chain.intermediate_cert_der());

            let root = chain.root_certificate_der_rustls();
            prop_assert_eq!(
                root.as_ref(),
                chain.root_cert_der(),
                "Root cert should match"
            );
        }

        /// Deterministic chains produce identical rustls output.
        #[test]
        fn chain_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let ch1 = fx1.x509_chain("prop-det-ch", ChainSpec::new("prop.example.com"));
            let ch2 = fx2.x509_chain("prop-det-ch", ChainSpec::new("prop.example.com"));

            prop_assert_eq!(
                ch1.leaf_cert_der(),
                ch2.leaf_cert_der(),
                "Deterministic chains should produce identical leaf certs"
            );
            prop_assert_eq!(
                ch1.root_cert_der(),
                ch2.root_cert_der(),
                "Deterministic chains should produce identical root certs"
            );
        }

        /// Different seeds produce different chain certificates.
        #[test]
        fn chain_different_seeds(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let ch_a = fx_a.x509_chain("prop-ch", ChainSpec::new("prop.example.com"));
            let ch_b = fx_b.x509_chain("prop-ch", ChainSpec::new("prop.example.com"));

            prop_assert_ne!(
                ch_a.leaf_cert_der(),
                ch_b.leaf_cert_der(),
                "Different seeds should produce different leaf certs"
            );
        }
    }
}

// =========================================================================
// RSA key → rustls private key
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_props {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

        /// RSA private key → rustls DER matches original.
        #[test]
        fn rsa_private_key_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-rsa", RsaSpec::rs256());

            let key = kp.private_key_der_rustls();
            prop_assert_eq!(
                key.secret_der(),
                kp.private_key_pkcs8_der(),
                "RSA private key DER should match"
            );
        }

        /// Deterministic RSA keys produce identical rustls conversions.
        #[test]
        fn rsa_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.rsa("prop-det-rsa", RsaSpec::rs256());
            let kp2 = fx2.rsa("prop-det-rsa", RsaSpec::rs256());

            let k1 = kp1.private_key_der_rustls();
            let k2 = kp2.private_key_der_rustls();
            prop_assert_eq!(
                k1.secret_der(),
                k2.secret_der(),
                "Deterministic RSA keys should produce identical rustls keys"
            );
        }
    }
}

// =========================================================================
// ECDSA key → rustls private key
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_props {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

        /// ECDSA P-256 private key → rustls DER matches original.
        #[test]
        fn ecdsa_p256_private_key_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-ec256", EcdsaSpec::es256());

            let key = kp.private_key_der_rustls();
            prop_assert_eq!(
                key.secret_der(),
                kp.private_key_pkcs8_der(),
                "P-256 private key DER should match"
            );
        }

        /// ECDSA P-384 private key → rustls DER matches original.
        #[test]
        fn ecdsa_p384_private_key_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-ec384", EcdsaSpec::es384());

            let key = kp.private_key_der_rustls();
            prop_assert_eq!(
                key.secret_der(),
                kp.private_key_pkcs8_der(),
                "P-384 private key DER should match"
            );
        }

        /// Deterministic ECDSA keys produce identical rustls conversions.
        #[test]
        fn ecdsa_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ecdsa("prop-det-ec", EcdsaSpec::es256());
            let kp2 = fx2.ecdsa("prop-det-ec", EcdsaSpec::es256());

            let k1 = kp1.private_key_der_rustls();
            let k2 = kp2.private_key_der_rustls();
            prop_assert_eq!(
                k1.secret_der(),
                k2.secret_der(),
                "Deterministic ECDSA keys should produce identical rustls keys"
            );
        }

        /// Different seeds yield different ECDSA keys.
        #[test]
        fn ecdsa_different_seeds(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.ecdsa("prop-ec", EcdsaSpec::es256());
            let kp_b = fx_b.ecdsa("prop-ec", EcdsaSpec::es256());

            let k_a = kp_a.private_key_der_rustls();
            let k_b = kp_b.private_key_der_rustls();
            prop_assert_ne!(
                k_a.secret_der(),
                k_b.secret_der(),
                "Different seeds should produce different ECDSA keys"
            );
        }
    }
}

// =========================================================================
// Ed25519 key → rustls private key
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_props {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Ed25519 private key → rustls DER matches original.
        #[test]
        fn ed25519_private_key_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-ed", Ed25519Spec::new());

            let key = kp.private_key_der_rustls();
            prop_assert_eq!(
                key.secret_der(),
                kp.private_key_pkcs8_der(),
                "Ed25519 private key DER should match"
            );
        }

        /// Deterministic Ed25519 keys produce identical rustls conversions.
        #[test]
        fn ed25519_deterministic(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ed25519("prop-det-ed", Ed25519Spec::new());
            let kp2 = fx2.ed25519("prop-det-ed", Ed25519Spec::new());

            let k1 = kp1.private_key_der_rustls();
            let k2 = kp2.private_key_der_rustls();
            prop_assert_eq!(
                k1.secret_der(),
                k2.secret_der(),
                "Deterministic Ed25519 keys should produce identical rustls keys"
            );
        }

        /// Different seeds yield different Ed25519 keys.
        #[test]
        fn ed25519_different_seeds(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.ed25519("prop-ed", Ed25519Spec::new());
            let kp_b = fx_b.ed25519("prop-ed", Ed25519Spec::new());

            let k_a = kp_a.private_key_der_rustls();
            let k_b = kp_b.private_key_der_rustls();
            prop_assert_ne!(
                k_a.secret_der(),
                k_b.secret_der(),
                "Different seeds should produce different Ed25519 keys"
            );
        }
    }
}
