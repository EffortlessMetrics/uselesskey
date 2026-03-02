//! Additional integration tests for uselesskey-core-rustls-pki conversion paths.
//!
//! Covers deterministic factory roundtrips, cross-label distinctness,
//! and property-level assertions for key/certificate conversions.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Deterministic RSA conversions
// ---------------------------------------------------------------------------

#[cfg(feature = "rsa")]
mod rsa_deterministic {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_core_rustls_pki::RustlsPrivateKeyExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn deterministic_rsa_key_is_reproducible() {
        let fx1 = Factory::deterministic(Seed::new([1u8; 32]));
        let fx2 = Factory::deterministic(Seed::new([1u8; 32]));
        let k1 = fx1.rsa("det-rsa", RsaSpec::rs256());
        let k2 = fx2.rsa("det-rsa", RsaSpec::rs256());
        assert_eq!(
            k1.private_key_der_rustls().secret_der(),
            k2.private_key_der_rustls().secret_der()
        );
    }

    #[test]
    fn different_labels_produce_different_rsa_keys() {
        let fx = Factory::random();
        let k1 = fx.rsa("label-a", RsaSpec::rs256());
        let k2 = fx.rsa("label-b", RsaSpec::rs256());
        assert_ne!(
            k1.private_key_der_rustls().secret_der(),
            k2.private_key_der_rustls().secret_der()
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic ECDSA conversions
// ---------------------------------------------------------------------------

#[cfg(feature = "ecdsa")]
mod ecdsa_deterministic {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_core_rustls_pki::RustlsPrivateKeyExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn deterministic_ecdsa_key_is_reproducible() {
        let fx1 = Factory::deterministic(Seed::new([2u8; 32]));
        let fx2 = Factory::deterministic(Seed::new([2u8; 32]));
        let k1 = fx1.ecdsa("det-ec", EcdsaSpec::es256());
        let k2 = fx2.ecdsa("det-ec", EcdsaSpec::es256());
        assert_eq!(
            k1.private_key_der_rustls().secret_der(),
            k2.private_key_der_rustls().secret_der()
        );
    }

    #[test]
    fn es256_and_es384_produce_different_keys() {
        let fx = Factory::random();
        let k256 = fx.ecdsa("curve-test", EcdsaSpec::es256());
        let k384 = fx.ecdsa("curve-test", EcdsaSpec::es384());
        assert_ne!(
            k256.private_key_der_rustls().secret_der(),
            k384.private_key_der_rustls().secret_der()
        );
    }

    #[test]
    fn ecdsa_key_der_non_empty() {
        let fx = Factory::random();
        let kp = fx.ecdsa("ec-nonempty", EcdsaSpec::es384());
        assert!(
            !kp.private_key_der_rustls().secret_der().is_empty(),
            "ECDSA ES384 key DER must not be empty"
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic Ed25519 conversions
// ---------------------------------------------------------------------------

#[cfg(feature = "ed25519")]
mod ed25519_deterministic {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_core_rustls_pki::RustlsPrivateKeyExt;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn deterministic_ed25519_key_is_reproducible() {
        let fx1 = Factory::deterministic(Seed::new([3u8; 32]));
        let fx2 = Factory::deterministic(Seed::new([3u8; 32]));
        let k1 = fx1.ed25519("det-ed", Ed25519Spec::new());
        let k2 = fx2.ed25519("det-ed", Ed25519Spec::new());
        assert_eq!(
            k1.private_key_der_rustls().secret_der(),
            k2.private_key_der_rustls().secret_der()
        );
    }

    #[test]
    fn different_labels_produce_different_ed25519_keys() {
        let fx = Factory::random();
        let k1 = fx.ed25519("ed-a", Ed25519Spec::new());
        let k2 = fx.ed25519("ed-b", Ed25519Spec::new());
        assert_ne!(
            k1.private_key_der_rustls().secret_der(),
            k2.private_key_der_rustls().secret_der()
        );
    }

    #[test]
    fn ed25519_key_der_non_empty() {
        let fx = Factory::random();
        let kp = fx.ed25519("ed-nonempty", Ed25519Spec::new());
        assert!(
            !kp.private_key_der_rustls().secret_der().is_empty(),
            "Ed25519 key DER must not be empty"
        );
    }
}

// ---------------------------------------------------------------------------
// X.509 deterministic and cross-label tests
// ---------------------------------------------------------------------------

#[cfg(feature = "x509")]
mod x509_deterministic {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_core_rustls_pki::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    #[test]
    fn deterministic_self_signed_key_is_reproducible() {
        let fx1 = Factory::deterministic(Seed::new([4u8; 32]));
        let fx2 = Factory::deterministic(Seed::new([4u8; 32]));
        let c1 = fx1.x509_self_signed("det-ss", X509Spec::self_signed("det.example.com"));
        let c2 = fx2.x509_self_signed("det-ss", X509Spec::self_signed("det.example.com"));
        assert_eq!(
            c1.private_key_der_rustls().secret_der(),
            c2.private_key_der_rustls().secret_der()
        );
        assert_eq!(
            c1.certificate_der_rustls().as_ref(),
            c2.certificate_der_rustls().as_ref()
        );
    }

    #[test]
    fn deterministic_chain_key_is_reproducible() {
        let fx1 = Factory::deterministic(Seed::new([5u8; 32]));
        let fx2 = Factory::deterministic(Seed::new([5u8; 32]));
        let ch1 = fx1.x509_chain("det-chain", ChainSpec::new("det.example.com"));
        let ch2 = fx2.x509_chain("det-chain", ChainSpec::new("det.example.com"));
        assert_eq!(
            ch1.private_key_der_rustls().secret_der(),
            ch2.private_key_der_rustls().secret_der()
        );
    }

    #[test]
    fn different_labels_produce_different_self_signed_certs() {
        let fx = Factory::random();
        let c1 = fx.x509_self_signed("ss-a", X509Spec::self_signed("a.example.com"));
        let c2 = fx.x509_self_signed("ss-b", X509Spec::self_signed("b.example.com"));
        assert_ne!(
            c1.certificate_der_rustls().as_ref(),
            c2.certificate_der_rustls().as_ref()
        );
    }

    #[test]
    fn chain_root_differs_from_leaf() {
        let fx = Factory::random();
        let chain = fx.x509_chain("root-vs-leaf", ChainSpec::new("test.example.com"));
        let root = chain.root_certificate_der_rustls();
        let leaf = chain.certificate_der_rustls();
        assert_ne!(
            root.as_ref(),
            leaf.as_ref(),
            "root and leaf certs must be different"
        );
    }

    #[test]
    fn chain_intermediate_differs_from_leaf_and_root() {
        let fx = Factory::random();
        let chain = fx.x509_chain("inter-test", ChainSpec::new("test.example.com"));
        let certs = chain.chain_der_rustls();
        let root = chain.root_certificate_der_rustls();
        // certs[0] = leaf, certs[1] = intermediate
        assert_ne!(
            certs[0].as_ref(),
            certs[1].as_ref(),
            "leaf and intermediate must differ"
        );
        assert_ne!(
            certs[1].as_ref(),
            root.as_ref(),
            "intermediate and root must differ"
        );
    }

    #[test]
    fn self_signed_key_and_cert_are_non_empty() {
        let fx = Factory::random();
        let cert = fx.x509_self_signed("ne-test", X509Spec::self_signed("test.example.com"));
        assert!(!cert.private_key_der_rustls().secret_der().is_empty());
        assert!(!cert.certificate_der_rustls().as_ref().is_empty());
    }
}
