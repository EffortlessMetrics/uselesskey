#![forbid(unsafe_code)]

use rustls_pki_types::PrivateKeyDer;

// ---------------------------------------------------------------------------
// RSA adapter
// ---------------------------------------------------------------------------

#[cfg(feature = "rsa")]
mod rsa_tests {
    use super::*;
    use uselesskey_core::Factory;
    use uselesskey_core_rustls_pki::RustlsPrivateKeyExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_private_key_roundtrips_through_rustls() {
        let fx = Factory::random();
        let kp = fx.rsa("rsa-pki-test", RsaSpec::rs256());

        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn rsa_key_is_pkcs8_variant() {
        let fx = Factory::random();
        let kp = fx.rsa("rsa-variant", RsaSpec::rs256());

        let key = kp.private_key_der_rustls();
        assert!(
            matches!(key, PrivateKeyDer::Pkcs8(_)),
            "expected PKCS#8 variant"
        );
    }

    #[test]
    fn rsa_key_der_is_non_empty() {
        let fx = Factory::random();
        let kp = fx.rsa("rsa-nonempty", RsaSpec::rs256());

        let key = kp.private_key_der_rustls();
        assert!(
            !key.secret_der().is_empty(),
            "private key DER must not be empty"
        );
    }
}

// ---------------------------------------------------------------------------
// ECDSA adapter
// ---------------------------------------------------------------------------

#[cfg(feature = "ecdsa")]
mod ecdsa_tests {
    use super::*;
    use uselesskey_core::Factory;
    use uselesskey_core_rustls_pki::RustlsPrivateKeyExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn ecdsa_es256_private_key_roundtrips() {
        let fx = Factory::random();
        let kp = fx.ecdsa("ec256-pki", EcdsaSpec::es256());

        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ecdsa_es384_private_key_roundtrips() {
        let fx = Factory::random();
        let kp = fx.ecdsa("ec384-pki", EcdsaSpec::es384());

        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ecdsa_key_is_pkcs8_variant() {
        let fx = Factory::random();
        let kp = fx.ecdsa("ec-variant", EcdsaSpec::es256());

        let key = kp.private_key_der_rustls();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }
}

// ---------------------------------------------------------------------------
// Ed25519 adapter
// ---------------------------------------------------------------------------

#[cfg(feature = "ed25519")]
mod ed25519_tests {
    use super::*;
    use uselesskey_core::Factory;
    use uselesskey_core_rustls_pki::RustlsPrivateKeyExt;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ed25519_private_key_roundtrips() {
        let fx = Factory::random();
        let kp = fx.ed25519("ed-pki", Ed25519Spec::new());

        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ed25519_key_is_pkcs8_variant() {
        let fx = Factory::random();
        let kp = fx.ed25519("ed-variant", Ed25519Spec::new());

        let key = kp.private_key_der_rustls();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }
}

// ---------------------------------------------------------------------------
// X.509 self-signed adapter
// ---------------------------------------------------------------------------

#[cfg(feature = "x509")]
mod x509_self_signed_tests {
    use super::*;
    use uselesskey_core::Factory;
    use uselesskey_core_rustls_pki::{RustlsCertExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{X509FactoryExt, X509Spec};

    #[test]
    fn self_signed_private_key_roundtrips() {
        let fx = Factory::random();
        let cert = fx.x509_self_signed("ss-pki", X509Spec::self_signed("test.example.com"));

        let key = cert.private_key_der_rustls();
        assert_eq!(key.secret_der(), cert.private_key_pkcs8_der());
    }

    #[test]
    fn self_signed_key_is_pkcs8_variant() {
        let fx = Factory::random();
        let cert = fx.x509_self_signed("ss-var", X509Spec::self_signed("test.example.com"));

        let key = cert.private_key_der_rustls();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn self_signed_certificate_roundtrips() {
        let fx = Factory::random();
        let cert = fx.x509_self_signed("ss-cert", X509Spec::self_signed("test.example.com"));

        let cert_der = cert.certificate_der_rustls();
        assert_eq!(cert_der.as_ref(), cert.cert_der());
    }

    #[test]
    fn self_signed_cert_der_is_non_empty() {
        let fx = Factory::random();
        let cert = fx.x509_self_signed("ss-ne", X509Spec::self_signed("test.example.com"));

        let cert_der = cert.certificate_der_rustls();
        assert!(!cert_der.as_ref().is_empty());
    }
}

// ---------------------------------------------------------------------------
// X.509 chain adapter
// ---------------------------------------------------------------------------

#[cfg(feature = "x509")]
mod x509_chain_tests {
    use super::*;
    use uselesskey_core::Factory;
    use uselesskey_core_rustls_pki::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    #[test]
    fn chain_private_key_roundtrips() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ch-pki", ChainSpec::new("test.example.com"));

        let key = chain.private_key_der_rustls();
        assert_eq!(key.secret_der(), chain.leaf_private_key_pkcs8_der());
    }

    #[test]
    fn chain_key_is_pkcs8_variant() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ch-var", ChainSpec::new("test.example.com"));

        let key = chain.private_key_der_rustls();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn chain_leaf_certificate_roundtrips() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ch-leaf", ChainSpec::new("test.example.com"));

        let cert_der = chain.certificate_der_rustls();
        assert_eq!(cert_der.as_ref(), chain.leaf_cert_der());
    }

    #[test]
    fn chain_der_has_leaf_and_intermediate() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ch-chain", ChainSpec::new("test.example.com"));

        let certs = chain.chain_der_rustls();
        assert_eq!(certs.len(), 2, "chain should have leaf + intermediate");
        assert_eq!(certs[0].as_ref(), chain.leaf_cert_der());
        assert_eq!(certs[1].as_ref(), chain.intermediate_cert_der());
    }

    #[test]
    fn root_certificate_roundtrips() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ch-root", ChainSpec::new("test.example.com"));

        let root = chain.root_certificate_der_rustls();
        assert_eq!(root.as_ref(), chain.root_cert_der());
    }

    #[test]
    fn chain_certs_are_all_non_empty() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ch-ne", ChainSpec::new("test.example.com"));

        for cert in &chain.chain_der_rustls() {
            assert!(!cert.as_ref().is_empty());
        }
        assert!(!chain.root_certificate_der_rustls().as_ref().is_empty());
    }
}
