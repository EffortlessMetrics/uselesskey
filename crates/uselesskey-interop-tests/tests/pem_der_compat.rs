//! PEM / DER format compatibility tests.
//!
//! Verifies that PEM and DER outputs from uselesskey are consistent with each
//! other and parseable by multiple crypto backends.

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-pem-der-compat-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

// =========================================================================
// RSA PEM/DER consistency
// =========================================================================

mod rsa_pem_der {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn private_pem_matches_der() {
        let kp = fx().rsa("pem-rsa-priv", RsaSpec::rs256());
        let pem = kp.private_key_pkcs8_pem();
        let der = kp.private_key_pkcs8_der();

        // Extract DER from PEM
        let pem_der = pem_to_der(pem);
        assert_eq!(pem_der, der, "PEM-decoded DER must match raw DER");
    }

    #[test]
    fn public_pem_matches_der() {
        let kp = fx().rsa("pem-rsa-pub", RsaSpec::rs256());
        let pem = kp.public_key_spki_pem();
        let der = kp.public_key_spki_der();

        let pem_der = pem_to_der(pem);
        assert_eq!(pem_der, der, "PEM-decoded SPKI DER must match raw DER");
    }

    #[test]
    fn pem_parseable_by_rustcrypto() {
        let kp = fx().rsa("pem-rsa-rc", RsaSpec::rs256());
        let pem = kp.private_key_pkcs8_pem();

        use rsa::pkcs8::DecodePrivateKey;
        let _priv_key =
            rsa::RsaPrivateKey::from_pkcs8_pem(pem).expect("rustcrypto should parse RSA PEM");
    }

    #[test]
    fn der_parseable_by_ring() {
        let kp = fx().rsa("pem-rsa-ring", RsaSpec::rs256());
        let _ring_kp = ring::rsa::KeyPair::from_pkcs8(kp.private_key_pkcs8_der())
            .expect("ring should parse RSA DER");
    }

    #[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
    #[test]
    fn der_parseable_by_aws_lc_rs() {
        let kp = fx().rsa("pem-rsa-aws", RsaSpec::rs256());
        let _aws_kp = aws_lc_rs::rsa::KeyPair::from_pkcs8(kp.private_key_pkcs8_der())
            .expect("aws-lc-rs should parse RSA DER");
    }
}

// =========================================================================
// ECDSA PEM/DER consistency
// =========================================================================

mod ecdsa_pem_der {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn p256_private_pem_matches_der() {
        let kp = fx().ecdsa("pem-p256-priv", EcdsaSpec::es256());
        let pem_der = pem_to_der(kp.private_key_pkcs8_pem());
        assert_eq!(pem_der, kp.private_key_pkcs8_der());
    }

    #[test]
    fn p256_public_pem_matches_der() {
        let kp = fx().ecdsa("pem-p256-pub", EcdsaSpec::es256());
        let pem_der = pem_to_der(kp.public_key_spki_pem());
        assert_eq!(pem_der, kp.public_key_spki_der());
    }

    #[test]
    fn p384_private_pem_matches_der() {
        let kp = fx().ecdsa("pem-p384-priv", EcdsaSpec::es384());
        let pem_der = pem_to_der(kp.private_key_pkcs8_pem());
        assert_eq!(pem_der, kp.private_key_pkcs8_der());
    }

    #[test]
    fn p384_public_pem_matches_der() {
        let kp = fx().ecdsa("pem-p384-pub", EcdsaSpec::es384());
        let pem_der = pem_to_der(kp.public_key_spki_pem());
        assert_eq!(pem_der, kp.public_key_spki_der());
    }

    #[test]
    fn p256_pem_parseable_by_rustcrypto() {
        let kp = fx().ecdsa("pem-p256-rc", EcdsaSpec::es256());
        use p256::pkcs8::DecodePrivateKey;
        let _sk = p256::ecdsa::SigningKey::from_pkcs8_pem(kp.private_key_pkcs8_pem())
            .expect("rustcrypto should parse P-256 PEM");
    }

    #[test]
    fn p384_pem_parseable_by_rustcrypto() {
        let kp = fx().ecdsa("pem-p384-rc", EcdsaSpec::es384());
        use p384::pkcs8::DecodePrivateKey;
        let _sk = p384::ecdsa::SigningKey::from_pkcs8_pem(kp.private_key_pkcs8_pem())
            .expect("rustcrypto should parse P-384 PEM");
    }

    #[test]
    fn p256_der_parseable_by_ring() {
        let kp = fx().ecdsa("pem-p256-ring", EcdsaSpec::es256());
        let _ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("ring should parse P-256 DER");
    }

    #[test]
    fn p384_der_parseable_by_ring() {
        let kp = fx().ecdsa("pem-p384-ring", EcdsaSpec::es384());
        let _ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("ring should parse P-384 DER");
    }
}

// =========================================================================
// Ed25519 PEM/DER consistency
// =========================================================================

mod ed25519_pem_der {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn private_pem_matches_der() {
        let kp = fx().ed25519("pem-ed-priv", Ed25519Spec::new());
        let pem_der = pem_to_der(kp.private_key_pkcs8_pem());
        assert_eq!(pem_der, kp.private_key_pkcs8_der());
    }

    #[test]
    fn public_pem_matches_der() {
        let kp = fx().ed25519("pem-ed-pub", Ed25519Spec::new());
        let pem_der = pem_to_der(kp.public_key_spki_pem());
        assert_eq!(pem_der, kp.public_key_spki_der());
    }

    #[test]
    fn pem_parseable_by_rustcrypto() {
        let kp = fx().ed25519("pem-ed-rc", Ed25519Spec::new());
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let _sk = ed25519_dalek::SigningKey::from_pkcs8_pem(kp.private_key_pkcs8_pem())
            .expect("rustcrypto should parse Ed25519 PEM");
    }

    #[test]
    fn der_parseable_by_ring() {
        let kp = fx().ed25519("pem-ed-ring", Ed25519Spec::new());
        let _ring_kp =
            ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(kp.private_key_pkcs8_der())
                .expect("ring should parse Ed25519 DER");
    }
}

// =========================================================================
// X.509 PEM/DER consistency
// =========================================================================

#[cfg(feature = "cross-tls")]
mod x509_pem_der {
    use super::*;
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    #[test]
    fn self_signed_cert_pem_matches_der() {
        let cert = fx().x509_self_signed("pem-x509-ss", X509Spec::self_signed("pem.example.com"));
        let pem_der = pem_to_der(cert.cert_pem());
        assert_eq!(pem_der, cert.cert_der());
    }

    #[test]
    fn self_signed_key_pem_matches_der() {
        let cert =
            fx().x509_self_signed("pem-x509-key", X509Spec::self_signed("pemkey.example.com"));
        let pem_der = pem_to_der(cert.private_key_pkcs8_pem());
        assert_eq!(pem_der, cert.private_key_pkcs8_der());
    }

    #[test]
    fn chain_leaf_cert_pem_matches_der() {
        let chain = fx().x509_chain("pem-x509-chain", ChainSpec::new("pemchain.example.com"));
        let pem_der = pem_to_der(chain.leaf_cert_pem());
        assert_eq!(pem_der, chain.leaf_cert_der());
    }

    #[test]
    fn chain_root_cert_pem_matches_der() {
        let chain = fx().x509_chain("pem-x509-root", ChainSpec::new("pemchainroot.example.com"));
        let pem_der = pem_to_der(chain.root_cert_pem());
        assert_eq!(pem_der, chain.root_cert_der());
    }
}

// =========================================================================
// Rustls pki-types conversions
// =========================================================================

#[cfg(feature = "cross-tls")]
mod rustls_pki_conversions {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn rsa_private_key_der_rustls_nonempty() {
        let kp = fx().rsa("pem-rustls-rsa", RsaSpec::rs256());
        let der = kp.private_key_der_rustls();
        assert!(!der.secret_der().is_empty());
    }

    #[test]
    fn ecdsa_p256_private_key_der_rustls_nonempty() {
        let kp = fx().ecdsa("pem-rustls-p256", EcdsaSpec::es256());
        let der = kp.private_key_der_rustls();
        assert!(!der.secret_der().is_empty());
    }

    #[test]
    fn ecdsa_p384_private_key_der_rustls_nonempty() {
        let kp = fx().ecdsa("pem-rustls-p384", EcdsaSpec::es384());
        let der = kp.private_key_der_rustls();
        assert!(!der.secret_der().is_empty());
    }

    #[test]
    fn ed25519_private_key_der_rustls_nonempty() {
        let kp = fx().ed25519("pem-rustls-ed", Ed25519Spec::new());
        let der = kp.private_key_der_rustls();
        assert!(!der.secret_der().is_empty());
    }
}

// =========================================================================
// PEM helper
// =========================================================================

/// Decode PEM to raw DER bytes by stripping headers and base64 decoding.
fn pem_to_der(pem: impl AsRef<str>) -> Vec<u8> {
    use base64::Engine;
    let b64: String = pem
        .as_ref()
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("valid base64 in PEM")
}
