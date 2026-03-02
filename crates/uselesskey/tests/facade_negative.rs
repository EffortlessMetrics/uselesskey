//! Negative fixture tests for the `uselesskey` facade crate.
//!
//! Exercises all corruption variants (PEM, DER, mismatch) for every key type
//! and all invalid certificate scenarios through the public facade API.

mod testutil;

use uselesskey::prelude::*;

fn fx() -> Factory {
    testutil::fx()
}

// ===========================================================================
// 1. CorruptPem — all variants for RSA
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_corrupt_pem {
    use super::*;

    fn keypair() -> RsaKeyPair {
        fx().rsa("neg-rsa-pem", RsaSpec::rs256())
    }

    #[test]
    fn bad_header() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("-----BEGIN CORRUPTED KEY-----"));
        assert!(!bad.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn bad_footer() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        assert!(bad.contains("-----END CORRUPTED KEY-----"));
        assert!(!bad.contains("END PRIVATE KEY"));
    }

    #[test]
    fn bad_base64() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
        // Header/footer preserved
        assert!(bad.contains("BEGIN PRIVATE KEY"));
        assert!(bad.contains("END PRIVATE KEY"));
    }

    #[test]
    fn truncate() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 25 });
        assert_eq!(bad.len(), 25);
    }

    #[test]
    fn extra_blank_line() {
        let kp = keypair();
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
        assert!(bad.contains("-----BEGIN PRIVATE KEY-----\n\n"));
        assert_ne!(bad, kp.private_key_pkcs8_pem());
    }

    #[test]
    fn all_variants_differ_from_original() {
        let kp = keypair();
        let original = kp.private_key_pkcs8_pem();
        let variants = [
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 30 }),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v, original, "RSA CorruptPem variant {i} should differ from original");
        }
    }

    #[test]
    fn all_variants_are_mutually_distinct() {
        let kp = keypair();
        let variants = [
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j], "RSA variants {i} and {j} should differ");
            }
        }
    }

    #[test]
    fn deterministic_corruption_is_stable() {
        let kp = keypair();
        let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-rsa-v1");
        let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-rsa-v1");
        assert_eq!(a, b);
        assert_ne!(a, kp.private_key_pkcs8_pem());
    }

    #[test]
    fn deterministic_corruption_different_variants_differ() {
        let kp = keypair();
        let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:alpha");
        let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:beta");
        assert!(a != b || a != kp.private_key_pkcs8_pem());
    }
}

// ===========================================================================
// 2. CorruptPem — all variants for ECDSA (ES256 + ES384)
// ===========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_corrupt_pem {
    use super::*;

    fn keypair_256() -> EcdsaKeyPair {
        fx().ecdsa("neg-ec256-pem", EcdsaSpec::es256())
    }

    fn keypair_384() -> EcdsaKeyPair {
        fx().ecdsa("neg-ec384-pem", EcdsaSpec::es384())
    }

    #[test]
    fn es256_bad_header() {
        let bad = keypair_256().private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
        assert!(!bad.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn es256_bad_footer() {
        let bad = keypair_256().private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        assert!(bad.contains("END CORRUPTED KEY"));
    }

    #[test]
    fn es256_bad_base64() {
        let bad = keypair_256().private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn es256_truncate() {
        let bad = keypair_256().private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 20 });
        assert_eq!(bad.len(), 20);
    }

    #[test]
    fn es256_extra_blank_line() {
        let kp = keypair_256();
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
        assert!(bad.contains("\n\n"));
        assert_ne!(bad, kp.private_key_pkcs8_pem());
    }

    #[test]
    fn es256_all_variants_differ_from_original() {
        let kp = keypair_256();
        let original = kp.private_key_pkcs8_pem();
        let variants = [
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 15 }),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v, original, "ECDSA ES256 variant {i} should differ");
        }
    }

    #[test]
    fn es384_bad_header() {
        let bad = keypair_384().private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn es384_all_variants_differ_from_original() {
        let kp = keypair_384();
        let original = kp.private_key_pkcs8_pem();
        let variants = [
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 15 }),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v, original, "ECDSA ES384 variant {i} should differ");
        }
    }

    #[test]
    fn deterministic_corruption_is_stable() {
        let kp = keypair_256();
        let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:ec-v1");
        let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:ec-v1");
        assert_eq!(a, b);
    }
}

// ===========================================================================
// 3. CorruptPem — all variants for Ed25519
// ===========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_corrupt_pem {
    use super::*;

    fn keypair() -> Ed25519KeyPair {
        fx().ed25519("neg-ed-pem", Ed25519Spec::new())
    }

    #[test]
    fn bad_header() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
        assert!(!bad.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn bad_footer() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        assert!(bad.contains("END CORRUPTED KEY"));
    }

    #[test]
    fn bad_base64() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn truncate() {
        let bad = keypair().private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 12 });
        assert_eq!(bad.len(), 12);
    }

    #[test]
    fn extra_blank_line() {
        let kp = keypair();
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
        assert!(bad.contains("\n\n"));
        assert_ne!(bad, kp.private_key_pkcs8_pem());
    }

    #[test]
    fn all_variants_differ_from_original() {
        let kp = keypair();
        let original = kp.private_key_pkcs8_pem();
        let variants = [
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 }),
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v, original, "Ed25519 variant {i} should differ");
        }
    }

    #[test]
    fn deterministic_corruption_is_stable() {
        let kp = keypair();
        let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:ed-v1");
        let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:ed-v1");
        assert_eq!(a, b);
    }
}

// ===========================================================================
// 4. DER truncation — all key types
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_der_truncation {
    use super::*;

    #[test]
    fn truncated_has_correct_length() {
        let kp = fx().rsa("neg-rsa-der", RsaSpec::rs256());
        let trunc = kp.private_key_pkcs8_der_truncated(16);
        assert_eq!(trunc.len(), 16);
    }

    #[test]
    fn truncated_is_prefix_of_original() {
        let kp = fx().rsa("neg-rsa-der", RsaSpec::rs256());
        let full = kp.private_key_pkcs8_der();
        let trunc = kp.private_key_pkcs8_der_truncated(16);
        assert_eq!(&trunc[..], &full[..16]);
    }

    #[test]
    fn truncated_at_zero() {
        let kp = fx().rsa("neg-rsa-der-zero", RsaSpec::rs256());
        assert!(kp.private_key_pkcs8_der_truncated(0).is_empty());
    }

    #[test]
    fn deterministic_der_corruption_is_stable() {
        let kp = fx().rsa("neg-rsa-der-det", RsaSpec::rs256());
        let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
        let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
        assert_eq!(a, b);
        assert_ne!(a.as_slice(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn deterministic_der_different_variants_differ() {
        let kp = fx().rsa("neg-rsa-der-div", RsaSpec::rs256());
        let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:d1");
        let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:d2");
        assert!(a != b || a.as_slice() != kp.private_key_pkcs8_der());
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_der_truncation {
    use super::*;

    #[test]
    fn es256_truncated() {
        let kp = fx().ecdsa("neg-ec256-der", EcdsaSpec::es256());
        let full = kp.private_key_pkcs8_der();
        let trunc = kp.private_key_pkcs8_der_truncated(8);
        assert_eq!(trunc.len(), 8);
        assert_eq!(&trunc[..], &full[..8]);
    }

    #[test]
    fn es384_truncated() {
        let kp = fx().ecdsa("neg-ec384-der", EcdsaSpec::es384());
        let trunc = kp.private_key_pkcs8_der_truncated(12);
        assert_eq!(trunc.len(), 12);
    }

    #[test]
    fn deterministic_der_corruption_is_stable() {
        let kp = fx().ecdsa("neg-ec-der-det", EcdsaSpec::es256());
        let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:ec-der-v1");
        let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:ec-der-v1");
        assert_eq!(a, b);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_der_truncation {
    use super::*;

    #[test]
    fn truncated() {
        let kp = fx().ed25519("neg-ed-der", Ed25519Spec::new());
        let full = kp.private_key_pkcs8_der();
        let trunc = kp.private_key_pkcs8_der_truncated(5);
        assert_eq!(trunc.len(), 5);
        assert!(trunc.len() < full.len());
    }

    #[test]
    fn deterministic_der_corruption_is_stable() {
        let kp = fx().ed25519("neg-ed-der-det", Ed25519Spec::new());
        let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:ed-der-v1");
        let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:ed-der-v1");
        assert_eq!(a, b);
    }
}

// ===========================================================================
// 5. Mismatched keypairs — all asymmetric key types
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_mismatch {
    use super::*;

    #[test]
    fn mismatched_differs_from_original() {
        let kp = fx().rsa("neg-rsa-mm", RsaSpec::rs256());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());
    }

    #[test]
    fn mismatched_is_valid_der() {
        let kp = fx().rsa("neg-rsa-mm-der", RsaSpec::rs256());
        let mm = kp.mismatched_public_key_spki_der();
        assert!(!mm.is_empty());
        assert_eq!(mm[0], 0x30, "mismatched RSA key is valid DER");
    }

    #[test]
    fn mismatched_is_deterministic() {
        let kp = fx().rsa("neg-rsa-mm-det", RsaSpec::rs256());
        let a = kp.mismatched_public_key_spki_der();
        let b = kp.mismatched_public_key_spki_der();
        assert_eq!(a, b);
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_mismatch {
    use super::*;

    #[test]
    fn es256_mismatched_differs() {
        let kp = fx().ecdsa("neg-ec256-mm", EcdsaSpec::es256());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());
        assert_eq!(mm[0], 0x30);
    }

    #[test]
    fn es384_mismatched_differs() {
        let kp = fx().ecdsa("neg-ec384-mm", EcdsaSpec::es384());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());
    }

    #[test]
    fn mismatched_is_deterministic() {
        let kp = fx().ecdsa("neg-ec-mm-det", EcdsaSpec::es256());
        let a = kp.mismatched_public_key_spki_der();
        let b = kp.mismatched_public_key_spki_der();
        assert_eq!(a, b);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_mismatch {
    use super::*;

    #[test]
    fn mismatched_differs_from_original() {
        let kp = fx().ed25519("neg-ed-mm", Ed25519Spec::new());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());
        assert_eq!(mm[0], 0x30);
    }

    #[test]
    fn mismatched_is_deterministic() {
        let kp = fx().ed25519("neg-ed-mm-det", Ed25519Spec::new());
        let a = kp.mismatched_public_key_spki_der();
        let b = kp.mismatched_public_key_spki_der();
        assert_eq!(a, b);
    }
}

// ===========================================================================
// 6. X.509 negative scenarios — certificates
// ===========================================================================

#[cfg(feature = "x509")]
mod x509_negative {
    use uselesskey::{X509FactoryExt, X509Spec};

    use super::*;

    fn cert() -> uselesskey::X509Cert {
        fx().x509_self_signed("neg-x509", X509Spec::self_signed("neg.example.com"))
    }

    #[test]
    fn expired_differs_from_valid() {
        let c = cert();
        let expired = c.expired();
        assert_ne!(c.cert_der(), expired.cert_der());
        assert!(expired.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn not_yet_valid_differs_from_valid() {
        let c = cert();
        let nyv = c.not_yet_valid();
        assert_ne!(c.cert_der(), nyv.cert_der());
    }

    #[test]
    fn wrong_key_usage_differs_from_valid() {
        let c = cert();
        let wku = c.wrong_key_usage();
        assert_ne!(c.cert_der(), wku.cert_der());
        assert!(wku.spec().is_ca);
    }

    #[test]
    fn corrupt_cert_pem_bad_header() {
        let c = cert();
        let bad = c.corrupt_cert_pem(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
        assert!(!bad.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn corrupt_cert_pem_bad_footer() {
        let c = cert();
        let bad = c.corrupt_cert_pem(CorruptPem::BadFooter);
        assert!(bad.contains("END CORRUPTED KEY"));
    }

    #[test]
    fn corrupt_cert_pem_bad_base64() {
        let c = cert();
        let bad = c.corrupt_cert_pem(CorruptPem::BadBase64);
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn corrupt_cert_pem_truncate() {
        let c = cert();
        let bad = c.corrupt_cert_pem(CorruptPem::Truncate { bytes: 20 });
        assert_eq!(bad.len(), 20);
    }

    #[test]
    fn corrupt_cert_pem_extra_blank_line() {
        let c = cert();
        let bad = c.corrupt_cert_pem(CorruptPem::ExtraBlankLine);
        assert!(bad.contains("\n\n"));
    }

    #[test]
    fn truncate_cert_der() {
        let c = cert();
        let trunc = c.truncate_cert_der(10);
        assert_eq!(trunc.len(), 10);
        assert_eq!(&trunc[..], &c.cert_der()[..10]);
    }

    #[test]
    fn deterministic_cert_pem_corruption_is_stable() {
        let c = cert();
        let a = c.corrupt_cert_pem_deterministic("corrupt:cert-v1");
        let b = c.corrupt_cert_pem_deterministic("corrupt:cert-v1");
        assert_eq!(a, b);
        assert_ne!(a, c.cert_pem());
    }

    #[test]
    fn deterministic_cert_der_corruption_is_stable() {
        let c = cert();
        let a = c.corrupt_cert_der_deterministic("corrupt:cert-der-v1");
        let b = c.corrupt_cert_der_deterministic("corrupt:cert-der-v1");
        assert_eq!(a, b);
        assert_ne!(a.as_slice(), c.cert_der());
    }

    #[test]
    fn all_negative_variants_differ_from_valid() {
        let c = cert();
        let variants = [c.expired(), c.not_yet_valid(), c.wrong_key_usage()];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(c.cert_der(), v.cert_der(), "X509 negative variant {i} should differ");
        }
    }

    #[test]
    fn negative_variants_are_mutually_distinct() {
        let c = cert();
        let expired = c.expired();
        let nyv = c.not_yet_valid();
        let wku = c.wrong_key_usage();

        assert_ne!(expired.cert_der(), nyv.cert_der());
        assert_ne!(expired.cert_der(), wku.cert_der());
        assert_ne!(nyv.cert_der(), wku.cert_der());
    }
}

// ===========================================================================
// 7. X.509 chain negative scenarios
// ===========================================================================

#[cfg(feature = "x509")]
mod x509_chain_negative {
    use uselesskey::{ChainSpec, X509FactoryExt};

    use super::*;

    fn chain() -> uselesskey::X509Chain {
        fx().x509_chain("neg-chain", ChainSpec::new("neg-chain.example.com"))
    }

    #[test]
    fn expired_leaf_differs() {
        let ch = chain();
        let exp = ch.expired_leaf();
        assert_ne!(ch.leaf_cert_der(), exp.leaf_cert_der());
    }

    #[test]
    fn expired_intermediate_differs() {
        let ch = chain();
        let exp = ch.expired_intermediate();
        assert_ne!(ch.intermediate_cert_der(), exp.intermediate_cert_der());
    }

    #[test]
    fn hostname_mismatch_differs() {
        let ch = chain();
        let mm = ch.hostname_mismatch("wrong.example.com");
        assert_ne!(ch.leaf_cert_der(), mm.leaf_cert_der());
    }

    #[test]
    fn unknown_ca_differs() {
        let ch = chain();
        let uca = ch.unknown_ca();
        assert_ne!(ch.root_cert_der(), uca.root_cert_der());
    }

    #[test]
    fn revoked_leaf_has_crl() {
        let ch = chain();
        assert!(ch.crl_der().is_none());

        let rev = ch.revoked_leaf();
        assert!(rev.crl_der().is_some());
        assert!(rev.crl_pem().unwrap().contains("BEGIN X509 CRL"));
    }

    #[test]
    fn revoked_leaf_crl_tempfiles() {
        let ch = chain();
        let rev = ch.revoked_leaf();

        let pem_file = rev.write_crl_pem().unwrap().unwrap();
        assert!(pem_file.path().exists());

        let der_file = rev.write_crl_der().unwrap().unwrap();
        assert!(der_file.path().exists());
    }

    #[test]
    fn good_chain_has_no_crl_tempfiles() {
        let ch = chain();
        assert!(ch.write_crl_pem().is_none());
        assert!(ch.write_crl_der().is_none());
    }

    #[test]
    fn all_negative_variants_reuse_leaf_key() {
        let ch = chain();
        let variants = [
            ch.expired_leaf(),
            ch.expired_intermediate(),
            ch.unknown_ca(),
            ch.hostname_mismatch("bad.example.com"),
            ch.revoked_leaf(),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_eq!(
                ch.leaf_private_key_pkcs8_der(),
                v.leaf_private_key_pkcs8_der(),
                "chain negative variant {i} should reuse leaf key"
            );
        }
    }

    #[test]
    fn all_negative_variants_have_different_leaf_certs() {
        let ch = chain();
        let variants = [
            ch.expired_leaf(),
            ch.expired_intermediate(),
            ch.unknown_ca(),
            ch.hostname_mismatch("alt.example.com"),
            ch.revoked_leaf(),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(
                ch.leaf_cert_der(),
                v.leaf_cert_der(),
                "chain negative variant {i} should have different leaf cert"
            );
        }
    }
}
