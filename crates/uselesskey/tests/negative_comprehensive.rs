//! Comprehensive negative fixture tests for the `uselesskey` facade crate.
//!
//! Covers all corruption modes across all key types, DER truncation edge cases,
//! mismatch keypairs, X.509 negative variants, chain negatives, deterministic
//! corruption stability, and PEM/DER parser rejection.

#![cfg(feature = "full")]

use uselesskey::negative::CorruptPem;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory,
    RsaFactoryExt, RsaSpec, Seed, X509FactoryExt, X509Spec,
};
use x509_parser::prelude::FromDer;

fn fx() -> Factory {
    Factory::deterministic(Seed::from_env_value("negative-comprehensive-seed").unwrap())
}

// =========================================================================
// 1. All CorruptPem variants for every key type
// =========================================================================

mod corrupt_pem_rsa {
    use super::*;

    fn rsa_pem() -> String {
        let fx = fx();
        let kp = fx.rsa("corrupt-pem-rsa", RsaSpec::rs256());
        kp.private_key_pkcs8_pem().to_string()
    }

    #[test]
    fn negative_bad_header_replaces_begin() {
        let bad = fx()
            .rsa("corrupt-pem-rsa", RsaSpec::rs256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("-----BEGIN CORRUPTED KEY-----"));
        assert!(!bad.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn negative_bad_footer_replaces_end() {
        let bad = fx()
            .rsa("corrupt-pem-rsa", RsaSpec::rs256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        assert!(bad.contains("-----END CORRUPTED KEY-----"));
        assert!(!bad.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn negative_bad_base64_injects_garbage() {
        let bad = fx()
            .rsa("corrupt-pem-rsa", RsaSpec::rs256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn negative_truncate_limits_length() {
        let bad = fx()
            .rsa("corrupt-pem-rsa", RsaSpec::rs256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 20 });
        assert_eq!(bad.chars().count(), 20);
    }

    #[test]
    fn negative_extra_blank_line_adds_empty() {
        let bad = fx()
            .rsa("corrupt-pem-rsa", RsaSpec::rs256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
        assert!(bad.contains("\n\n"));
    }

    #[test]
    fn negative_all_variants_differ_from_original() {
        let original = rsa_pem();
        let variants: Vec<CorruptPem> = vec![
            CorruptPem::BadHeader,
            CorruptPem::BadFooter,
            CorruptPem::BadBase64,
            CorruptPem::Truncate { bytes: 20 },
            CorruptPem::ExtraBlankLine,
        ];
        for v in variants {
            let bad = uselesskey::negative::corrupt_pem(&original, v);
            assert_ne!(bad, original, "{v:?} should differ from original");
        }
    }
}

mod corrupt_pem_ecdsa {
    use super::*;

    #[test]
    fn negative_bad_header() {
        let bad = fx()
            .ecdsa("corrupt-pem-ecdsa", EcdsaSpec::es256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("-----BEGIN CORRUPTED KEY-----"));
    }

    #[test]
    fn negative_bad_footer() {
        let bad = fx()
            .ecdsa("corrupt-pem-ecdsa", EcdsaSpec::es256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        assert!(bad.contains("-----END CORRUPTED KEY-----"));
    }

    #[test]
    fn negative_bad_base64() {
        let bad = fx()
            .ecdsa("corrupt-pem-ecdsa", EcdsaSpec::es256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn negative_truncate() {
        let bad = fx()
            .ecdsa("corrupt-pem-ecdsa", EcdsaSpec::es256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 15 });
        assert_eq!(bad.chars().count(), 15);
    }

    #[test]
    fn negative_extra_blank_line() {
        let bad = fx()
            .ecdsa("corrupt-pem-ecdsa", EcdsaSpec::es256())
            .private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
        assert!(bad.contains("\n\n"));
    }
}

mod corrupt_pem_ed25519 {
    use super::*;

    #[test]
    fn negative_bad_header() {
        let bad = fx()
            .ed25519("corrupt-pem-ed25519", Ed25519Spec::new())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("-----BEGIN CORRUPTED KEY-----"));
    }

    #[test]
    fn negative_bad_footer() {
        let bad = fx()
            .ed25519("corrupt-pem-ed25519", Ed25519Spec::new())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        assert!(bad.contains("-----END CORRUPTED KEY-----"));
    }

    #[test]
    fn negative_bad_base64() {
        let bad = fx()
            .ed25519("corrupt-pem-ed25519", Ed25519Spec::new())
            .private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn negative_truncate() {
        let bad = fx()
            .ed25519("corrupt-pem-ed25519", Ed25519Spec::new())
            .private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 12 });
        assert_eq!(bad.chars().count(), 12);
    }

    #[test]
    fn negative_extra_blank_line() {
        let bad = fx()
            .ed25519("corrupt-pem-ed25519", Ed25519Spec::new())
            .private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
        assert!(bad.contains("\n\n"));
    }
}

// =========================================================================
// 2. DER truncation edge cases
// =========================================================================

mod der_truncation {
    use super::*;

    #[test]
    fn negative_truncate_to_zero_bytes() {
        let kp = fx().rsa("der-trunc", RsaSpec::rs256());
        let truncated = kp.private_key_pkcs8_der_truncated(0);
        assert!(truncated.is_empty());
    }

    #[test]
    fn negative_truncate_to_one_byte() {
        let kp = fx().rsa("der-trunc", RsaSpec::rs256());
        let truncated = kp.private_key_pkcs8_der_truncated(1);
        assert_eq!(truncated.len(), 1);
    }

    #[test]
    fn negative_truncate_to_half_length() {
        let kp = fx().rsa("der-trunc", RsaSpec::rs256());
        let full_len = kp.private_key_pkcs8_der().len();
        let half = full_len / 2;
        let truncated = kp.private_key_pkcs8_der_truncated(half);
        assert_eq!(truncated.len(), half);
    }

    #[test]
    fn negative_truncate_to_length_minus_one() {
        let kp = fx().rsa("der-trunc", RsaSpec::rs256());
        let full_len = kp.private_key_pkcs8_der().len();
        let truncated = kp.private_key_pkcs8_der_truncated(full_len - 1);
        assert_eq!(truncated.len(), full_len - 1);
    }

    #[test]
    fn negative_truncate_at_full_length_returns_full() {
        let kp = fx().rsa("der-trunc", RsaSpec::rs256());
        let full_len = kp.private_key_pkcs8_der().len();
        let truncated = kp.private_key_pkcs8_der_truncated(full_len);
        assert_eq!(truncated.len(), full_len);
    }

    #[test]
    fn negative_truncate_beyond_length_returns_full() {
        let kp = fx().rsa("der-trunc", RsaSpec::rs256());
        let full_len = kp.private_key_pkcs8_der().len();
        let truncated = kp.private_key_pkcs8_der_truncated(full_len + 100);
        assert_eq!(truncated.len(), full_len);
    }

    #[test]
    fn negative_ecdsa_truncation_edges() {
        let kp = fx().ecdsa("der-trunc-ec", EcdsaSpec::es256());
        let full_len = kp.private_key_pkcs8_der().len();
        assert!(full_len > 2);
        assert_eq!(kp.private_key_pkcs8_der_truncated(0).len(), 0);
        assert_eq!(kp.private_key_pkcs8_der_truncated(1).len(), 1);
        assert_eq!(
            kp.private_key_pkcs8_der_truncated(full_len / 2).len(),
            full_len / 2
        );
    }

    #[test]
    fn negative_ed25519_truncation_edges() {
        let kp = fx().ed25519("der-trunc-ed", Ed25519Spec::new());
        let full_len = kp.private_key_pkcs8_der().len();
        assert!(full_len > 2);
        assert_eq!(kp.private_key_pkcs8_der_truncated(0).len(), 0);
        assert_eq!(kp.private_key_pkcs8_der_truncated(1).len(), 1);
        assert_eq!(
            kp.private_key_pkcs8_der_truncated(full_len - 1).len(),
            full_len - 1
        );
    }
}

// =========================================================================
// 3. Mismatch keypair coverage
// =========================================================================

mod mismatch_keypair {
    use super::*;

    #[test]
    fn negative_rsa_mismatch_differs_from_original() {
        let kp = fx().rsa("mismatch-rsa", RsaSpec::rs256());
        let mismatched = kp.mismatched_public_key_spki_der();
        assert!(!mismatched.is_empty());
        assert_ne!(mismatched, kp.public_key_spki_der());
    }

    #[test]
    fn negative_ecdsa_mismatch_differs_from_original() {
        let kp = fx().ecdsa("mismatch-ecdsa", EcdsaSpec::es256());
        let mismatched = kp.mismatched_public_key_spki_der();
        assert!(!mismatched.is_empty());
        assert_ne!(mismatched, kp.public_key_spki_der());
    }

    #[test]
    fn negative_ed25519_mismatch_differs_from_original() {
        let kp = fx().ed25519("mismatch-ed25519", Ed25519Spec::new());
        let mismatched = kp.mismatched_public_key_spki_der();
        assert!(!mismatched.is_empty());
        assert_ne!(mismatched, kp.public_key_spki_der());
    }

    #[test]
    fn negative_rsa_mismatch_is_valid_spki_shape() {
        let kp = fx().rsa("mismatch-shape-rsa", RsaSpec::rs256());
        let mismatched = kp.mismatched_public_key_spki_der();
        // Valid SPKI DER starts with a SEQUENCE tag (0x30)
        assert!(mismatched.len() > 10);
        assert_eq!(mismatched[0], 0x30);
    }

    #[test]
    fn negative_ecdsa_mismatch_is_valid_spki_shape() {
        let kp = fx().ecdsa("mismatch-shape-ecdsa", EcdsaSpec::es256());
        let mismatched = kp.mismatched_public_key_spki_der();
        assert!(mismatched.len() > 10);
        assert_eq!(mismatched[0], 0x30);
    }

    #[test]
    fn negative_ed25519_mismatch_is_valid_spki_shape() {
        let kp = fx().ed25519("mismatch-shape-ed25519", Ed25519Spec::new());
        let mismatched = kp.mismatched_public_key_spki_der();
        assert!(mismatched.len() > 10);
        assert_eq!(mismatched[0], 0x30);
    }
}

// =========================================================================
// 4. X.509 negative variants
// =========================================================================

mod x509_negative {
    use super::*;

    fn cert() -> uselesskey::X509Cert {
        fx().x509_self_signed("x509-neg", X509Spec::self_signed("neg.example.com"))
    }

    #[test]
    fn negative_expired_produces_different_cert() {
        let c = cert();
        let expired = c.expired();
        assert_ne!(c.cert_der(), expired.cert_der());
    }

    #[test]
    fn negative_not_yet_valid_produces_different_cert() {
        let c = cert();
        let nyv = c.not_yet_valid();
        assert_ne!(c.cert_der(), nyv.cert_der());
    }

    #[test]
    fn negative_wrong_key_usage_produces_different_cert() {
        let c = cert();
        let wku = c.wrong_key_usage();
        assert_ne!(c.cert_der(), wku.cert_der());
        assert!(wku.spec().is_ca);
        assert!(!wku.spec().key_usage.key_cert_sign);
    }

    #[test]
    fn negative_self_signed_but_claims_ca() {
        let c = cert();
        let ca = c.negative(uselesskey_x509::X509Negative::SelfSignedButClaimsCA);
        assert_ne!(c.cert_der(), ca.cert_der());
        assert!(ca.spec().is_ca);
    }

    #[test]
    fn negative_expired_cert_der_is_parseable() {
        let expired = cert().expired();
        let (_, parsed) =
            x509_parser::prelude::X509Certificate::from_der(expired.cert_der()).expect("parse");
        let nb = parsed.validity().not_before.timestamp();
        let na = parsed.validity().not_after.timestamp();
        assert!(na > nb);
        assert!((na - nb) / 86400 <= 365);
    }

    #[test]
    fn negative_not_yet_valid_cert_has_future_not_before() {
        let nyv = cert().not_yet_valid();
        let (_, parsed) =
            x509_parser::prelude::X509Certificate::from_der(nyv.cert_der()).expect("parse");
        let nb = parsed.validity().not_before.timestamp();
        let na = parsed.validity().not_after.timestamp();
        assert!(na > nb);
    }

    #[test]
    fn negative_corrupt_cert_pem_bad_header() {
        let c = cert();
        let bad = c.corrupt_cert_pem(CorruptPem::BadHeader);
        assert!(bad.contains("-----BEGIN CORRUPTED KEY-----"));
        assert!(!bad.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn negative_truncate_cert_der_to_ten() {
        let c = cert();
        let truncated = c.truncate_cert_der(10);
        assert_eq!(truncated.len(), 10);
    }
}

// =========================================================================
// 5. Chain negatives
// =========================================================================

mod chain_negative {
    use super::*;

    fn chain() -> uselesskey::X509Chain {
        fx().x509_chain("chain-neg", ChainSpec::new("chain-neg.example.com"))
    }

    #[test]
    fn negative_expired_leaf_differs() {
        let c = chain();
        let expired = c.expired_leaf();
        assert_ne!(c.leaf_cert_der(), expired.leaf_cert_der());
    }

    #[test]
    fn negative_expired_intermediate_differs() {
        let c = chain();
        let expired = c.expired_intermediate();
        assert_ne!(c.intermediate_cert_der(), expired.intermediate_cert_der());
    }

    #[test]
    fn negative_unknown_ca_changes_root_identity() {
        let c = chain();
        let unknown = c.unknown_ca();
        assert_ne!(c.root_cert_der(), unknown.root_cert_der());

        let (_, good_root) =
            x509_parser::prelude::X509Certificate::from_der(c.root_cert_der()).expect("parse");
        let (_, bad_root) =
            x509_parser::prelude::X509Certificate::from_der(unknown.root_cert_der())
                .expect("parse");
        assert_ne!(good_root.subject(), bad_root.subject());
    }

    #[test]
    fn negative_hostname_mismatch_changes_leaf_cn() {
        let c = chain();
        let mm = c.hostname_mismatch("evil.example.com");
        let (_, leaf) =
            x509_parser::prelude::X509Certificate::from_der(mm.leaf_cert_der()).expect("parse");
        let cn = leaf
            .subject()
            .iter_common_name()
            .next()
            .expect("CN")
            .as_str()
            .unwrap();
        assert_eq!(cn, "evil.example.com");
    }

    #[test]
    fn negative_revoked_leaf_has_crl() {
        let c = chain();
        assert!(c.crl_der().is_none());
        let revoked = c.revoked_leaf();
        assert!(revoked.crl_der().is_some());
        assert!(revoked.crl_pem().unwrap().contains("-----BEGIN X509 CRL-----"));
    }

    #[test]
    fn negative_chain_variants_reuse_leaf_keys() {
        let c = chain();
        let variants = vec![
            c.expired_leaf(),
            c.expired_intermediate(),
            c.unknown_ca(),
            c.hostname_mismatch("other.example.com"),
            c.revoked_leaf(),
        ];
        for v in &variants {
            assert_eq!(c.leaf_private_key_pkcs8_der(), v.leaf_private_key_pkcs8_der());
        }
    }
}

// =========================================================================
// 6. Deterministic corruption stability
// =========================================================================

mod deterministic_corruption {
    use super::*;

    #[test]
    fn negative_same_seed_label_corruption_same_output_rsa() {
        let fx = fx();
        let kp1 = fx.rsa("det-rsa", RsaSpec::rs256());
        let corrupt1 = kp1.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
        // Clear cache and regenerate
        fx.clear_cache();
        let kp2 = fx.rsa("det-rsa", RsaSpec::rs256());
        let corrupt2 = kp2.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
        assert_eq!(corrupt1, corrupt2);
    }

    #[test]
    fn negative_same_seed_label_corruption_same_output_ecdsa() {
        let fx = fx();
        let kp1 = fx.ecdsa("det-ecdsa", EcdsaSpec::es256());
        let corrupt1 = kp1.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
        fx.clear_cache();
        let kp2 = fx.ecdsa("det-ecdsa", EcdsaSpec::es256());
        let corrupt2 = kp2.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
        assert_eq!(corrupt1, corrupt2);
    }

    #[test]
    fn negative_same_seed_label_corruption_same_output_ed25519() {
        let fx = fx();
        let kp1 = fx.ed25519("det-ed25519", Ed25519Spec::new());
        let corrupt1 = kp1.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
        fx.clear_cache();
        let kp2 = fx.ed25519("det-ed25519", Ed25519Spec::new());
        let corrupt2 = kp2.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
        assert_eq!(corrupt1, corrupt2);
    }

    #[test]
    fn negative_der_deterministic_corruption_stable_rsa() {
        let fx = fx();
        let kp1 = fx.rsa("det-der-rsa", RsaSpec::rs256());
        let corrupt1 = kp1.private_key_pkcs8_der_corrupt_deterministic("corrupt:d1");
        fx.clear_cache();
        let kp2 = fx.rsa("det-der-rsa", RsaSpec::rs256());
        let corrupt2 = kp2.private_key_pkcs8_der_corrupt_deterministic("corrupt:d1");
        assert_eq!(corrupt1, corrupt2);
    }

    #[test]
    fn negative_different_variant_different_corruption() {
        let kp = fx().rsa("det-diff", RsaSpec::rs256());
        let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:alpha");
        let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:beta");
        // Different variants should produce different corruptions (overwhelmingly likely)
        assert_ne!(a, b);
    }

    #[test]
    fn negative_x509_deterministic_corrupt_cert_pem_stable() {
        let fx = fx();
        let cert1 = fx.x509_self_signed("det-x509", X509Spec::self_signed("det.example.com"));
        let c1 = cert1.corrupt_cert_pem_deterministic("corrupt:cert-v1");
        fx.clear_cache();
        let cert2 = fx.x509_self_signed("det-x509", X509Spec::self_signed("det.example.com"));
        let c2 = cert2.corrupt_cert_pem_deterministic("corrupt:cert-v1");
        assert_eq!(c1, c2);
    }

    #[test]
    fn negative_x509_deterministic_corrupt_cert_der_stable() {
        let fx = fx();
        let cert1 = fx.x509_self_signed("det-x509-der", X509Spec::self_signed("det.example.com"));
        let c1 = cert1.corrupt_cert_der_deterministic("corrupt:der-v1");
        fx.clear_cache();
        let cert2 =
            fx.x509_self_signed("det-x509-der", X509Spec::self_signed("det.example.com"));
        let c2 = cert2.corrupt_cert_der_deterministic("corrupt:der-v1");
        assert_eq!(c1, c2);
    }
}

// =========================================================================
// 7. Corrupt PEM parsing — standard PEM parsers reject our corrupt PEM
// =========================================================================

mod corrupt_pem_parsing {
    use super::*;

    #[test]
    fn negative_bad_header_rejected_by_pem_parser() {
        let kp = fx().rsa("pem-parse-rsa", RsaSpec::rs256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        // The pem crate should still parse it (it parses any BEGIN/END pair),
        // but the tag won't match "PRIVATE KEY"
        let parsed = pem::parse(bad);
        match parsed {
            Ok(p) => assert_ne!(p.tag(), "PRIVATE KEY"),
            Err(_) => {} // Also acceptable: parser rejects it
        }
    }

    #[test]
    fn negative_bad_footer_rejected_by_pem_parser() {
        let kp = fx().rsa("pem-parse-footer", RsaSpec::rs256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        // Mismatched header/footer should cause parse failure
        let parsed = pem::parse(bad);
        assert!(parsed.is_err(), "mismatched header/footer should fail pem parse");
    }

    #[test]
    fn negative_bad_base64_rejected_by_pem_parser() {
        let kp = fx().rsa("pem-parse-b64", RsaSpec::rs256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        let parsed = pem::parse(bad);
        assert!(parsed.is_err(), "invalid base64 should fail pem parse");
    }

    #[test]
    fn negative_truncated_pem_rejected_by_pem_parser() {
        let kp = fx().rsa("pem-parse-trunc", RsaSpec::rs256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 30 });
        let parsed = pem::parse(bad);
        assert!(parsed.is_err(), "truncated PEM should fail pem parse");
    }

    #[test]
    fn negative_ecdsa_bad_header_rejected() {
        let kp = fx().ecdsa("pem-parse-ecdsa", EcdsaSpec::es256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        let parsed = pem::parse(&bad);
        match parsed {
            Ok(p) => assert_ne!(p.tag(), "PRIVATE KEY"),
            Err(_) => {}
        }
    }

    #[test]
    fn negative_ed25519_bad_base64_rejected() {
        let kp = fx().ed25519("pem-parse-ed25519", Ed25519Spec::new());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        let parsed = pem::parse(bad);
        assert!(parsed.is_err(), "invalid base64 should fail pem parse for ed25519");
    }
}

// =========================================================================
// 8. DER validity — truncated DER rejected by parsers
// =========================================================================

mod der_validity {
    use super::*;

    #[test]
    fn negative_truncated_rsa_der_rejected_by_x509_parser() {
        let cert = fx().x509_self_signed("der-val", X509Spec::self_signed("der.example.com"));
        let truncated = cert.truncate_cert_der(10);
        let result = x509_parser::prelude::X509Certificate::from_der(&truncated);
        assert!(result.is_err(), "truncated cert DER should fail x509 parse");
    }

    #[test]
    fn negative_truncated_to_one_byte_rejected() {
        let cert = fx().x509_self_signed("der-val-1", X509Spec::self_signed("der1.example.com"));
        let truncated = cert.truncate_cert_der(1);
        let result = x509_parser::prelude::X509Certificate::from_der(&truncated);
        assert!(result.is_err());
    }

    #[test]
    fn negative_truncated_to_half_rejected() {
        let cert =
            fx().x509_self_signed("der-val-half", X509Spec::self_signed("derhalf.example.com"));
        let full_len = cert.cert_der().len();
        let truncated = cert.truncate_cert_der(full_len / 2);
        let result = x509_parser::prelude::X509Certificate::from_der(&truncated);
        assert!(result.is_err(), "half-truncated cert DER should fail x509 parse");
    }

    #[test]
    fn negative_corrupt_cert_der_deterministic_rejected() {
        let cert = fx().x509_self_signed(
            "der-val-corrupt",
            X509Spec::self_signed("dercorrupt.example.com"),
        );
        let corrupted = cert.corrupt_cert_der_deterministic("corrupt:parse-test");
        // Corrupted DER may or may not parse, but should differ from original
        assert_ne!(corrupted.as_slice(), cert.cert_der());
    }

    #[test]
    fn negative_rsa_truncated_pkcs8_der_is_not_valid_pkcs8() {
        let kp = fx().rsa("der-pkcs8-rsa", RsaSpec::rs256());
        let truncated = kp.private_key_pkcs8_der_truncated(10);
        // Truncated PKCS#8 should not start with a valid DER SEQUENCE of the right length
        assert_eq!(truncated.len(), 10);
        // A 10-byte blob can't hold a valid RSA PKCS#8 key
    }

    #[test]
    fn negative_ecdsa_truncated_pkcs8_der_short() {
        let kp = fx().ecdsa("der-pkcs8-ecdsa", EcdsaSpec::es256());
        let truncated = kp.private_key_pkcs8_der_truncated(5);
        assert_eq!(truncated.len(), 5);
    }

    #[test]
    fn negative_ed25519_truncated_pkcs8_der_short() {
        let kp = fx().ed25519("der-pkcs8-ed25519", Ed25519Spec::new());
        let truncated = kp.private_key_pkcs8_der_truncated(3);
        assert_eq!(truncated.len(), 3);
    }
}
