//! External unit tests for uselesskey-x509.
//!
//! These tests cover gaps not covered by inline `#[cfg(test)]` tests:
//! - X509Spec::with_sans builder
//! - stable_bytes version prefix and SAN handling
//! - KeyUsage stable_bytes exact values
//! - Tempfile content matching in-memory values
//! - identity_pem cert-before-key ordering
//! - Different labels → different certs
//! - ChainSpec stable_bytes version prefix
//! - Chain PEM ordering (leaf first)
//! - Full chain PEM ordering (leaf, intermediate, root)
//! - Chain tempfile content matching
//! - ChainNegative::apply_to_spec all variants

mod testutil;

use testutil::fx;
use uselesskey_x509::{ChainNegative, ChainSpec, KeyUsage, X509FactoryExt, X509Negative, X509Spec};

// =========================================================================
// X509Spec tests
// =========================================================================

#[test]
fn test_with_sans_builder() {
    let spec = X509Spec::self_signed("example.com").with_sans(vec![
        "example.com".to_string(),
        "www.example.com".to_string(),
    ]);

    assert_eq!(spec.sans.len(), 2);
    assert!(spec.sans.contains(&"example.com".to_string()));
    assert!(spec.sans.contains(&"www.example.com".to_string()));
    // Other fields should remain at defaults
    assert_eq!(spec.subject_cn, "example.com");
    assert_eq!(spec.issuer_cn, "example.com");
    assert_eq!(spec.validity_days, 3650);
    assert!(!spec.is_ca);
}

#[test]
fn test_stable_bytes_version_prefix() {
    let spec = X509Spec::self_signed("test");
    let bytes = spec.stable_bytes();
    assert_eq!(
        bytes[0], 4,
        "X509Spec stable_bytes version prefix should be 4"
    );
}

#[test]
fn test_stable_bytes_different_sans_differ() {
    let spec_no_sans = X509Spec::self_signed("test");
    let spec_with_sans =
        X509Spec::self_signed("test").with_sans(vec!["san.example.com".to_string()]);
    assert_ne!(spec_no_sans.stable_bytes(), spec_with_sans.stable_bytes());
}

#[test]
fn test_stable_bytes_san_order_independent() {
    let spec1 = X509Spec::self_signed("test").with_sans(vec![
        "a.example.com".to_string(),
        "b.example.com".to_string(),
    ]);
    let spec2 = X509Spec::self_signed("test").with_sans(vec![
        "b.example.com".to_string(),
        "a.example.com".to_string(),
    ]);
    assert_eq!(
        spec1.stable_bytes(),
        spec2.stable_bytes(),
        "SANs in different order should produce same stable_bytes"
    );
}

// =========================================================================
// KeyUsage stable_bytes exact values
// =========================================================================

#[test]
fn test_key_usage_stable_bytes_values() {
    let leaf = KeyUsage::leaf().stable_bytes();
    // leaf: key_cert_sign=false, crl_sign=false, digital_signature=true, key_encipherment=true
    assert_eq!(leaf, [0, 0, 1, 1]);

    let ca = KeyUsage::ca().stable_bytes();
    // ca: key_cert_sign=true, crl_sign=true, digital_signature=true, key_encipherment=false
    assert_eq!(ca, [1, 1, 1, 0]);
}

// =========================================================================
// X509Cert output tests
// =========================================================================

#[test]
fn test_tempfile_content_matches_in_memory() {
    let fx = fx();
    let spec = X509Spec::self_signed("tempfile-test.example.com");
    let cert = fx.x509_self_signed("tempfile-test", spec);

    let cert_file = cert.write_cert_pem().unwrap();
    let file_content = std::fs::read_to_string(cert_file.path()).unwrap();
    assert_eq!(
        file_content,
        cert.cert_pem(),
        "Tempfile content should match cert_pem()"
    );
}

#[test]
fn test_identity_pem_cert_before_key() {
    let fx = fx();
    let spec = X509Spec::self_signed("identity-order.example.com");
    let cert = fx.x509_self_signed("identity-order", spec);

    let identity = cert.identity_pem();
    let cert_pos = identity
        .find("-----BEGIN CERTIFICATE-----")
        .expect("should contain cert marker");
    let key_pos = identity
        .find("-----BEGIN PRIVATE KEY-----")
        .expect("should contain key marker");

    assert!(
        cert_pos < key_pos,
        "Certificate should appear before private key in identity_pem()"
    );
}

#[test]
fn test_different_labels_different_certs() {
    let fx = fx();
    let spec = X509Spec::self_signed("label-test.example.com");
    let cert_a = fx.x509_self_signed("label-alpha", spec.clone());
    let cert_b = fx.x509_self_signed("label-beta", spec);

    assert_ne!(
        cert_a.cert_der(),
        cert_b.cert_der(),
        "Different labels should produce different certificates"
    );
}

// =========================================================================
// ChainSpec tests
// =========================================================================

#[test]
fn test_chain_spec_stable_bytes_version_prefix() {
    let spec = ChainSpec::new("test.example.com");
    let bytes = spec.stable_bytes();
    assert_eq!(
        bytes[0], 2,
        "ChainSpec stable_bytes version prefix should be 2"
    );
}

// =========================================================================
// X509Chain output tests
// =========================================================================

#[test]
fn test_chain_pem_leaf_first() {
    let fx = fx();
    let spec = ChainSpec::new("chain-order.example.com");
    let chain = fx.x509_chain("chain-order", spec);

    let chain_pem = chain.chain_pem();

    // chain_pem should start with the leaf cert PEM
    let leaf_pos = chain_pem
        .find(chain.leaf_cert_pem())
        .expect("chain_pem should contain leaf cert");
    let int_pos = chain_pem
        .find(chain.intermediate_cert_pem())
        .expect("chain_pem should contain intermediate cert");

    assert!(
        leaf_pos < int_pos,
        "Leaf cert should appear before intermediate cert in chain_pem"
    );

    // Verify via DER parsing that leaf is not CA and intermediate is CA
    use x509_parser::prelude::*;
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");

    assert!(!leaf.is_ca(), "Leaf should not be a CA");
    assert!(int.is_ca(), "Intermediate should be a CA");
}

#[test]
fn test_chain_full_pem_all_three_in_order() {
    use x509_parser::prelude::*;

    let fx = fx();
    let spec = ChainSpec::new("fullchain.example.com");
    let chain = fx.x509_chain("fullchain", spec);

    let full_pem = chain.full_chain_pem();

    // Should contain exactly 3 certs
    assert_eq!(
        full_pem.matches("-----BEGIN CERTIFICATE-----").count(),
        3,
        "full_chain_pem should contain 3 certificates"
    );

    // Verify ordering: leaf, then intermediate, then root
    let leaf_pos = full_pem
        .find(chain.leaf_cert_pem())
        .expect("should contain leaf");
    let int_pos = full_pem
        .find(chain.intermediate_cert_pem())
        .expect("should contain intermediate");
    let root_pos = full_pem
        .find(chain.root_cert_pem())
        .expect("should contain root");

    assert!(leaf_pos < int_pos, "Leaf should appear before intermediate");
    assert!(int_pos < root_pos, "Intermediate should appear before root");

    // Verify issuer chain via DER parsing
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");
    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");

    assert!(!leaf.is_ca(), "Leaf should not be CA");
    assert!(int.is_ca(), "Intermediate should be CA");
    assert!(root.is_ca(), "Root should be CA");

    assert_eq!(
        leaf.issuer(),
        int.subject(),
        "Leaf issuer should be intermediate subject"
    );
    assert_eq!(
        int.issuer(),
        root.subject(),
        "Intermediate issuer should be root subject"
    );
}

#[test]
fn test_chain_tempfile_content_matches() {
    let fx = fx();
    let spec = ChainSpec::new("chain-tempfile.example.com");
    let chain = fx.x509_chain("chain-tempfile", spec);

    let leaf_file = chain.write_leaf_cert_pem().unwrap();
    let file_content = std::fs::read_to_string(leaf_file.path()).unwrap();
    assert_eq!(
        file_content,
        chain.leaf_cert_pem(),
        "Leaf cert tempfile content should match leaf_cert_pem()"
    );
}

// =========================================================================
// ChainNegative::apply_to_spec coverage
// =========================================================================

#[test]
fn test_chain_negative_apply_to_spec_all_variants() {
    let base = ChainSpec::new("neg-test.example.com");

    // HostnameMismatch
    let hostname_neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    let modified = hostname_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_cn, "wrong.example.com");
    assert_eq!(modified.leaf_sans, vec!["wrong.example.com".to_string()]);

    // UnknownCa
    let unknown_neg = ChainNegative::UnknownCa;
    let modified = unknown_neg.apply_to_spec(&base);
    assert!(
        modified.root_cn.contains("Unknown"),
        "UnknownCa should modify root_cn"
    );

    // ExpiredLeaf
    let expired_leaf_neg = ChainNegative::ExpiredLeaf;
    let modified = expired_leaf_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_validity_days, 1);
    assert_eq!(modified.leaf_not_before_offset_days, Some(730));

    // ExpiredIntermediate
    let expired_int_neg = ChainNegative::ExpiredIntermediate;
    let modified = expired_int_neg.apply_to_spec(&base);
    assert_eq!(modified.intermediate_validity_days, 1);
    assert_eq!(modified.intermediate_not_before_offset_days, Some(730));

    // RevokedLeaf
    let revoked_neg = ChainNegative::RevokedLeaf;
    let modified = revoked_neg.apply_to_spec(&base);
    // RevokedLeaf doesn't change the spec; CRL generation is a side-effect
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
}

// =========================================================================
// X509Negative::apply_to_spec (supplement to inline tests)
// =========================================================================

#[test]
fn test_x509_negative_apply_preserves_cn() {
    let base = X509Spec::self_signed("preserve.example.com");

    for neg in [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ] {
        let modified = neg.apply_to_spec(&base);
        assert_eq!(
            modified.subject_cn, "preserve.example.com",
            "{:?} should preserve subject_cn",
            neg
        );
    }
}
