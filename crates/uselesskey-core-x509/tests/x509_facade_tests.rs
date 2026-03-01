//! Integration tests for the uselesskey-core-x509 facade crate.
//!
//! This crate re-exports X.509 negative policy types and spec models.
//! These tests verify the re-exports are accessible and functional.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_x509::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, ChainNegative, ChainSpec, KeyUsage,
    NotBeforeOffset, SERIAL_NUMBER_BYTES, X509Negative, X509Spec,
    deterministic_base_time_from_parts, deterministic_serial_number,
};

#[test]
fn x509_negative_types_accessible() {
    let base = X509Spec::self_signed("test.example.com");
    let expired = X509Negative::Expired.apply_to_spec(&base);

    assert_eq!(expired.not_before_offset, NotBeforeOffset::DaysAgo(395));
    assert_eq!(expired.validity_days, 365);
}

#[test]
fn chain_negative_types_accessible() {
    let base = ChainSpec::new("api.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let modified = neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_cn, "evil.example.com");
}

#[test]
fn x509_spec_builder_api_accessible() {
    let spec = X509Spec::self_signed("builder.example.com")
        .with_validity_days(90)
        .with_rsa_bits(4096)
        .with_is_ca(false)
        .with_key_usage(KeyUsage::leaf())
        .with_sans(vec!["builder.example.com".into()]);

    assert_eq!(spec.validity_days, 90);
    assert_eq!(spec.rsa_bits, 4096);
}

#[test]
fn chain_spec_builder_api_accessible() {
    let spec = ChainSpec::new("chain.example.com")
        .with_root_cn("Test Root CA")
        .with_intermediate_cn("Test Int CA")
        .with_rsa_bits(2048)
        .with_root_validity_days(7300)
        .with_leaf_validity_days(365);

    assert_eq!(spec.root_cn, "Test Root CA");
    assert_eq!(spec.intermediate_cn, "Test Int CA");
}

#[test]
fn x509_negative_all_variants_accessible() {
    let base = X509Spec::self_signed("test");

    let _expired = X509Negative::Expired.apply_to_spec(&base);
    let _not_yet = X509Negative::NotYetValid.apply_to_spec(&base);
    let _wrong_ku = X509Negative::WrongKeyUsage.apply_to_spec(&base);
    let _self_ca = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);
}

#[test]
fn chain_negative_all_variants_accessible() {
    let base = ChainSpec::new("test.example.com");

    let _hostname = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    }
    .apply_to_spec(&base);
    let _unknown = ChainNegative::UnknownCa.apply_to_spec(&base);
    let _expired_leaf = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    let _expired_int = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
    let _revoked = ChainNegative::RevokedLeaf.apply_to_spec(&base);
}

#[test]
fn derive_helpers_accessible() {
    // Verify constants are non-zero (compile-time check).
    const { assert!(BASE_TIME_EPOCH_UNIX > 0) };
    const { assert!(BASE_TIME_WINDOW_DAYS > 0) };
    const { assert!(SERIAL_NUMBER_BYTES > 0) };

    let _time = deterministic_base_time_from_parts(&[b"test-label"]);

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let serial = deterministic_serial_number(&mut rng);
    let bytes = serial.to_bytes();
    assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
}

#[test]
fn key_usage_types_accessible() {
    let leaf = KeyUsage::leaf();
    assert!(leaf.digital_signature);
    assert!(!leaf.key_cert_sign);

    let ca = KeyUsage::ca();
    assert!(ca.key_cert_sign);
    assert!(ca.crl_sign);

    assert_eq!(KeyUsage::default(), KeyUsage::leaf());
}

#[test]
fn not_before_offset_types_accessible() {
    let ago = NotBeforeOffset::DaysAgo(1);
    let future = NotBeforeOffset::DaysFromNow(7);
    assert_ne!(ago, future);
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}
