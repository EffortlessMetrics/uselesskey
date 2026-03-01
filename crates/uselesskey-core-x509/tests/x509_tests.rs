//! Integration tests for `uselesskey-core-x509`.
//!
//! These tests exercise the public API surface re-exported by the crate:
//! negative-policy enums, spec models, and deterministic derivation helpers.

use std::collections::HashSet;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use time::OffsetDateTime;
use uselesskey_core_x509::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, ChainNegative, ChainSpec, NotBeforeOffset,
    SERIAL_NUMBER_BYTES, X509Negative, X509Spec, deterministic_base_time_from_parts,
    deterministic_serial_number,
};

#[test]
fn all_x509_negative_variants_are_distinct() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    let debug_reprs: HashSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(
        debug_reprs.len(),
        variants.len(),
        "every X509Negative variant must have a unique Debug representation"
    );

    let descriptions: HashSet<&str> = variants.iter().map(|v| v.description()).collect();
    assert_eq!(
        descriptions.len(),
        variants.len(),
        "every X509Negative variant must have a unique description"
    );

    let names: HashSet<&str> = variants.iter().map(|v| v.variant_name()).collect();
    assert_eq!(
        names.len(),
        variants.len(),
        "every X509Negative variant must have a unique variant_name"
    );
}

#[test]
fn x509_spec_default_is_self_signed() {
    let spec = X509Spec::self_signed("example.com");

    assert_eq!(spec.subject_cn, "example.com");
    assert_eq!(
        spec.issuer_cn, "example.com",
        "self-signed: issuer == subject"
    );
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysAgo(1));
    assert_eq!(spec.validity_days, 3650, "default validity is 10 years");
    assert!(!spec.is_ca);
    assert_eq!(spec.rsa_bits, 2048);
    assert!(spec.sans.is_empty());
}

#[test]
fn chain_spec_default_has_three_levels() {
    let spec = ChainSpec::new("app.example.com");

    // Leaf
    assert_eq!(spec.leaf_cn, "app.example.com");
    assert_eq!(spec.leaf_sans, vec!["app.example.com"]);

    // Root CA
    assert!(
        spec.root_cn.contains("Root CA"),
        "root_cn should contain 'Root CA', got: {}",
        spec.root_cn
    );

    // Intermediate CA
    assert!(
        spec.intermediate_cn.contains("Intermediate CA"),
        "intermediate_cn should contain 'Intermediate CA', got: {}",
        spec.intermediate_cn
    );

    // Validity periods: root > intermediate
    assert!(
        spec.root_validity_days > spec.intermediate_validity_days,
        "root validity ({}) should exceed intermediate ({})",
        spec.root_validity_days,
        spec.intermediate_validity_days
    );

    // No not_before overrides by default
    assert_eq!(spec.leaf_not_before_offset_days, None);
    assert_eq!(spec.intermediate_not_before_offset_days, None);
}

#[test]
fn deterministic_serial_number_is_stable() {
    let seed = [42u8; 32];

    let serial_a = {
        let mut rng = ChaCha20Rng::from_seed(seed);
        deterministic_serial_number(&mut rng)
    };
    let serial_b = {
        let mut rng = ChaCha20Rng::from_seed(seed);
        deterministic_serial_number(&mut rng)
    };

    let bytes_a = serial_a.to_bytes();
    let bytes_b = serial_b.to_bytes();

    assert_eq!(bytes_a, bytes_b, "same seed must produce same serial");
    assert_eq!(bytes_a.len(), SERIAL_NUMBER_BYTES);
    assert_eq!(bytes_a[0] & 0x80, 0, "high bit must be cleared (positive)");

    // Different seed produces different serial
    let serial_c = {
        let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
        deterministic_serial_number(&mut rng)
    };
    assert_ne!(bytes_a, serial_c.to_bytes());
}

#[test]
fn deterministic_base_time_is_bounded() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    // Test several different identity inputs
    let inputs: &[&[&[u8]]] = &[
        &[b"label-a", b"leaf"],
        &[b"label-b", b"root"],
        &[b"x", b"y", b"z"],
        &[b"single-part"],
    ];

    for parts in inputs {
        let t = deterministic_base_time_from_parts(parts);
        assert!(
            t >= epoch,
            "base time {t} should be >= epoch {epoch} for parts {parts:?}"
        );
        assert!(
            t < max,
            "base time {t} should be < max {max} for parts {parts:?}"
        );
    }

    // Determinism: same input → same output
    let a = deterministic_base_time_from_parts(&[b"stable", b"test"]);
    let b = deterministic_base_time_from_parts(&[b"stable", b"test"]);
    assert_eq!(a, b);
}

#[test]
fn stable_bytes_changes_with_cn() {
    let spec_a = X509Spec::self_signed("alice.example.com");
    let spec_b = X509Spec::self_signed("bob.example.com");

    assert_ne!(
        spec_a.stable_bytes(),
        spec_b.stable_bytes(),
        "different CNs must produce different stable_bytes"
    );

    // Also verify ChainSpec stable_bytes changes with leaf_cn
    let chain_a = ChainSpec::new("alice.example.com");
    let chain_b = ChainSpec::new("bob.example.com");

    assert_ne!(
        chain_a.stable_bytes(),
        chain_b.stable_bytes(),
        "different leaf CNs must produce different ChainSpec stable_bytes"
    );
}

#[test]
fn chain_negative_variants_are_distinct() {
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "evil.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];

    let debug_reprs: HashSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(
        debug_reprs.len(),
        variants.len(),
        "every ChainNegative variant must have a unique Debug representation"
    );

    let names: HashSet<String> = variants.iter().map(|v| v.variant_name()).collect();
    assert_eq!(
        names.len(),
        variants.len(),
        "every ChainNegative variant must have a unique variant_name"
    );
}
