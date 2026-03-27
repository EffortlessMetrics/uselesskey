//! Mutant-killing tests for X.509 chain negative fixtures.

use uselesskey_core_x509_chain_negative::ChainNegative;
use uselesskey_core_x509_spec::{ChainSpec, NotBeforeOffset};

#[test]
fn hostname_mismatch_variant_name_contains_hostname() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    assert_eq!(neg.variant_name(), "hostname_mismatch:evil.example.com");
}

#[test]
fn unknown_ca_variant_name() {
    assert_eq!(ChainNegative::UnknownCa.variant_name(), "unknown_ca");
}

#[test]
fn expired_leaf_variant_name() {
    assert_eq!(ChainNegative::ExpiredLeaf.variant_name(), "expired_leaf");
}

#[test]
fn not_yet_valid_leaf_variant_name() {
    assert_eq!(
        ChainNegative::NotYetValidLeaf.variant_name(),
        "not_yet_valid_leaf"
    );
}

#[test]
fn expired_intermediate_variant_name() {
    assert_eq!(
        ChainNegative::ExpiredIntermediate.variant_name(),
        "expired_intermediate"
    );
}

#[test]
fn not_yet_valid_intermediate_variant_name() {
    assert_eq!(
        ChainNegative::NotYetValidIntermediate.variant_name(),
        "not_yet_valid_intermediate"
    );
}

#[test]
fn intermediate_not_ca_variant_name() {
    assert_eq!(
        ChainNegative::IntermediateNotCa.variant_name(),
        "intermediate_not_ca"
    );
}

#[test]
fn intermediate_wrong_key_usage_variant_name() {
    assert_eq!(
        ChainNegative::IntermediateWrongKeyUsage.variant_name(),
        "intermediate_wrong_key_usage"
    );
}

#[test]
fn revoked_leaf_variant_name() {
    assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
}

#[test]
fn hostname_mismatch_changes_leaf_cn_and_sans() {
    let base = ChainSpec::new("good.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    let modified = neg.apply_to_spec(&base);

    assert_eq!(modified.leaf_cn, "wrong.example.com");
    assert_eq!(modified.leaf_sans, vec!["wrong.example.com"]);
    // Other fields unchanged
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
}

#[test]
fn unknown_ca_changes_root_cn_only() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

    assert_eq!(modified.root_cn, "test.example.com Unknown Root CA");
    // Other fields unchanged
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_sans, base.leaf_sans);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
}

#[test]
fn expired_leaf_sets_exact_values() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    assert_eq!(modified.leaf_validity_days, 1);
    assert_eq!(
        modified.leaf_not_before,
        Some(NotBeforeOffset::DaysAgo(730))
    );
    // Other fields unchanged
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(
        modified.intermediate_validity_days,
        base.intermediate_validity_days
    );
}

#[test]
fn not_yet_valid_leaf_sets_exact_values() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::NotYetValidLeaf.apply_to_spec(&base);

    assert_eq!(
        modified.leaf_not_before,
        Some(NotBeforeOffset::DaysFromNow(730))
    );
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
}

#[test]
fn expired_intermediate_sets_exact_values() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

    assert_eq!(modified.intermediate_validity_days, 1);
    assert_eq!(
        modified.intermediate_not_before,
        Some(NotBeforeOffset::DaysAgo(730))
    );
    // Other fields unchanged
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
}

#[test]
fn not_yet_valid_intermediate_sets_exact_values() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::NotYetValidIntermediate.apply_to_spec(&base);

    assert_eq!(
        modified.intermediate_not_before,
        Some(NotBeforeOffset::DaysFromNow(730))
    );
    assert_eq!(
        modified.intermediate_validity_days,
        base.intermediate_validity_days
    );
}

#[test]
fn intermediate_not_ca_sets_exact_values() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::IntermediateNotCa.apply_to_spec(&base);

    assert_eq!(modified.intermediate_is_ca, Some(false));
    assert_eq!(modified.intermediate_key_usage, base.intermediate_key_usage);
}

#[test]
fn intermediate_wrong_key_usage_sets_exact_values() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::IntermediateWrongKeyUsage.apply_to_spec(&base);

    assert_eq!(modified.intermediate_is_ca, Some(true));
    assert_eq!(
        modified.intermediate_key_usage,
        Some(uselesskey_core_x509_spec::KeyUsage {
            key_cert_sign: false,
            crl_sign: false,
            digital_signature: true,
            key_encipherment: false,
        })
    );
}

#[test]
fn revoked_leaf_does_not_change_spec() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);

    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_sans, base.leaf_sans);
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
    assert_eq!(modified.leaf_not_before, base.leaf_not_before);
}

#[test]
fn all_variant_names_are_distinct() {
    let names: Vec<String> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "x".to_string(),
        }
        .variant_name(),
        ChainNegative::UnknownCa.variant_name(),
        ChainNegative::ExpiredLeaf.variant_name(),
        ChainNegative::NotYetValidLeaf.variant_name(),
        ChainNegative::ExpiredIntermediate.variant_name(),
        ChainNegative::NotYetValidIntermediate.variant_name(),
        ChainNegative::IntermediateNotCa.variant_name(),
        ChainNegative::IntermediateWrongKeyUsage.variant_name(),
        ChainNegative::RevokedLeaf.variant_name(),
    ];

    for (i, a) in names.iter().enumerate() {
        for (j, b) in names.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "variant names must be distinct: {a} vs {b}");
            }
        }
    }
}
