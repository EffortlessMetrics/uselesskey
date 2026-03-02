//! Integration tests for X.509 negative-fixture policies — covers all
//! variants, spec mutation safety, and stable metadata.

use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ── X509Negative: each variant produces a distinct mutation ──────────

#[test]
fn all_x509_negative_variants_differ_from_base() {
    let base = X509Spec::self_signed("neg.example.com");
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    for v in &variants {
        let mutated = v.apply_to_spec(&base);
        assert_ne!(
            mutated.stable_bytes(),
            base.stable_bytes(),
            "variant {v:?} should differ from base"
        );
    }
}

#[test]
fn all_x509_negative_variants_differ_from_each_other() {
    let base = X509Spec::self_signed("neg.example.com");
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    for (i, vi) in variants.iter().enumerate() {
        for (j, vj) in variants.iter().enumerate() {
            if i != j {
                let si = vi.apply_to_spec(&base);
                let sj = vj.apply_to_spec(&base);
                assert_ne!(
                    si.stable_bytes(),
                    sj.stable_bytes(),
                    "{vi:?} and {vj:?} should produce different specs"
                );
            }
        }
    }
}

// ── X509Negative: mutation doesn't corrupt unrelated fields ──────────

#[test]
fn expired_preserves_cn() {
    let base = X509Spec::self_signed("preserve.example.com");
    let mutated = X509Negative::Expired.apply_to_spec(&base);
    assert_eq!(mutated.subject_cn, base.subject_cn);
}

#[test]
fn not_yet_valid_preserves_key_usage() {
    let base = X509Spec::self_signed("preserve.example.com");
    let mutated = X509Negative::NotYetValid.apply_to_spec(&base);
    assert_eq!(mutated.key_usage, KeyUsage::leaf());
    assert!(!mutated.is_ca);
}

#[test]
fn wrong_key_usage_exact_flags() {
    let base = X509Spec::self_signed("flags.example.com");
    let mutated = X509Negative::WrongKeyUsage.apply_to_spec(&base);
    assert!(mutated.is_ca);
    assert!(!mutated.key_usage.key_cert_sign);
    assert!(!mutated.key_usage.crl_sign);
    assert!(mutated.key_usage.digital_signature);
    assert!(mutated.key_usage.key_encipherment);
}

#[test]
fn self_signed_ca_sets_ca_key_usage() {
    let base = X509Spec::self_signed("ca.example.com");
    let mutated = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);
    assert!(mutated.is_ca);
    assert_eq!(mutated.key_usage, KeyUsage::ca());
}

// ── X509Negative: metadata stability ─────────────────────────────────

#[test]
fn variant_names_are_unique() {
    let names: Vec<&str> = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ]
    .iter()
    .map(|v| v.variant_name())
    .collect();

    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(unique.len(), names.len());
}

#[test]
fn descriptions_are_non_empty() {
    for v in [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ] {
        assert!(!v.description().is_empty(), "{v:?} has empty description");
    }
}

// ── ChainNegative: all variants produce valid mutations ──────────────

#[test]
fn chain_hostname_mismatch_replaces_leaf_cn_and_sans() {
    let base = ChainSpec::new("api.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let mutated = neg.apply_to_spec(&base);
    assert_eq!(mutated.leaf_cn, "evil.example.com");
    assert_eq!(mutated.leaf_sans, vec!["evil.example.com"]);
    // Root and intermediate should be preserved
    assert_eq!(mutated.root_cn, base.root_cn);
    assert_eq!(mutated.intermediate_cn, base.intermediate_cn);
}

#[test]
fn chain_unknown_ca_modifies_root_cn_only() {
    let base = ChainSpec::new("api.example.com");
    let mutated = ChainNegative::UnknownCa.apply_to_spec(&base);
    assert!(mutated.root_cn.contains("Unknown"));
    assert_ne!(mutated.root_cn, base.root_cn);
    assert_eq!(mutated.leaf_cn, base.leaf_cn);
    assert_eq!(mutated.intermediate_cn, base.intermediate_cn);
}

#[test]
fn chain_expired_leaf_sets_short_validity_and_past_offset() {
    let base = ChainSpec::new("api.example.com");
    let mutated = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    assert_eq!(mutated.leaf_validity_days, 1);
    assert_eq!(mutated.leaf_not_before_offset_days, Some(730));
    // Intermediate should be unchanged
    assert_eq!(
        mutated.intermediate_validity_days,
        base.intermediate_validity_days
    );
}

#[test]
fn chain_expired_intermediate_sets_short_validity_and_past_offset() {
    let base = ChainSpec::new("api.example.com");
    let mutated = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
    assert_eq!(mutated.intermediate_validity_days, 1);
    assert_eq!(mutated.intermediate_not_before_offset_days, Some(730));
    // Leaf should be unchanged
    assert_eq!(mutated.leaf_validity_days, base.leaf_validity_days);
}

#[test]
fn chain_revoked_leaf_does_not_mutate_spec() {
    let base = ChainSpec::new("api.example.com");
    let mutated = ChainNegative::RevokedLeaf.apply_to_spec(&base);
    assert_eq!(mutated.leaf_cn, base.leaf_cn);
    assert_eq!(mutated.leaf_validity_days, base.leaf_validity_days);
    assert_eq!(mutated.root_cn, base.root_cn);
}

// ── ChainNegative: variant name stability ────────────────────────────

#[test]
fn chain_variant_names_are_unique() {
    let names: Vec<String> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "test.com".to_string(),
        }
        .variant_name(),
        ChainNegative::UnknownCa.variant_name(),
        ChainNegative::ExpiredLeaf.variant_name(),
        ChainNegative::ExpiredIntermediate.variant_name(),
        ChainNegative::RevokedLeaf.variant_name(),
    ];

    let unique: std::collections::HashSet<&String> = names.iter().collect();
    assert_eq!(unique.len(), names.len());
}

#[test]
fn chain_hostname_mismatch_variant_name_includes_hostname() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    let name = neg.variant_name();
    assert!(name.contains("hostname_mismatch"));
    assert!(name.contains("wrong.example.com"));
}

// ── X509Negative: timing values ──────────────────────────────────────

#[test]
fn expired_has_not_before_in_the_past() {
    let base = X509Spec::self_signed("timing.example.com");
    let mutated = X509Negative::Expired.apply_to_spec(&base);
    assert_eq!(mutated.not_before_offset, NotBeforeOffset::DaysAgo(395));
    assert_eq!(mutated.validity_days, 365);
}

#[test]
fn not_yet_valid_has_not_before_in_the_future() {
    let base = X509Spec::self_signed("timing.example.com");
    let mutated = X509Negative::NotYetValid.apply_to_spec(&base);
    assert_eq!(mutated.not_before_offset, NotBeforeOffset::DaysFromNow(30));
}
