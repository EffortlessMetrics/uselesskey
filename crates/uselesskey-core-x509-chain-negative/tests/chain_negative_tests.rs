use uselesskey_core_x509_chain_negative::ChainNegative;
use uselesskey_core_x509_spec::ChainSpec;

#[test]
fn chain_negative_variant_names_are_stable() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    assert_eq!(neg.variant_name(), "hostname_mismatch:wrong.example.com");
    assert_eq!(ChainNegative::UnknownCa.variant_name(), "unknown_ca");
    assert_eq!(ChainNegative::ExpiredLeaf.variant_name(), "expired_leaf");
    assert_eq!(
        ChainNegative::ExpiredIntermediate.variant_name(),
        "expired_intermediate"
    );
    assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
}

#[test]
fn chain_negative_apply_to_spec_all_variants() {
    let base = ChainSpec::new("neg-test.example.com");

    let hostname_neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    let modified = hostname_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_cn, "wrong.example.com");
    assert_eq!(modified.leaf_sans, vec!["wrong.example.com".to_string()]);

    let unknown_neg = ChainNegative::UnknownCa;
    let modified = unknown_neg.apply_to_spec(&base);
    assert!(
        modified.root_cn.contains("Unknown"),
        "UnknownCa should modify root_cn"
    );

    let expired_leaf_neg = ChainNegative::ExpiredLeaf;
    let modified = expired_leaf_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_validity_days, 1);
    assert_eq!(modified.leaf_not_before_offset_days, Some(730));

    let expired_int_neg = ChainNegative::ExpiredIntermediate;
    let modified = expired_int_neg.apply_to_spec(&base);
    assert_eq!(modified.intermediate_validity_days, 1);
    assert_eq!(modified.intermediate_not_before_offset_days, Some(730));

    let revoked_neg = ChainNegative::RevokedLeaf;
    let modified = revoked_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
}
