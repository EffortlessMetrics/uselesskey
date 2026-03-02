use uselesskey_core_x509_chain_negative::ChainNegative;
use uselesskey_core_x509_spec::ChainSpec;

// ---------------------------------------------------------------------------
// Construction and trait impls
// ---------------------------------------------------------------------------

#[test]
fn clone_produces_equal_value() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    assert_eq!(neg.clone(), neg);
}

#[test]
fn debug_contains_variant_name() {
    let neg = ChainNegative::UnknownCa;
    let dbg = format!("{neg:?}");
    assert!(dbg.contains("UnknownCa"), "Debug output: {dbg}");
}

#[test]
fn eq_same_variant_same_data() {
    let a = ChainNegative::ExpiredLeaf;
    let b = ChainNegative::ExpiredLeaf;
    assert_eq!(a, b);
}

#[test]
fn ne_different_variants() {
    assert_ne!(
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate
    );
    assert_ne!(ChainNegative::UnknownCa, ChainNegative::RevokedLeaf);
}

#[test]
fn ne_same_variant_different_data() {
    let a = ChainNegative::HostnameMismatch {
        wrong_hostname: "a.example.com".to_string(),
    };
    let b = ChainNegative::HostnameMismatch {
        wrong_hostname: "b.example.com".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn hash_equality_is_consistent() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let neg = ChainNegative::RevokedLeaf;
    let mut h1 = DefaultHasher::new();
    neg.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    neg.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn hash_differs_between_variants() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "x.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];
    let hashes: Vec<u64> = variants
        .iter()
        .map(|v| {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            h.finish()
        })
        .collect();

    // All hashes should be distinct (extremely likely for 5 distinct variants).
    for (i, a) in hashes.iter().enumerate() {
        for b in &hashes[i + 1..] {
            assert_ne!(a, b, "hash collision among chain negative variants");
        }
    }
}

// ---------------------------------------------------------------------------
// variant_name
// ---------------------------------------------------------------------------

#[test]
fn variant_name_hostname_mismatch_includes_hostname() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "attacker.example.com".to_string(),
    };
    let name = neg.variant_name();
    assert!(name.starts_with("hostname_mismatch:"));
    assert!(name.contains("attacker.example.com"));
}

#[test]
fn variant_name_all_unit_variants() {
    assert_eq!(ChainNegative::UnknownCa.variant_name(), "unknown_ca");
    assert_eq!(ChainNegative::ExpiredLeaf.variant_name(), "expired_leaf");
    assert_eq!(
        ChainNegative::ExpiredIntermediate.variant_name(),
        "expired_intermediate"
    );
    assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
}

#[test]
fn variant_names_are_unique() {
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "bad.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];
    let names: Vec<String> = variants.iter().map(|v| v.variant_name()).collect();
    for (i, a) in names.iter().enumerate() {
        for b in &names[i + 1..] {
            assert_ne!(a, b, "duplicate variant name");
        }
    }
}

// ---------------------------------------------------------------------------
// apply_to_spec — HostnameMismatch
// ---------------------------------------------------------------------------

#[test]
fn hostname_mismatch_replaces_leaf_cn_and_sans() {
    let base = ChainSpec::new("good.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let spec = neg.apply_to_spec(&base);
    assert_eq!(spec.leaf_cn, "evil.example.com");
    assert_eq!(spec.leaf_sans, vec!["evil.example.com".to_string()]);
}

#[test]
fn hostname_mismatch_preserves_ca_fields() {
    let base = ChainSpec::new("good.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let spec = neg.apply_to_spec(&base);
    assert_eq!(spec.root_cn, base.root_cn);
    assert_eq!(spec.intermediate_cn, base.intermediate_cn);
    assert_eq!(spec.rsa_bits, base.rsa_bits);
}

// ---------------------------------------------------------------------------
// apply_to_spec — UnknownCa
// ---------------------------------------------------------------------------

#[test]
fn unknown_ca_modifies_root_cn() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::UnknownCa.apply_to_spec(&base);
    assert_ne!(spec.root_cn, base.root_cn);
    assert!(spec.root_cn.contains("Unknown"));
}

#[test]
fn unknown_ca_preserves_leaf_and_intermediate() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::UnknownCa.apply_to_spec(&base);
    assert_eq!(spec.leaf_cn, base.leaf_cn);
    assert_eq!(spec.leaf_sans, base.leaf_sans);
    assert_eq!(spec.intermediate_cn, base.intermediate_cn);
    assert_eq!(spec.leaf_validity_days, base.leaf_validity_days);
}

// ---------------------------------------------------------------------------
// apply_to_spec — ExpiredLeaf
// ---------------------------------------------------------------------------

#[test]
fn expired_leaf_sets_short_validity_and_past_offset() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    assert_eq!(spec.leaf_validity_days, 1);
    assert_eq!(spec.leaf_not_before_offset_days, Some(730));
}

#[test]
fn expired_leaf_does_not_touch_intermediate_or_root() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    assert_eq!(spec.root_validity_days, base.root_validity_days);
    assert_eq!(
        spec.intermediate_validity_days,
        base.intermediate_validity_days
    );
    assert_eq!(
        spec.intermediate_not_before_offset_days,
        base.intermediate_not_before_offset_days
    );
}

// ---------------------------------------------------------------------------
// apply_to_spec — ExpiredIntermediate
// ---------------------------------------------------------------------------

#[test]
fn expired_intermediate_sets_short_validity_and_past_offset() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
    assert_eq!(spec.intermediate_validity_days, 1);
    assert_eq!(spec.intermediate_not_before_offset_days, Some(730));
}

#[test]
fn expired_intermediate_does_not_touch_leaf_or_root() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
    assert_eq!(spec.leaf_validity_days, base.leaf_validity_days);
    assert_eq!(
        spec.leaf_not_before_offset_days,
        base.leaf_not_before_offset_days
    );
    assert_eq!(spec.root_validity_days, base.root_validity_days);
}

// ---------------------------------------------------------------------------
// apply_to_spec — RevokedLeaf
// ---------------------------------------------------------------------------

#[test]
fn revoked_leaf_does_not_modify_spec() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::RevokedLeaf.apply_to_spec(&base);
    assert_eq!(spec, base);
}

// ---------------------------------------------------------------------------
// apply_to_spec — base spec is not mutated (all variants)
// ---------------------------------------------------------------------------

#[test]
fn apply_to_spec_does_not_mutate_original() {
    let base = ChainSpec::new("immutable.example.com");
    let original = base.clone();

    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "x.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];

    for v in &variants {
        let _ = v.apply_to_spec(&base);
        assert_eq!(base, original, "base mutated by {:?}", v);
    }
}

// ---------------------------------------------------------------------------
// apply_to_spec with custom base spec
// ---------------------------------------------------------------------------

#[test]
fn apply_preserves_custom_rsa_bits() {
    let base = ChainSpec::new("custom.example.com").with_rsa_bits(4096);
    let spec = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    assert_eq!(spec.rsa_bits, 4096);
}

#[test]
fn hostname_mismatch_overwrites_custom_sans() {
    let base = ChainSpec::new("custom.example.com").with_sans(vec![
        "alt1.example.com".to_string(),
        "alt2.example.com".to_string(),
    ]);
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    let spec = neg.apply_to_spec(&base);
    assert_eq!(spec.leaf_sans, vec!["wrong.example.com".to_string()]);
}
