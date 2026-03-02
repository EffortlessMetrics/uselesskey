//! Insta snapshot tests for uselesskey-core-x509-chain-negative.
//!
//! Snapshot ChainNegative variant names and the spec modifications each
//! variant applies. No key material is captured.

use serde::Serialize;
use uselesskey_core_x509_chain_negative::ChainNegative;
use uselesskey_core_x509_spec::ChainSpec;

#[derive(Serialize)]
struct ChainNegativeVariantShape {
    variant_name: String,
    leaf_cn: String,
    root_cn: String,
    leaf_validity_days: u32,
    intermediate_validity_days: u32,
    leaf_not_before_offset_days: Option<i64>,
    intermediate_not_before_offset_days: Option<i64>,
    leaf_sans_count: usize,
    differs_from_base: bool,
}

fn base_spec() -> ChainSpec {
    ChainSpec::new("test.example.com")
}

fn variant_shape(variant: &ChainNegative) -> ChainNegativeVariantShape {
    let base = base_spec();
    let modified = variant.apply_to_spec(&base);
    ChainNegativeVariantShape {
        variant_name: variant.variant_name(),
        leaf_cn: modified.leaf_cn.clone(),
        root_cn: modified.root_cn.clone(),
        leaf_validity_days: modified.leaf_validity_days,
        intermediate_validity_days: modified.intermediate_validity_days,
        leaf_not_before_offset_days: modified.leaf_not_before_offset_days,
        intermediate_not_before_offset_days: modified.intermediate_not_before_offset_days,
        leaf_sans_count: modified.leaf_sans.len(),
        differs_from_base: modified != base,
    }
}

#[test]
fn snapshot_chain_negative_hostname_mismatch() {
    let variant = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".into(),
    };
    insta::assert_yaml_snapshot!("chain_neg_hostname_mismatch", variant_shape(&variant));
}

#[test]
fn snapshot_chain_negative_unknown_ca() {
    let variant = ChainNegative::UnknownCa;
    insta::assert_yaml_snapshot!("chain_neg_unknown_ca", variant_shape(&variant));
}

#[test]
fn snapshot_chain_negative_expired_leaf() {
    let variant = ChainNegative::ExpiredLeaf;
    insta::assert_yaml_snapshot!("chain_neg_expired_leaf", variant_shape(&variant));
}

#[test]
fn snapshot_chain_negative_expired_intermediate() {
    let variant = ChainNegative::ExpiredIntermediate;
    insta::assert_yaml_snapshot!("chain_neg_expired_intermediate", variant_shape(&variant));
}

#[test]
fn snapshot_chain_negative_revoked_leaf() {
    let variant = ChainNegative::RevokedLeaf;
    insta::assert_yaml_snapshot!("chain_neg_revoked_leaf", variant_shape(&variant));
}

#[test]
fn snapshot_chain_negative_all_variant_names() {
    #[derive(Serialize)]
    struct VariantNameList {
        variants: Vec<String>,
    }

    let variants = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".into(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];

    let result = VariantNameList {
        variants: variants.iter().map(|v| v.variant_name()).collect(),
    };

    insta::assert_yaml_snapshot!("chain_neg_all_variant_names", result);
}
