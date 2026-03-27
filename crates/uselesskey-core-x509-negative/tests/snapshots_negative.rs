//! Insta snapshot tests for uselesskey-core-x509-negative.
//!
//! These tests snapshot negative-fixture policy application and
//! variant metadata to detect unintended changes.

use serde::Serialize;
use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{NotBeforeOffset, X509Spec};

// ---------------------------------------------------------------------------
// X509Negative variant metadata
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct VariantMeta {
    variant: &'static str,
    variant_name: &'static str,
    description: &'static str,
}

#[test]
fn snapshot_x509_negative_variant_metadata() {
    let metas: Vec<VariantMeta> = vec![
        VariantMeta {
            variant: "Expired",
            variant_name: X509Negative::Expired.variant_name(),
            description: X509Negative::Expired.description(),
        },
        VariantMeta {
            variant: "NotYetValid",
            variant_name: X509Negative::NotYetValid.variant_name(),
            description: X509Negative::NotYetValid.description(),
        },
        VariantMeta {
            variant: "WrongKeyUsage",
            variant_name: X509Negative::WrongKeyUsage.variant_name(),
            description: X509Negative::WrongKeyUsage.description(),
        },
        VariantMeta {
            variant: "SelfSignedButClaimsCA",
            variant_name: X509Negative::SelfSignedButClaimsCA.variant_name(),
            description: X509Negative::SelfSignedButClaimsCA.description(),
        },
    ];
    insta::assert_yaml_snapshot!("x509_negative_variant_metadata", metas);
}

// ---------------------------------------------------------------------------
// X509Negative::apply_to_spec — full spec output
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AppliedSpecSnapshot {
    variant: &'static str,
    subject_cn: String,
    not_before_offset: String,
    validity_days: u32,
    is_ca: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    digital_signature: bool,
    key_encipherment: bool,
}

fn fmt_offset(o: &NotBeforeOffset) -> String {
    match o {
        NotBeforeOffset::DaysAgo(d) => format!("DaysAgo({d})"),
        NotBeforeOffset::DaysFromNow(d) => format!("DaysFromNow({d})"),
    }
}

fn nbo_string(o: &NotBeforeOffset) -> String {
    fmt_offset(o)
}

fn apply_snapshot(variant: &'static str, neg: X509Negative) -> AppliedSpecSnapshot {
    let base = X509Spec::self_signed("neg.example.com");
    let spec = neg.apply_to_spec(&base);
    AppliedSpecSnapshot {
        variant,
        subject_cn: spec.subject_cn,
        not_before_offset: fmt_offset(&spec.not_before_offset),
        validity_days: spec.validity_days,
        is_ca: spec.is_ca,
        key_cert_sign: spec.key_usage.key_cert_sign,
        crl_sign: spec.key_usage.crl_sign,
        digital_signature: spec.key_usage.digital_signature,
        key_encipherment: spec.key_usage.key_encipherment,
    }
}

#[test]
fn snapshot_x509_negative_applied_specs() {
    let specs: Vec<AppliedSpecSnapshot> = vec![
        apply_snapshot("Expired", X509Negative::Expired),
        apply_snapshot("NotYetValid", X509Negative::NotYetValid),
        apply_snapshot("WrongKeyUsage", X509Negative::WrongKeyUsage),
        apply_snapshot("SelfSignedButClaimsCA", X509Negative::SelfSignedButClaimsCA),
    ];
    insta::assert_yaml_snapshot!("x509_negative_applied_specs", specs);
}

// ---------------------------------------------------------------------------
// ChainNegative variant metadata
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChainVariantMeta {
    variant: &'static str,
    variant_name: String,
}

#[test]
fn snapshot_chain_negative_variant_names() {
    let metas: Vec<ChainVariantMeta> = vec![
        ChainVariantMeta {
            variant: "HostnameMismatch",
            variant_name: ChainNegative::HostnameMismatch {
                wrong_hostname: "evil.example.com".to_string(),
            }
            .variant_name(),
        },
        ChainVariantMeta {
            variant: "UnknownCa",
            variant_name: ChainNegative::UnknownCa.variant_name(),
        },
        ChainVariantMeta {
            variant: "ExpiredLeaf",
            variant_name: ChainNegative::ExpiredLeaf.variant_name(),
        },
        ChainVariantMeta {
            variant: "NotYetValidLeaf",
            variant_name: ChainNegative::NotYetValidLeaf.variant_name(),
        },
        ChainVariantMeta {
            variant: "ExpiredIntermediate",
            variant_name: ChainNegative::ExpiredIntermediate.variant_name(),
        },
        ChainVariantMeta {
            variant: "NotYetValidIntermediate",
            variant_name: ChainNegative::NotYetValidIntermediate.variant_name(),
        },
        ChainVariantMeta {
            variant: "IntermediateNotCa",
            variant_name: ChainNegative::IntermediateNotCa.variant_name(),
        },
        ChainVariantMeta {
            variant: "IntermediateWrongKeyUsage",
            variant_name: ChainNegative::IntermediateWrongKeyUsage.variant_name(),
        },
        ChainVariantMeta {
            variant: "RevokedLeaf",
            variant_name: ChainNegative::RevokedLeaf.variant_name(),
        },
    ];
    insta::assert_yaml_snapshot!("chain_negative_variant_names", metas);
}

// ---------------------------------------------------------------------------
// ChainNegative::apply_to_spec
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChainAppliedSnapshot {
    variant: String,
    leaf_cn: String,
    leaf_sans: Vec<String>,
    root_cn: String,
    leaf_validity_days: u32,
    intermediate_validity_days: u32,
    leaf_not_before: Option<String>,
    intermediate_not_before: Option<String>,
    intermediate_is_ca: Option<bool>,
    intermediate_key_usage: Option<[u8; 4]>,
}

fn chain_apply_snapshot(neg: &ChainNegative) -> ChainAppliedSnapshot {
    let base = uselesskey_core_x509_spec::ChainSpec::new("chain.example.com");
    let spec = neg.apply_to_spec(&base);
    ChainAppliedSnapshot {
        variant: neg.variant_name(),
        leaf_cn: spec.leaf_cn,
        leaf_sans: spec.leaf_sans,
        root_cn: spec.root_cn,
        leaf_validity_days: spec.leaf_validity_days,
        intermediate_validity_days: spec.intermediate_validity_days,
        leaf_not_before: spec.leaf_not_before.map(|o| nbo_string(&o)),
        intermediate_not_before: spec.intermediate_not_before.map(|o| nbo_string(&o)),
        intermediate_is_ca: spec.intermediate_is_ca,
        intermediate_key_usage: spec.intermediate_key_usage.map(|ku| ku.stable_bytes()),
    }
}

#[test]
fn snapshot_chain_negative_applied_specs() {
    let specs: Vec<ChainAppliedSnapshot> = vec![
        chain_apply_snapshot(&ChainNegative::HostnameMismatch {
            wrong_hostname: "evil.example.com".to_string(),
        }),
        chain_apply_snapshot(&ChainNegative::UnknownCa),
        chain_apply_snapshot(&ChainNegative::ExpiredLeaf),
        chain_apply_snapshot(&ChainNegative::NotYetValidLeaf),
        chain_apply_snapshot(&ChainNegative::ExpiredIntermediate),
        chain_apply_snapshot(&ChainNegative::NotYetValidIntermediate),
        chain_apply_snapshot(&ChainNegative::IntermediateNotCa),
        chain_apply_snapshot(&ChainNegative::IntermediateWrongKeyUsage),
        chain_apply_snapshot(&ChainNegative::RevokedLeaf),
    ];
    insta::assert_yaml_snapshot!("chain_negative_applied_specs", specs);
}
