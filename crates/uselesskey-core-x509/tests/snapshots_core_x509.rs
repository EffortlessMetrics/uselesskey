//! Insta snapshot tests for uselesskey-core-x509.
//!
//! These tests snapshot the facade re-exports and negative-policy
//! application to detect unintended changes.

use serde::Serialize;
use uselesskey_core_x509::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, ChainNegative, ChainSpec, KeyUsage,
    NotBeforeOffset, SERIAL_NUMBER_BYTES, X509Negative, X509Spec,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct DeriveConstants {
    base_time_epoch_unix: i64,
    base_time_window_days: u32,
    serial_number_bytes: usize,
}

#[test]
fn snapshot_derive_constants() {
    let c = DeriveConstants {
        base_time_epoch_unix: BASE_TIME_EPOCH_UNIX,
        base_time_window_days: BASE_TIME_WINDOW_DAYS,
        serial_number_bytes: SERIAL_NUMBER_BYTES,
    };
    insta::assert_yaml_snapshot!("derive_constants", c);
}

// ---------------------------------------------------------------------------
// X509Negative::apply_to_spec
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct NegativeSpecSnapshot {
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

fn neg_snapshot(variant: &'static str, neg: X509Negative) -> NegativeSpecSnapshot {
    let base = X509Spec::self_signed("neg.example.com");
    let spec = neg.apply_to_spec(&base);
    NegativeSpecSnapshot {
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
fn snapshot_x509_negative_all_variants() {
    let variants: Vec<NegativeSpecSnapshot> = vec![
        neg_snapshot("Expired", X509Negative::Expired),
        neg_snapshot("NotYetValid", X509Negative::NotYetValid),
        neg_snapshot("WrongKeyUsage", X509Negative::WrongKeyUsage),
        neg_snapshot("SelfSignedButClaimsCA", X509Negative::SelfSignedButClaimsCA),
    ];
    insta::assert_yaml_snapshot!("x509_negative_all_variants", variants);
}

// ---------------------------------------------------------------------------
// ChainNegative::apply_to_spec
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChainNegativeSpecSnapshot {
    variant: String,
    leaf_cn: String,
    leaf_sans: Vec<String>,
    root_cn: String,
    leaf_validity_days: u32,
    intermediate_validity_days: u32,
    leaf_not_before_offset_days: Option<i64>,
    intermediate_not_before_offset_days: Option<i64>,
}

fn chain_neg_snapshot(neg: &ChainNegative) -> ChainNegativeSpecSnapshot {
    let base = ChainSpec::new("chain.example.com");
    let spec = neg.apply_to_spec(&base);
    ChainNegativeSpecSnapshot {
        variant: neg.variant_name(),
        leaf_cn: spec.leaf_cn,
        leaf_sans: spec.leaf_sans,
        root_cn: spec.root_cn,
        leaf_validity_days: spec.leaf_validity_days,
        intermediate_validity_days: spec.intermediate_validity_days,
        leaf_not_before_offset_days: spec.leaf_not_before_offset_days,
        intermediate_not_before_offset_days: spec.intermediate_not_before_offset_days,
    }
}

#[test]
fn snapshot_chain_negative_all_variants() {
    let variants: Vec<ChainNegativeSpecSnapshot> = vec![
        chain_neg_snapshot(&ChainNegative::HostnameMismatch {
            wrong_hostname: "evil.example.com".to_string(),
        }),
        chain_neg_snapshot(&ChainNegative::UnknownCa),
        chain_neg_snapshot(&ChainNegative::ExpiredLeaf),
        chain_neg_snapshot(&ChainNegative::ExpiredIntermediate),
        chain_neg_snapshot(&ChainNegative::RevokedLeaf),
    ];
    insta::assert_yaml_snapshot!("chain_negative_all_variants", variants);
}

// ---------------------------------------------------------------------------
// X509Spec defaults and builder
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SpecDefaults {
    subject_cn: String,
    issuer_cn: String,
    not_before_offset: String,
    validity_days: u32,
    is_ca: bool,
    rsa_bits: usize,
    key_cert_sign: bool,
    crl_sign: bool,
    digital_signature: bool,
    key_encipherment: bool,
    sans: Vec<String>,
}

fn spec_snapshot(spec: &X509Spec) -> SpecDefaults {
    SpecDefaults {
        subject_cn: spec.subject_cn.clone(),
        issuer_cn: spec.issuer_cn.clone(),
        not_before_offset: fmt_offset(&spec.not_before_offset),
        validity_days: spec.validity_days,
        is_ca: spec.is_ca,
        rsa_bits: spec.rsa_bits,
        key_cert_sign: spec.key_usage.key_cert_sign,
        crl_sign: spec.key_usage.crl_sign,
        digital_signature: spec.key_usage.digital_signature,
        key_encipherment: spec.key_usage.key_encipherment,
        sans: spec.sans.clone(),
    }
}

#[test]
fn snapshot_self_signed_spec_defaults() {
    let spec = X509Spec::self_signed("snap.example.com");
    insta::assert_yaml_snapshot!("self_signed_spec_defaults", spec_snapshot(&spec));
}

#[test]
fn snapshot_self_signed_ca_spec_defaults() {
    let spec = X509Spec::self_signed_ca("Snap Root CA");
    insta::assert_yaml_snapshot!("self_signed_ca_spec_defaults", spec_snapshot(&spec));
}

#[test]
fn snapshot_key_usage_leaf_vs_ca() {
    #[derive(Serialize)]
    struct UsageComparison {
        leaf: [u8; 4],
        ca: [u8; 4],
    }
    let cmp = UsageComparison {
        leaf: KeyUsage::leaf().stable_bytes(),
        ca: KeyUsage::ca().stable_bytes(),
    };
    insta::assert_yaml_snapshot!("key_usage_leaf_vs_ca", cmp);
}
