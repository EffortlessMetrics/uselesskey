//! Insta snapshot tests for uselesskey-core-x509-spec.
//!
//! Snapshot X.509 spec metadata shapes: field values, stable_bytes lengths,
//! key-usage flags, and ChainSpec defaults. No key material is captured.

use serde::Serialize;
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ── X509Spec snapshots ──────────────────────────────────────────────

#[derive(Serialize)]
struct X509SpecShape {
    subject_cn: String,
    issuer_cn: String,
    validity_days: u32,
    is_ca: bool,
    rsa_bits: usize,
    sans_count: usize,
    not_before_offset: String,
    key_usage: KeyUsageShape,
    stable_bytes_len: usize,
}

#[derive(Serialize)]
struct KeyUsageShape {
    key_cert_sign: bool,
    crl_sign: bool,
    digital_signature: bool,
    key_encipherment: bool,
    stable_bytes: [u8; 4],
}

fn ku_shape(ku: &KeyUsage) -> KeyUsageShape {
    KeyUsageShape {
        key_cert_sign: ku.key_cert_sign,
        crl_sign: ku.crl_sign,
        digital_signature: ku.digital_signature,
        key_encipherment: ku.key_encipherment,
        stable_bytes: ku.stable_bytes(),
    }
}

fn nbo_string(nbo: &NotBeforeOffset) -> String {
    match nbo {
        NotBeforeOffset::DaysAgo(d) => format!("DaysAgo({d})"),
        NotBeforeOffset::DaysFromNow(d) => format!("DaysFromNow({d})"),
    }
}

#[test]
fn snapshot_x509_spec_default() {
    let spec = X509Spec::default();
    let result = X509SpecShape {
        subject_cn: spec.subject_cn.clone(),
        issuer_cn: spec.issuer_cn.clone(),
        validity_days: spec.validity_days,
        is_ca: spec.is_ca,
        rsa_bits: spec.rsa_bits,
        sans_count: spec.sans.len(),
        not_before_offset: nbo_string(&spec.not_before_offset),
        key_usage: ku_shape(&spec.key_usage),
        stable_bytes_len: spec.stable_bytes().len(),
    };
    insta::assert_yaml_snapshot!("x509_spec_default", result);
}

#[test]
fn snapshot_x509_spec_self_signed_leaf() {
    let spec = X509Spec::self_signed("myapp.example.com")
        .with_validity_days(90)
        .with_sans(vec!["myapp.example.com".into(), "api.example.com".into()])
        .with_rsa_bits(4096);

    let result = X509SpecShape {
        subject_cn: spec.subject_cn.clone(),
        issuer_cn: spec.issuer_cn.clone(),
        validity_days: spec.validity_days,
        is_ca: spec.is_ca,
        rsa_bits: spec.rsa_bits,
        sans_count: spec.sans.len(),
        not_before_offset: nbo_string(&spec.not_before_offset),
        key_usage: ku_shape(&spec.key_usage),
        stable_bytes_len: spec.stable_bytes().len(),
    };
    insta::assert_yaml_snapshot!("x509_spec_self_signed_leaf", result);
}

#[test]
fn snapshot_x509_spec_ca() {
    let spec = X509Spec::self_signed_ca("My Test CA");
    let result = X509SpecShape {
        subject_cn: spec.subject_cn.clone(),
        issuer_cn: spec.issuer_cn.clone(),
        validity_days: spec.validity_days,
        is_ca: spec.is_ca,
        rsa_bits: spec.rsa_bits,
        sans_count: spec.sans.len(),
        not_before_offset: nbo_string(&spec.not_before_offset),
        key_usage: ku_shape(&spec.key_usage),
        stable_bytes_len: spec.stable_bytes().len(),
    };
    insta::assert_yaml_snapshot!("x509_spec_ca", result);
}

#[test]
fn snapshot_x509_key_usage_presets() {
    #[derive(Serialize)]
    struct KeyUsagePresets {
        leaf: KeyUsageShape,
        ca: KeyUsageShape,
    }

    let result = KeyUsagePresets {
        leaf: ku_shape(&KeyUsage::leaf()),
        ca: ku_shape(&KeyUsage::ca()),
    };
    insta::assert_yaml_snapshot!("x509_key_usage_presets", result);
}

#[test]
fn snapshot_x509_spec_stable_bytes_determinism() {
    #[derive(Serialize)]
    struct StableBytesCheck {
        spec_description: &'static str,
        stable_bytes_len: usize,
        is_deterministic: bool,
    }

    let specs: Vec<(&str, X509Spec)> = vec![
        ("default", X509Spec::default()),
        ("self_signed_leaf", X509Spec::self_signed("test.com")),
        ("ca", X509Spec::self_signed_ca("CA").with_rsa_bits(4096)),
        (
            "with_sans",
            X509Spec::self_signed("san.com").with_sans(vec!["a.com".into(), "b.com".into()]),
        ),
        (
            "future_not_before",
            X509Spec::self_signed("future.com").with_not_before(NotBeforeOffset::DaysFromNow(7)),
        ),
    ];

    let results: Vec<StableBytesCheck> = specs
        .into_iter()
        .map(|(desc, spec)| {
            let a = spec.stable_bytes();
            let b = spec.stable_bytes();
            StableBytesCheck {
                spec_description: desc,
                stable_bytes_len: a.len(),
                is_deterministic: a == b,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("x509_spec_stable_bytes_determinism", results);
}

// ── ChainSpec snapshots ─────────────────────────────────────────────

#[derive(Serialize)]
struct ChainSpecShape {
    leaf_cn: String,
    root_cn: String,
    intermediate_cn: String,
    leaf_sans_count: usize,
    rsa_bits: usize,
    root_validity_days: u32,
    intermediate_validity_days: u32,
    leaf_validity_days: u32,
    leaf_not_before_offset_days: Option<i64>,
    intermediate_not_before_offset_days: Option<i64>,
    stable_bytes_len: usize,
}

fn chain_shape(spec: &ChainSpec) -> ChainSpecShape {
    ChainSpecShape {
        leaf_cn: spec.leaf_cn.clone(),
        root_cn: spec.root_cn.clone(),
        intermediate_cn: spec.intermediate_cn.clone(),
        leaf_sans_count: spec.leaf_sans.len(),
        rsa_bits: spec.rsa_bits,
        root_validity_days: spec.root_validity_days,
        intermediate_validity_days: spec.intermediate_validity_days,
        leaf_validity_days: spec.leaf_validity_days,
        leaf_not_before_offset_days: spec.leaf_not_before_offset_days,
        intermediate_not_before_offset_days: spec.intermediate_not_before_offset_days,
        stable_bytes_len: spec.stable_bytes().len(),
    }
}

#[test]
fn snapshot_chain_spec_default() {
    let spec = ChainSpec::new("test.example.com");
    insta::assert_yaml_snapshot!("chain_spec_default", chain_shape(&spec));
}

#[test]
fn snapshot_chain_spec_custom() {
    let spec = ChainSpec::new("custom.example.com")
        .with_sans(vec![
            "custom.example.com".into(),
            "www.custom.example.com".into(),
        ])
        .with_root_cn("Custom Root CA")
        .with_intermediate_cn("Custom Int CA")
        .with_rsa_bits(4096)
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(90);

    insta::assert_yaml_snapshot!("chain_spec_custom", chain_shape(&spec));
}

#[test]
fn snapshot_chain_spec_stable_bytes_determinism() {
    #[derive(Serialize)]
    struct ChainStableBytesCheck {
        description: &'static str,
        stable_bytes_len: usize,
        is_deterministic: bool,
    }

    let spec = ChainSpec::new("det.example.com");
    let a = spec.stable_bytes();
    let b = spec.stable_bytes();

    let result = ChainStableBytesCheck {
        description: "ChainSpec::new default",
        stable_bytes_len: a.len(),
        is_deterministic: a == b,
    };

    insta::assert_yaml_snapshot!("chain_spec_stable_bytes", result);
}
