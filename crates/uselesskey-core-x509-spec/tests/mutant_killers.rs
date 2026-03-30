//! Mutant-killing tests for X.509 spec types.

use std::time::Duration;
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};
use uselesskey_core_x509_spec::{
    CrlIssuerKind, CrlSpec, OcspCertStatus, OcspNoncePolicy, OcspResponderKind, OcspSpec,
    RevocationReasonCode, TimeOffsetDays,
};

// ── KeyUsage ─────────────────────────────────────────────────────

#[test]
fn key_usage_leaf_exact_fields() {
    let ku = KeyUsage::leaf();
    assert!(!ku.key_cert_sign);
    assert!(!ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(ku.key_encipherment);
}

#[test]
fn key_usage_ca_exact_fields() {
    let ku = KeyUsage::ca();
    assert!(ku.key_cert_sign);
    assert!(ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(!ku.key_encipherment);
}

#[test]
fn key_usage_stable_bytes_leaf() {
    let ku = KeyUsage::leaf();
    assert_eq!(ku.stable_bytes(), [0, 0, 1, 1]);
}

#[test]
fn key_usage_stable_bytes_ca() {
    let ku = KeyUsage::ca();
    assert_eq!(ku.stable_bytes(), [1, 1, 1, 0]);
}

#[test]
fn key_usage_stable_bytes_all_false() {
    let ku = KeyUsage {
        key_cert_sign: false,
        crl_sign: false,
        digital_signature: false,
        key_encipherment: false,
    };
    assert_eq!(ku.stable_bytes(), [0, 0, 0, 0]);
}

#[test]
fn key_usage_stable_bytes_all_true() {
    let ku = KeyUsage {
        key_cert_sign: true,
        crl_sign: true,
        digital_signature: true,
        key_encipherment: true,
    };
    assert_eq!(ku.stable_bytes(), [1, 1, 1, 1]);
}

#[test]
fn key_usage_leaf_ne_ca() {
    assert_ne!(KeyUsage::leaf(), KeyUsage::ca());
    assert_ne!(
        KeyUsage::leaf().stable_bytes(),
        KeyUsage::ca().stable_bytes()
    );
}

// ── NotBeforeOffset ──────────────────────────────────────────────

#[test]
fn not_before_offset_default_is_days_ago_1() {
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}

#[test]
fn not_before_offset_variants_differ() {
    assert_ne!(NotBeforeOffset::DaysAgo(1), NotBeforeOffset::DaysFromNow(1));
}

// ── X509Spec ─────────────────────────────────────────────────────

#[test]
fn x509_spec_default_exact_values() {
    let spec = X509Spec::default();
    assert_eq!(spec.subject_cn, "Test Certificate");
    assert_eq!(spec.issuer_cn, "Test Certificate");
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysAgo(1));
    assert_eq!(spec.validity_days, 3650);
    assert_eq!(spec.key_usage, KeyUsage::leaf());
    assert!(!spec.is_ca);
    assert_eq!(spec.rsa_bits, 2048);
    assert!(spec.sans.is_empty());
}

#[test]
fn self_signed_sets_subject_and_issuer_to_same() {
    let spec = X509Spec::self_signed("example.com");
    assert_eq!(spec.subject_cn, "example.com");
    assert_eq!(spec.issuer_cn, "example.com");
}

#[test]
fn self_signed_ca_sets_ca_flags() {
    let spec = X509Spec::self_signed_ca("My CA");
    assert!(spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::ca());
    assert_eq!(spec.subject_cn, "My CA");
    assert_eq!(spec.issuer_cn, "My CA");
}

#[test]
fn not_before_duration_days_ago_computes_correctly() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysAgo(5));
    let expected_secs = 5u64 * 24 * 60 * 60;
    assert_eq!(
        spec.not_before_duration(),
        Duration::from_secs(expected_secs)
    );
}

#[test]
fn not_before_duration_days_from_now_is_zero() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysFromNow(30));
    assert_eq!(spec.not_before_duration(), Duration::ZERO);
}

#[test]
fn not_after_duration_days_ago_is_just_validity() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysAgo(1))
        .with_validity_days(10);
    let expected = Duration::from_secs(10 * 24 * 60 * 60);
    assert_eq!(spec.not_after_duration(), expected);
}

#[test]
fn not_after_duration_days_from_now_adds_offset() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysFromNow(5))
        .with_validity_days(10);
    let expected = Duration::from_secs((5 + 10) * 24 * 60 * 60);
    assert_eq!(spec.not_after_duration(), expected);
}

#[test]
fn stable_bytes_version_prefix_is_4() {
    let spec = X509Spec::self_signed("test");
    let bytes = spec.stable_bytes();
    assert_eq!(bytes[0], 4, "version prefix must be 4");
}

#[test]
fn stable_bytes_not_before_tag_byte_days_ago() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysAgo(1));
    let bytes = spec.stable_bytes();
    // After version(1) + subject_cn(4+1) + issuer_cn(4+1), the not_before tag byte
    let subject_len = "t".len();
    let issuer_len = "t".len();
    let offset = 1 + 4 + subject_len + 4 + issuer_len;
    assert_eq!(bytes[offset], 0, "DaysAgo tag must be 0");
}

#[test]
fn stable_bytes_not_before_tag_byte_days_from_now() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysFromNow(1));
    let bytes = spec.stable_bytes();
    let subject_len = "t".len();
    let issuer_len = "t".len();
    let offset = 1 + 4 + subject_len + 4 + issuer_len;
    assert_eq!(bytes[offset], 1, "DaysFromNow tag must be 1");
}

// ── ChainSpec ────────────────────────────────────────────────────

#[test]
fn chain_spec_new_defaults() {
    let spec = ChainSpec::new("leaf.example.com");
    assert_eq!(spec.leaf_cn, "leaf.example.com");
    assert_eq!(spec.leaf_sans, vec!["leaf.example.com"]);
    assert_eq!(spec.root_cn, "leaf.example.com Root CA");
    assert_eq!(spec.intermediate_cn, "leaf.example.com Intermediate CA");
    assert_eq!(spec.rsa_bits, 2048);
    assert_eq!(spec.root_validity_days, 3650);
    assert_eq!(spec.intermediate_validity_days, 1825);
    assert_eq!(spec.leaf_validity_days, 3650);
    assert!(spec.leaf_not_before.is_none());
    assert!(spec.intermediate_not_before.is_none());
}

#[test]
fn chain_spec_stable_bytes_version_is_2() {
    let spec = ChainSpec::new("test");
    let bytes = spec.stable_bytes();
    assert_eq!(
        bytes[0], 2,
        "default chain spec stable_bytes must keep the v2 compatibility prefix"
    );
}

#[test]
fn chain_spec_future_offsets_use_v3() {
    let spec = ChainSpec::new("test").with_leaf_not_before(NotBeforeOffset::DaysFromNow(1));
    let bytes = spec.stable_bytes();
    assert_eq!(bytes[0], 3, "future offsets must opt into v3 encoding");
}

#[test]
fn chain_spec_none_offset_tag_is_0() {
    let spec = ChainSpec::new("test");
    let bytes = spec.stable_bytes();
    // Find the offset tag bytes at the end
    // none tag should be 0
    let len = bytes.len();
    // Last two bytes should be the tags (both None = 0)
    assert_eq!(bytes[len - 1], 0, "intermediate offset None tag must be 0");
    assert_eq!(bytes[len - 2], 0, "leaf offset None tag must be 0");
}

#[test]
fn chain_spec_some_offset_tag_is_1() {
    let mut spec = ChainSpec::new("test");
    spec.leaf_not_before = Some(NotBeforeOffset::DaysAgo(100));
    let bytes = spec.stable_bytes();
    // The intermediate is still None (last byte = 0), leaf has Some (tag = 1)
    let len = bytes.len();
    assert_eq!(bytes[len - 1], 0, "intermediate offset None tag must be 0");
}

// ── Revocation fixtures ──────────────────────────────────────────

#[test]
fn crl_spec_for_intermediate_sets_expected_defaults() {
    let spec = CrlSpec::for_intermediate(vec![0x01, 0x02, 0x03]);

    assert_eq!(spec.issuer_kind, CrlIssuerKind::Intermediate);
    assert_eq!(spec.this_update, TimeOffsetDays::from_base(0));
    assert_eq!(spec.next_update, TimeOffsetDays::from_base(30));
    assert_eq!(spec.revoked_serials, vec![vec![0x01, 0x02, 0x03]]);
    assert_eq!(spec.reason_code, Some(RevocationReasonCode::KeyCompromise));
    assert_eq!(spec.crl_number, 1);
}

#[test]
fn crl_spec_stable_bytes_encode_all_fields() {
    let spec = CrlSpec {
        issuer_kind: CrlIssuerKind::Root,
        this_update: TimeOffsetDays::from_base(-2),
        next_update: TimeOffsetDays::from_base(5),
        revoked_serials: vec![vec![0x02], vec![0x01, 0x02], vec![0x02]],
        reason_code: Some(RevocationReasonCode::AaCompromise),
        crl_number: 0x0102_0304_0506_0708,
    };

    assert_eq!(
        spec.stable_bytes(),
        vec![
            1, 1, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02,
            0x00, 0x00, 0x00, 0x01, 0x02,
        ]
    );
}

#[test]
fn ocsp_spec_for_issuer_revoked_sets_reason_and_nonce_policy() {
    let spec = OcspSpec::for_issuer(OcspCertStatus::Revoked);

    assert_eq!(spec.responder_kind, OcspResponderKind::Issuer);
    assert_eq!(spec.produced_at, TimeOffsetDays::from_base(0));
    assert_eq!(spec.this_update, TimeOffsetDays::from_base(0));
    assert_eq!(spec.next_update, Some(TimeOffsetDays::from_base(7)));
    assert_eq!(spec.cert_status, OcspCertStatus::Revoked);
    assert_eq!(
        spec.revocation_reason,
        Some(RevocationReasonCode::KeyCompromise)
    );
    assert_eq!(spec.nonce_policy, OcspNoncePolicy::Deterministic);
}

#[test]
fn ocsp_spec_stable_bytes_encode_all_fields() {
    let spec = OcspSpec {
        responder_kind: OcspResponderKind::Intermediate,
        produced_at: TimeOffsetDays::from_base(-1),
        this_update: TimeOffsetDays::from_base(2),
        next_update: None,
        cert_status: OcspCertStatus::Unknown,
        revocation_reason: Some(RevocationReasonCode::AaCompromise),
        nonce_policy: OcspNoncePolicy::Absent,
    };

    assert_eq!(
        spec.stable_bytes(),
        vec![
            1, 3, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x09, 0x00,
        ]
    );
}
