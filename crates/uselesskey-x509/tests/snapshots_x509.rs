//! Insta snapshot tests for uselesskey-x509 certificate fixtures.
//!
//! These tests snapshot certificate shapes produced by deterministic keys
//! to detect unintended changes in X.509 output.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};
use x509_parser::prelude::*;

// =========================================================================
// Snapshot structs
// =========================================================================

#[derive(Serialize)]
struct SelfSignedSnapshot {
    label: String,
    subject_cn: String,
    issuer_cn: String,
    is_ca: bool,
    validity_days: i64,
    serial_number_len: usize,
    cert_pem_has_header: bool,
    cert_pem_has_footer: bool,
    private_key_pem_has_header: bool,
    private_key_pem_has_footer: bool,
    cert_der_len: usize,
    key_usage_digital_signature: bool,
    key_usage_key_encipherment: bool,
    key_usage_key_cert_sign: bool,
    key_usage_crl_sign: bool,
    has_eku: bool,
    eku_server_auth: Option<bool>,
    eku_client_auth: Option<bool>,
}

#[derive(Serialize)]
struct ChainSnapshot {
    label: String,
    root_cn: String,
    root_is_ca: bool,
    intermediate_cn: String,
    intermediate_is_ca: bool,
    leaf_cn: String,
    leaf_is_ca: bool,
    chain_pem_cert_count: usize,
    full_chain_pem_cert_count: usize,
    root_serial_len: usize,
    intermediate_serial_len: usize,
    leaf_serial_len: usize,
    issuer_chain_valid: bool,
}

#[derive(Serialize)]
struct NegativeCertSnapshot {
    variant: String,
    subject_cn: String,
    is_ca: bool,
    validity_days: i64,
    differs_from_good: bool,
}

#[derive(Serialize)]
struct CorruptPemSnapshot {
    variant: String,
    contains_begin_certificate: bool,
    contains_begin_corrupted: bool,
}

#[derive(Serialize)]
struct ChainNegativeSnapshot {
    variant: String,
    leaf_cn: String,
    root_cn: String,
    leaf_differs_from_good: bool,
    has_crl: bool,
}

// =========================================================================
// Helper functions
// =========================================================================

fn parse_key_usage(parsed: &X509Certificate<'_>) -> (bool, bool, bool, bool) {
    let ku_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE);

    match ku_ext {
        Some(ext) => match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::KeyUsage(ku) => (
                ku.digital_signature(),
                ku.key_encipherment(),
                ku.key_cert_sign(),
                ku.crl_sign(),
            ),
            _ => (false, false, false, false),
        },
        None => (false, false, false, false),
    }
}

fn parse_eku(
    parsed: &X509Certificate<'_>,
) -> (bool, Option<bool>, Option<bool>) {
    let eku_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE);

    match eku_ext {
        Some(ext) => match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
                (true, Some(eku.server_auth), Some(eku.client_auth))
            }
            _ => (false, None, None),
        },
        None => (false, None, None),
    }
}

fn get_cn(name: &x509_parser::x509::X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("<none>")
        .to_string()
}

// =========================================================================
// Self-signed cert snapshots
// =========================================================================

#[test]
fn snapshot_self_signed_leaf() {
    let fx = fx();
    let spec = X509Spec::self_signed("snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-leaf", spec);

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    let (ds, ke, kcs, cs) = parse_key_usage(&parsed);
    let (has_eku, sa, ca) = parse_eku(&parsed);

    let result = SelfSignedSnapshot {
        label: cert.label().to_string(),
        subject_cn: get_cn(&parsed.subject()),
        issuer_cn: get_cn(&parsed.issuer()),
        is_ca: parsed.is_ca(),
        validity_days,
        serial_number_len: parsed.serial.to_bytes_be().len(),
        cert_pem_has_header: cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"),
        cert_pem_has_footer: cert.cert_pem().contains("-----END CERTIFICATE-----"),
        private_key_pem_has_header: cert
            .private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----"),
        private_key_pem_has_footer: cert
            .private_key_pkcs8_pem()
            .contains("-----END PRIVATE KEY-----"),
        cert_der_len: cert.cert_der().len(),
        key_usage_digital_signature: ds,
        key_usage_key_encipherment: ke,
        key_usage_key_cert_sign: kcs,
        key_usage_crl_sign: cs,
        has_eku,
        eku_server_auth: sa,
        eku_client_auth: ca,
    };

    insta::assert_yaml_snapshot!("self_signed_leaf", result, {
        ".cert_der_len" => "[REDACTED]",
        ".serial_number_len" => "[REDACTED]",
    });
}

#[test]
fn snapshot_self_signed_ca() {
    let fx = fx();
    let spec = X509Spec::self_signed_ca("snapshot-ca.example.com");
    let cert = fx.x509_self_signed("snapshot-ca", spec);

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    let (ds, ke, kcs, cs) = parse_key_usage(&parsed);
    let (has_eku, sa, ca) = parse_eku(&parsed);

    let result = SelfSignedSnapshot {
        label: cert.label().to_string(),
        subject_cn: get_cn(&parsed.subject()),
        issuer_cn: get_cn(&parsed.issuer()),
        is_ca: parsed.is_ca(),
        validity_days,
        serial_number_len: parsed.serial.to_bytes_be().len(),
        cert_pem_has_header: cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"),
        cert_pem_has_footer: cert.cert_pem().contains("-----END CERTIFICATE-----"),
        private_key_pem_has_header: cert
            .private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----"),
        private_key_pem_has_footer: cert
            .private_key_pkcs8_pem()
            .contains("-----END PRIVATE KEY-----"),
        cert_der_len: cert.cert_der().len(),
        key_usage_digital_signature: ds,
        key_usage_key_encipherment: ke,
        key_usage_key_cert_sign: kcs,
        key_usage_crl_sign: cs,
        has_eku,
        eku_server_auth: sa,
        eku_client_auth: ca,
    };

    insta::assert_yaml_snapshot!("self_signed_ca", result, {
        ".cert_der_len" => "[REDACTED]",
        ".serial_number_len" => "[REDACTED]",
    });
}

// =========================================================================
// Negative cert snapshots
// =========================================================================

#[test]
fn snapshot_negative_expired() {
    let fx = fx();
    let spec = X509Spec::self_signed("neg-expired.example.com");
    let good = fx.x509_self_signed("neg-expired", spec);
    let expired = good.expired();

    let (_, parsed) = X509Certificate::from_der(expired.cert_der()).expect("parse cert");
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    let result = NegativeCertSnapshot {
        variant: "expired".to_string(),
        subject_cn: get_cn(&parsed.subject()),
        is_ca: parsed.is_ca(),
        validity_days,
        differs_from_good: good.cert_der() != expired.cert_der(),
    };

    insta::assert_yaml_snapshot!("negative_expired", result);
}

#[test]
fn snapshot_negative_not_yet_valid() {
    let fx = fx();
    let spec = X509Spec::self_signed("neg-nyv.example.com");
    let good = fx.x509_self_signed("neg-nyv", spec);
    let nyv = good.not_yet_valid();

    let (_, parsed) = X509Certificate::from_der(nyv.cert_der()).expect("parse cert");
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    let result = NegativeCertSnapshot {
        variant: "not_yet_valid".to_string(),
        subject_cn: get_cn(&parsed.subject()),
        is_ca: parsed.is_ca(),
        validity_days,
        differs_from_good: good.cert_der() != nyv.cert_der(),
    };

    insta::assert_yaml_snapshot!("negative_not_yet_valid", result);
}

#[test]
fn snapshot_negative_wrong_key_usage() {
    let fx = fx();
    let spec = X509Spec::self_signed("neg-wku.example.com");
    let good = fx.x509_self_signed("neg-wku", spec);
    let wku = good.wrong_key_usage();

    let (_, parsed) = X509Certificate::from_der(wku.cert_der()).expect("parse cert");
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    let result = NegativeCertSnapshot {
        variant: "wrong_key_usage".to_string(),
        subject_cn: get_cn(&parsed.subject()),
        is_ca: parsed.is_ca(),
        validity_days,
        differs_from_good: good.cert_der() != wku.cert_der(),
    };

    insta::assert_yaml_snapshot!("negative_wrong_key_usage", result);
}

// =========================================================================
// Corrupt PEM snapshot
// =========================================================================

#[test]
fn snapshot_corrupt_cert_pem() {
    use uselesskey_core::negative::CorruptPem;

    let fx = fx();
    let spec = X509Spec::self_signed("corrupt.example.com");
    let cert = fx.x509_self_signed("corrupt", spec);

    let bad_header = cert.corrupt_cert_pem(CorruptPem::BadHeader);

    let result = CorruptPemSnapshot {
        variant: "BadHeader".to_string(),
        contains_begin_certificate: bad_header.contains("-----BEGIN CERTIFICATE-----"),
        contains_begin_corrupted: bad_header.contains("-----BEGIN CORRUPTED KEY-----"),
    };

    insta::assert_yaml_snapshot!("corrupt_pem_bad_header", result);
}

// =========================================================================
// Chain snapshots
// =========================================================================

#[test]
fn snapshot_chain_three_level() {
    let fx = fx();
    let spec = ChainSpec::new("chain-snapshot.example.com");
    let chain = fx.x509_chain("snapshot-chain", spec);

    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    let issuer_chain_valid = int.issuer() == root.subject() && leaf.issuer() == int.subject();

    let result = ChainSnapshot {
        label: chain.label().to_string(),
        root_cn: get_cn(&root.subject()),
        root_is_ca: root.is_ca(),
        intermediate_cn: get_cn(&int.subject()),
        intermediate_is_ca: int.is_ca(),
        leaf_cn: get_cn(&leaf.subject()),
        leaf_is_ca: leaf.is_ca(),
        chain_pem_cert_count: chain
            .chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count(),
        full_chain_pem_cert_count: chain
            .full_chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count(),
        root_serial_len: root.serial.to_bytes_be().len(),
        intermediate_serial_len: int.serial.to_bytes_be().len(),
        leaf_serial_len: leaf.serial.to_bytes_be().len(),
        issuer_chain_valid,
    };

    insta::assert_yaml_snapshot!("chain_three_level", result, {
        ".root_serial_len" => "[REDACTED]",
        ".intermediate_serial_len" => "[REDACTED]",
        ".leaf_serial_len" => "[REDACTED]",
    });
}

// =========================================================================
// Chain negative snapshots
// =========================================================================

#[test]
fn snapshot_chain_hostname_mismatch() {
    let fx = fx();
    let spec = ChainSpec::new("chain-neg.example.com");
    let good = fx.x509_chain("chain-neg", spec);
    let mismatched = good.hostname_mismatch("wrong.example.com");

    let (_, leaf) = X509Certificate::from_der(mismatched.leaf_cert_der()).expect("parse leaf");
    let (_, root) = X509Certificate::from_der(mismatched.root_cert_der()).expect("parse root");

    let result = ChainNegativeSnapshot {
        variant: "hostname_mismatch".to_string(),
        leaf_cn: get_cn(&leaf.subject()),
        root_cn: get_cn(&root.subject()),
        leaf_differs_from_good: good.leaf_cert_der() != mismatched.leaf_cert_der(),
        has_crl: mismatched.crl_der().is_some(),
    };

    insta::assert_yaml_snapshot!("chain_hostname_mismatch", result);
}

#[test]
fn snapshot_chain_revoked_leaf() {
    let fx = fx();
    let spec = ChainSpec::new("chain-revoked.example.com");
    let good = fx.x509_chain("chain-revoked", spec);
    let revoked = good.revoked_leaf();

    let (_, leaf) = X509Certificate::from_der(revoked.leaf_cert_der()).expect("parse leaf");
    let (_, root) = X509Certificate::from_der(revoked.root_cert_der()).expect("parse root");

    let result = ChainNegativeSnapshot {
        variant: "revoked_leaf".to_string(),
        leaf_cn: get_cn(&leaf.subject()),
        root_cn: get_cn(&root.subject()),
        leaf_differs_from_good: good.leaf_cert_der() != revoked.leaf_cert_der(),
        has_crl: revoked.crl_der().is_some(),
    };

    insta::assert_yaml_snapshot!("chain_revoked_leaf", result);
}

#[test]
fn snapshot_chain_unknown_ca() {
    let fx = fx();
    let spec = ChainSpec::new("chain-uca.example.com");
    let good = fx.x509_chain("chain-uca", spec);
    let unknown = good.unknown_ca();

    let (_, leaf) = X509Certificate::from_der(unknown.leaf_cert_der()).expect("parse leaf");
    let (_, root) = X509Certificate::from_der(unknown.root_cert_der()).expect("parse root");

    let result = ChainNegativeSnapshot {
        variant: "unknown_ca".to_string(),
        leaf_cn: get_cn(&leaf.subject()),
        root_cn: get_cn(&root.subject()),
        leaf_differs_from_good: good.leaf_cert_der() != unknown.leaf_cert_der(),
        has_crl: unknown.crl_der().is_some(),
    };

    insta::assert_yaml_snapshot!("chain_unknown_ca", result);
}

// =========================================================================
// Identity PEM snapshot
// =========================================================================

#[test]
fn snapshot_identity_pem_shape() {
    let fx = fx();
    let spec = X509Spec::self_signed("identity.example.com");
    let cert = fx.x509_self_signed("identity", spec);
    let identity = cert.identity_pem();

    #[derive(Serialize)]
    struct IdentityPemSnapshot {
        contains_cert: bool,
        contains_key: bool,
        section_count: usize,
    }

    let result = IdentityPemSnapshot {
        contains_cert: identity.contains("-----BEGIN CERTIFICATE-----"),
        contains_key: identity.contains("-----BEGIN PRIVATE KEY-----"),
        section_count: identity.matches("-----BEGIN ").count(),
    };

    insta::assert_yaml_snapshot!("identity_pem_shape", result);
}
