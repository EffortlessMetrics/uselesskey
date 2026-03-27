//! Comprehensive X.509 integration tests.
//!
//! Covers:
//! - Certificate field validation (subject, issuer, validity, extensions)
//! - PEM/DER encoding round-trips
//! - Certificate chain issuer/subject validation
//! - Chain CA flag and BasicConstraints checks
//! - Negative fixtures: expired, not-yet-valid, wrong key usage, corrupted
//! - Determinism across cache clears
//! - Tempfile content consistency
//! - Serial number uniqueness across chain members
//! - CRL parsing and serial matching for revoked-leaf

mod testutil;

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Negative, X509Spec};
use x509_parser::prelude::*;

fn det(seed_str: &str) -> Factory {
    Factory::deterministic(Seed::from_env_value(seed_str).unwrap())
}

// =========================================================================
// Self-signed: PEM/DER round-trip
// =========================================================================

#[test]
fn pem_contains_single_certificate_block() {
    let fx = fx();
    let cert = fx.x509_self_signed("pem-rt", X509Spec::self_signed("pem-rt.example.com"));
    let pem = cert.cert_pem();

    assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 1);
    assert_eq!(pem.matches("-----END CERTIFICATE-----").count(), 1);
}

#[test]
fn pem_key_contains_single_private_key_block() {
    let fx = fx();
    let cert = fx.x509_self_signed("key-rt", X509Spec::self_signed("key-rt.example.com"));
    let pem = cert.private_key_pkcs8_pem();

    assert_eq!(pem.matches("-----BEGIN PRIVATE KEY-----").count(), 1);
    assert_eq!(pem.matches("-----END PRIVATE KEY-----").count(), 1);
}

#[test]
fn der_round_trips_through_x509_parser() {
    let fx = fx();
    let cert = fx.x509_self_signed("der-rt", X509Spec::self_signed("der-rt.example.com"));
    let der = cert.cert_der();

    let (remaining, parsed) = X509Certificate::from_der(der).expect("valid DER");
    assert!(remaining.is_empty(), "should consume all bytes");
    assert_eq!(parsed.version(), X509Version::V3);
}

#[test]
fn pem_base64_decodes_to_same_der() {
    let fx = fx();
    let cert = fx.x509_self_signed("b64-rt", X509Spec::self_signed("b64-rt.example.com"));

    let pem = cert.cert_pem();
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body)
        .expect("valid base64");

    assert_eq!(decoded, cert.cert_der());
}

// =========================================================================
// Self-signed: certificate field validation
// =========================================================================

#[test]
fn self_signed_subject_matches_issuer() {
    let fx = fx();
    let cert = fx.x509_self_signed(
        "self-sign-check",
        X509Spec::self_signed("selfsign.example.com"),
    );
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    assert_eq!(parsed.subject(), parsed.issuer());
}

#[test]
fn self_signed_subject_cn_matches_spec() {
    let fx = fx();
    let cert = fx.x509_self_signed("cn-check", X509Spec::self_signed("myapp.example.com"));
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .expect("CN present");
    assert_eq!(cn.as_str().unwrap(), "myapp.example.com");
}

#[test]
fn self_signed_has_v3_version() {
    let fx = fx();
    let cert = fx.x509_self_signed("v3-check", X509Spec::self_signed("v3.example.com"));
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    assert_eq!(parsed.version(), X509Version::V3);
}

#[test]
fn self_signed_serial_is_positive_and_16_bytes() {
    let fx = fx();
    let cert = fx.x509_self_signed("serial-sz", X509Spec::self_signed("serial.example.com"));
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    let serial_bytes = parsed.serial.to_bytes_be();
    assert_eq!(serial_bytes.len(), 16, "serial should be 16 bytes");
    assert_eq!(serial_bytes[0] & 0x80, 0, "serial high bit must be cleared");
}

#[test]
fn self_signed_validity_matches_spec() {
    let fx = fx();
    let spec = X509Spec::self_signed("validity-check.example.com").with_validity_days(90);
    let cert = fx.x509_self_signed("validity-check", spec);
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    let nb = parsed.validity().not_before.timestamp();
    let na = parsed.validity().not_after.timestamp();
    let days = (na - nb) / 86400;
    assert_eq!(days, 90);
}

#[test]
fn self_signed_with_sans_appear_in_parsed_cert() {
    let fx = fx();
    let spec = X509Spec::self_signed("san-check.example.com").with_sans(vec![
        "san-check.example.com".to_string(),
        "api.example.com".to_string(),
        "www.example.com".to_string(),
    ]);
    let cert = fx.x509_self_signed("san-check", spec);
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    let san_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .expect("SAN extension present");

    let san = match san_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => san,
        other => panic!("expected SAN, got {:?}", other),
    };

    let dns_names: HashSet<String> = san
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
            _ => None,
        })
        .collect();

    assert!(dns_names.contains("san-check.example.com"));
    assert!(dns_names.contains("api.example.com"));
    assert!(dns_names.contains("www.example.com"));
    assert_eq!(dns_names.len(), 3);
}

#[test]
fn self_signed_leaf_has_basic_constraints_no_ca() {
    let fx = fx();
    let cert = fx.x509_self_signed("bc-leaf", X509Spec::self_signed("bc-leaf.example.com"));
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    assert!(!parsed.is_ca());
}

#[test]
fn self_signed_ca_has_basic_constraints_ca() {
    let fx = fx();
    let cert = fx.x509_self_signed("bc-ca", X509Spec::self_signed_ca("bc-ca.example.com"));
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    assert!(parsed.is_ca());
}

#[test]
fn leaf_eku_includes_server_and_client_auth() {
    let fx = fx();
    let cert = fx.x509_self_signed("eku-both", X509Spec::self_signed("eku.example.com"));
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    let eku_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE)
        .expect("EKU extension");

    let eku = match eku_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => eku,
        other => panic!("expected EKU, got {:?}", other),
    };

    assert!(eku.server_auth);
    assert!(eku.client_auth);
}

#[test]
fn ca_cert_has_no_eku() {
    let fx = fx();
    let cert = fx.x509_self_signed("ca-no-eku", X509Spec::self_signed_ca("ca.example.com"));
    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse");

    let eku = parsed
        .extensions()
        .iter()
        .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE);
    assert!(eku.is_none(), "CA cert should not have EKU");
}

// =========================================================================
// Certificate chain: issuer/subject chain validation
// =========================================================================

#[test]
fn chain_issuer_subject_relationship_validated() {
    let fx = fx();
    let chain = fx.x509_chain("iss-subj", ChainSpec::new("chain-val.example.com"));

    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    // Root is self-signed
    assert_eq!(root.subject(), root.issuer(), "root should be self-signed");

    // Intermediate issued by root
    assert_eq!(
        int.issuer(),
        root.subject(),
        "intermediate issuer = root subject"
    );

    // Leaf issued by intermediate
    assert_eq!(
        leaf.issuer(),
        int.subject(),
        "leaf issuer = intermediate subject"
    );
}

#[test]
fn chain_root_has_path_len_constraint() {
    let fx = fx();
    let chain = fx.x509_chain("pathlen", ChainSpec::new("pathlen.example.com"));
    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");

    assert!(root.is_ca());
    let bc = root
        .basic_constraints()
        .expect("bc extension")
        .expect("bc present");
    assert!(bc.value.ca);
}

#[test]
fn chain_intermediate_is_ca() {
    let fx = fx();
    let chain = fx.x509_chain("int-ca", ChainSpec::new("int-ca.example.com"));
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");

    assert!(int.is_ca());
}

#[test]
fn chain_leaf_is_not_ca() {
    let fx = fx();
    let chain = fx.x509_chain("leaf-noca", ChainSpec::new("leaf-noca.example.com"));
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    assert!(!leaf.is_ca());
}

#[test]
fn chain_serials_are_unique() {
    let fx = fx();
    let chain = fx.x509_chain("unique-serial", ChainSpec::new("serial.example.com"));

    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    let serials: HashSet<Vec<u8>> = [
        root.serial.to_bytes_be(),
        int.serial.to_bytes_be(),
        leaf.serial.to_bytes_be(),
    ]
    .into_iter()
    .collect();

    assert_eq!(
        serials.len(),
        3,
        "all three chain certs should have unique serial numbers"
    );
}

#[test]
fn chain_serials_are_pinned_for_regression_seed() {
    let fx = det("serial-probe");
    let chain = fx.x509_chain("serial-probe", ChainSpec::new("serial-probe.example.com"));

    let parsed = [
        (
            "root",
            X509Certificate::from_der(chain.root_cert_der())
                .expect("parse root")
                .1,
            "50:42:01:f5:84:e1:68:4a:eb:63:a8:61:e0:a4:83:3f",
        ),
        (
            "intermediate",
            X509Certificate::from_der(chain.intermediate_cert_der())
                .expect("parse intermediate")
                .1,
            "31:1d:3e:70:e5:4d:92:56:b4:d9:65:dc:06:ae:b1:b3",
        ),
        (
            "leaf",
            X509Certificate::from_der(chain.leaf_cert_der())
                .expect("parse leaf")
                .1,
            "53:04:fe:8a:aa:3f:6f:35:eb:67:17:1b:c7:72:ee:9c",
        ),
    ];

    for (role, cert, expected_serial) in parsed {
        assert_eq!(
            cert.raw_serial().len(),
            16,
            "{role} serial should stay 16 bytes"
        );
        assert_eq!(
            cert.raw_serial_as_string(),
            expected_serial,
            "{role} serial should remain pinned for deterministic derivation"
        );
    }
}

#[test]
fn chain_root_key_usage_includes_cert_sign_and_crl_sign() {
    let fx = fx();
    let chain = fx.x509_chain("root-ku", ChainSpec::new("root-ku.example.com"));
    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");

    let ku_ext = root
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .expect("root KeyUsage");

    let ku = match ku_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
        other => panic!("expected KeyUsage, got {:?}", other),
    };

    assert!(ku.key_cert_sign(), "root must have KeyCertSign");
    assert!(ku.crl_sign(), "root must have CrlSign");
}

#[test]
fn chain_leaf_key_usage_has_signature_and_encipherment() {
    let fx = fx();
    let chain = fx.x509_chain("leaf-ku", ChainSpec::new("leaf-ku.example.com"));
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    let ku_ext = leaf
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .expect("leaf KeyUsage");

    let ku = match ku_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
        other => panic!("expected KeyUsage, got {:?}", other),
    };

    assert!(ku.digital_signature());
    assert!(ku.key_encipherment());
    assert!(!ku.key_cert_sign(), "leaf must NOT have KeyCertSign");
}

#[test]
fn chain_leaf_has_san_from_spec() {
    let fx = fx();
    let spec = ChainSpec::new("san-chain.example.com").with_sans(vec![
        "san-chain.example.com".to_string(),
        "api.san-chain.example.com".to_string(),
    ]);
    let chain = fx.x509_chain("san-chain", spec);
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    let san_ext = leaf
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .expect("SAN extension");

    let san = match san_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => san,
        other => panic!("expected SAN, got {:?}", other),
    };

    let dns_names: HashSet<String> = san
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
            _ => None,
        })
        .collect();

    assert!(dns_names.contains("san-chain.example.com"));
    assert!(dns_names.contains("api.san-chain.example.com"));
}

#[test]
fn chain_cn_fields_match_spec() {
    let fx = fx();
    let spec = ChainSpec::new("cn-match.example.com")
        .with_root_cn("My Root CA")
        .with_intermediate_cn("My Int CA");
    let chain = fx.x509_chain("cn-match", spec);

    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    let root_cn = root
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    let int_cn = int
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    let leaf_cn = leaf
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();

    assert_eq!(root_cn, "My Root CA");
    assert_eq!(int_cn, "My Int CA");
    assert_eq!(leaf_cn, "cn-match.example.com");
}

// =========================================================================
// Chain: PEM/DER round-trips
// =========================================================================

#[test]
fn chain_all_three_certs_parse_as_valid_der() {
    let fx = fx();
    let chain = fx.x509_chain("parse-all", ChainSpec::new("parse-all.example.com"));

    X509Certificate::from_der(chain.root_cert_der()).expect("root DER valid");
    X509Certificate::from_der(chain.intermediate_cert_der()).expect("int DER valid");
    X509Certificate::from_der(chain.leaf_cert_der()).expect("leaf DER valid");
}

#[test]
fn chain_pem_has_two_certs_full_chain_has_three() {
    let fx = fx();
    let chain = fx.x509_chain("pem-count", ChainSpec::new("pem-count.example.com"));

    assert_eq!(
        chain
            .chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count(),
        2
    );
    assert_eq!(
        chain
            .full_chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count(),
        3
    );
}

#[test]
fn chain_private_keys_all_non_empty_and_valid_pem() {
    let fx = fx();
    let chain = fx.x509_chain("keys-check", ChainSpec::new("keys.example.com"));

    for (name, der, pem) in [
        (
            "root",
            chain.root_private_key_pkcs8_der(),
            chain.root_private_key_pkcs8_pem(),
        ),
        (
            "intermediate",
            chain.intermediate_private_key_pkcs8_der(),
            chain.intermediate_private_key_pkcs8_pem(),
        ),
        (
            "leaf",
            chain.leaf_private_key_pkcs8_der(),
            chain.leaf_private_key_pkcs8_pem(),
        ),
    ] {
        assert!(!der.is_empty(), "{name} key DER should be non-empty");
        assert!(
            pem.contains("-----BEGIN PRIVATE KEY-----"),
            "{name} key PEM should have header"
        );
        assert!(
            pem.contains("-----END PRIVATE KEY-----"),
            "{name} key PEM should have footer"
        );
    }
}

// =========================================================================
// Chain: validity periods
// =========================================================================

#[test]
fn chain_validity_periods_are_ordered() {
    let fx = fx();
    let chain = fx.x509_chain("validity-ord", ChainSpec::new("validity-ord.example.com"));

    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
    let (_, int) =
        X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

    // Each cert's not_after should be after not_before
    for (name, cert) in [("root", &root), ("int", &int), ("leaf", &leaf)] {
        let nb = cert.validity().not_before.timestamp();
        let na = cert.validity().not_after.timestamp();
        assert!(
            na > nb,
            "{name} not_after ({na}) must be after not_before ({nb})"
        );
    }
}

#[test]
fn chain_root_has_longest_validity() {
    let fx = fx();
    let chain = fx.x509_chain(
        "long-root",
        ChainSpec::new("long-root.example.com")
            .with_root_validity_days(7300)
            .with_intermediate_validity_days(1825)
            .with_leaf_validity_days(365),
    );

    let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("root");
    let (_, int) = X509Certificate::from_der(chain.intermediate_cert_der()).expect("int");
    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("leaf");

    let root_days =
        (root.validity().not_after.timestamp() - root.validity().not_before.timestamp()) / 86400;
    let int_days =
        (int.validity().not_after.timestamp() - int.validity().not_before.timestamp()) / 86400;
    let leaf_days =
        (leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp()) / 86400;

    assert_eq!(root_days, 7300);
    assert_eq!(int_days, 1825);
    assert_eq!(leaf_days, 365);
}

// =========================================================================
// Negative fixtures: expired self-signed cert
// =========================================================================

#[test]
fn expired_cert_not_after_before_now() {
    let fx = fx();
    let cert = fx.x509_self_signed("exp-full", X509Spec::self_signed("exp-full.example.com"));
    let expired = cert.expired();

    let (_, parsed) = X509Certificate::from_der(expired.cert_der()).expect("parse");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let not_after = parsed.validity().not_after.timestamp();

    assert!(
        not_after < now,
        "expired cert not_after should be in the past"
    );
}

#[test]
fn expired_cert_preserves_cn() {
    let fx = fx();
    let cert = fx.x509_self_signed("exp-cn", X509Spec::self_signed("exp-cn.example.com"));
    let expired = cert.expired();

    let (_, parsed) = X509Certificate::from_der(expired.cert_der()).expect("parse");
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(cn, "exp-cn.example.com");
}

// =========================================================================
// Negative fixtures: not-yet-valid self-signed cert
// =========================================================================

#[test]
fn not_yet_valid_cert_not_before_after_base_good_cert() {
    let fx = fx();
    let cert = fx.x509_self_signed("nyv-cmp", X509Spec::self_signed("nyv-cmp.example.com"));
    let nyv = cert.not_yet_valid();

    let (_, good) = X509Certificate::from_der(cert.cert_der()).expect("parse good");
    let (_, bad) = X509Certificate::from_der(nyv.cert_der()).expect("parse nyv");

    assert!(
        bad.validity().not_before.timestamp() > good.validity().not_before.timestamp(),
        "not-yet-valid should have later not_before"
    );
}

// =========================================================================
// Negative fixtures: wrong key usage
// =========================================================================

#[test]
fn wrong_key_usage_is_ca_without_cert_sign() {
    let fx = fx();
    let cert = fx.x509_self_signed("wku-int", X509Spec::self_signed("wku-int.example.com"));
    let bad = cert.wrong_key_usage();

    let (_, parsed) = X509Certificate::from_der(bad.cert_der()).expect("parse");
    assert!(parsed.is_ca());

    let ku_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .expect("KU extension");

    let ku = match ku_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
        other => panic!("expected KeyUsage, got {:?}", other),
    };

    assert!(!ku.key_cert_sign(), "wrong KU should NOT have KeyCertSign");
    assert!(!ku.crl_sign(), "wrong KU should NOT have CrlSign");
}

// =========================================================================
// Negative fixtures: chain expired leaf via DER validation
// =========================================================================

#[test]
fn chain_expired_leaf_not_after_in_past() {
    let fx = fx();
    let chain = fx.x509_chain("exp-leaf-v", ChainSpec::new("exp-leaf-v.example.com"));
    let expired = chain.expired_leaf();

    let (_, leaf) = X509Certificate::from_der(expired.leaf_cert_der()).expect("parse");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        leaf.validity().not_after.timestamp() < now,
        "expired leaf not_after should be before now"
    );
}

#[test]
fn chain_expired_leaf_root_still_valid() {
    let fx = fx();
    let chain = fx.x509_chain("exp-leaf-rv", ChainSpec::new("exp-leaf-rv.example.com"));
    let expired = chain.expired_leaf();

    let (_, root) = X509Certificate::from_der(expired.root_cert_der()).expect("parse root");
    let nb = root.validity().not_before.timestamp();
    let na = root.validity().not_after.timestamp();
    let days = (na - nb) / 86400;
    assert!(days >= 3000, "root should have long validity ({days} days)");
}

// =========================================================================
// Negative fixtures: chain expired intermediate
// =========================================================================

#[test]
fn chain_expired_intermediate_not_after_in_past() {
    let fx = fx();
    let chain = fx.x509_chain("exp-int-v", ChainSpec::new("exp-int-v.example.com"));
    let expired = chain.expired_intermediate();

    let (_, int) =
        X509Certificate::from_der(expired.intermediate_cert_der()).expect("parse intermediate");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        int.validity().not_after.timestamp() < now,
        "expired intermediate not_after should be before now"
    );
}

#[test]
fn chain_not_yet_valid_leaf_not_before_in_future() {
    let fx = fx();
    let chain = fx.x509_chain("nyv-leaf-v", ChainSpec::new("nyv-leaf-v.example.com"));
    let future = chain.not_yet_valid_leaf();

    let (_, leaf) = X509Certificate::from_der(future.leaf_cert_der()).expect("parse leaf");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        leaf.validity().not_before.timestamp() > now,
        "not-yet-valid leaf not_before should be after now"
    );
}

#[test]
fn chain_not_yet_valid_intermediate_not_before_in_future() {
    let fx = fx();
    let chain = fx.x509_chain("nyv-int-v", ChainSpec::new("nyv-int-v.example.com"));
    let future = chain.not_yet_valid_intermediate();

    let (_, int) =
        X509Certificate::from_der(future.intermediate_cert_der()).expect("parse intermediate");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        int.validity().not_before.timestamp() > now,
        "not-yet-valid intermediate not_before should be after now"
    );
}

#[test]
fn chain_intermediate_not_ca_clears_ca_flag() {
    let fx = fx();
    let chain = fx.x509_chain("int-not-ca", ChainSpec::new("int-not-ca.example.com"));
    let bad = chain.intermediate_not_ca();

    let (_, int) =
        X509Certificate::from_der(bad.intermediate_cert_der()).expect("parse intermediate");
    assert!(!int.is_ca(), "intermediate_not_ca should clear the CA flag");
}

#[test]
fn chain_intermediate_wrong_key_usage_keeps_ca_but_drops_cert_sign() {
    let fx = fx();
    let chain = fx.x509_chain("int-wku", ChainSpec::new("int-wku.example.com"));
    let bad = chain.intermediate_wrong_key_usage();

    let (_, int) =
        X509Certificate::from_der(bad.intermediate_cert_der()).expect("parse intermediate");
    assert!(
        int.is_ca(),
        "wrong-key-usage intermediate should still claim CA"
    );

    let ku_ext = int
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .expect("intermediate KeyUsage");

    let ku = match ku_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
        other => panic!("expected KeyUsage, got {:?}", other),
    };

    assert!(
        !ku.key_cert_sign(),
        "intermediate_wrong_key_usage must omit keyCertSign"
    );
}

#[test]
fn new_chain_negative_variants_preserve_key_material() {
    let fx = fx();
    let chain = fx.x509_chain(
        "chain-neg-keys",
        ChainSpec::new("chain-neg-keys.example.com"),
    );

    let variants: Vec<(&str, uselesskey_x509::X509Chain)> = vec![
        ("not_yet_valid_leaf", chain.not_yet_valid_leaf()),
        (
            "not_yet_valid_intermediate",
            chain.not_yet_valid_intermediate(),
        ),
        ("intermediate_not_ca", chain.intermediate_not_ca()),
        (
            "intermediate_wrong_key_usage",
            chain.intermediate_wrong_key_usage(),
        ),
    ];

    for (name, bad) in &variants {
        assert_eq!(
            bad.root_private_key_pkcs8_der(),
            chain.root_private_key_pkcs8_der(),
            "{name} should preserve the root key"
        );
        assert_eq!(
            bad.intermediate_private_key_pkcs8_der(),
            chain.intermediate_private_key_pkcs8_der(),
            "{name} should preserve the intermediate key"
        );
        assert_eq!(
            bad.leaf_private_key_pkcs8_der(),
            chain.leaf_private_key_pkcs8_der(),
            "{name} should preserve the leaf key"
        );

        if *name == "not_yet_valid_leaf" {
            assert_ne!(
                bad.leaf_cert_der(),
                chain.leaf_cert_der(),
                "{name} should change the leaf certificate"
            );
        } else {
            assert_ne!(
                bad.intermediate_cert_der(),
                chain.intermediate_cert_der(),
                "{name} should change the intermediate certificate"
            );
        }
    }
}

// =========================================================================
// Negative fixtures: chain hostname mismatch
// =========================================================================

#[test]
fn chain_hostname_mismatch_leaf_cn_changed() {
    let fx = fx();
    let chain = fx.x509_chain("hm-val", ChainSpec::new("good-host.example.com"));
    let bad = chain.hostname_mismatch("evil-host.example.com");

    let (_, leaf) = X509Certificate::from_der(bad.leaf_cert_der()).expect("parse");
    let cn = leaf
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(cn, "evil-host.example.com");
}

#[test]
fn chain_hostname_mismatch_root_unchanged() {
    let fx = fx();
    let chain = fx.x509_chain("hm-root", ChainSpec::new("good.example.com"));
    let good_root_cn = {
        let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse");
        root.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    };

    let bad = chain.hostname_mismatch("evil.example.com");
    let (_, bad_root) = X509Certificate::from_der(bad.root_cert_der()).expect("parse");
    let bad_root_cn = bad_root
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap();

    assert_eq!(good_root_cn, bad_root_cn);
}

// =========================================================================
// Negative fixtures: chain unknown CA
// =========================================================================

#[test]
fn chain_unknown_ca_root_subject_differs() {
    let fx = fx();
    let chain = fx.x509_chain("uca-val", ChainSpec::new("uca-val.example.com"));
    let bad = chain.unknown_ca();

    let (_, good_root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse good");
    let (_, bad_root) = X509Certificate::from_der(bad.root_cert_der()).expect("parse bad");

    assert_ne!(good_root.subject(), bad_root.subject());
}

#[test]
fn chain_unknown_ca_intermediate_issuer_matches_bad_root() {
    let fx = fx();
    let chain = fx.x509_chain("uca-chain", ChainSpec::new("uca-chain.example.com"));
    let bad = chain.unknown_ca();

    let (_, bad_root) = X509Certificate::from_der(bad.root_cert_der()).expect("parse root");
    let (_, bad_int) =
        X509Certificate::from_der(bad.intermediate_cert_der()).expect("parse intermediate");

    assert_eq!(
        bad_int.issuer(),
        bad_root.subject(),
        "intermediate issuer should match unknown root subject"
    );
}

// =========================================================================
// Negative fixtures: chain revoked leaf with CRL
// =========================================================================

#[test]
fn chain_revoked_leaf_crl_parses_and_contains_leaf_serial() {
    let fx = fx();
    let chain = fx.x509_chain("rev-parse", ChainSpec::new("rev-parse.example.com"));
    let revoked = chain.revoked_leaf();

    let crl_der = revoked.crl_der().expect("CRL present");
    let (_, crl) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der).expect("parse");

    let (_, leaf) = X509Certificate::from_der(revoked.leaf_cert_der()).expect("parse leaf");
    let leaf_serial = leaf.serial.to_bytes_be();

    let revoked_entries: Vec<_> = crl.iter_revoked_certificates().collect();
    assert_eq!(
        revoked_entries.len(),
        1,
        "CRL should have exactly one entry"
    );
    assert_eq!(revoked_entries[0].raw_serial(), leaf_serial);
}

#[test]
fn chain_revoked_leaf_crl_pem_has_correct_markers() {
    let fx = fx();
    let chain = fx.x509_chain("rev-pem", ChainSpec::new("rev-pem.example.com"));
    let revoked = chain.revoked_leaf();

    let pem = revoked.crl_pem().expect("CRL PEM present");
    assert!(pem.contains("-----BEGIN X509 CRL-----"));
    assert!(pem.contains("-----END X509 CRL-----"));
}

#[test]
fn chain_good_has_no_crl() {
    let fx = fx();
    let chain = fx.x509_chain("no-crl", ChainSpec::new("no-crl.example.com"));

    assert!(chain.crl_der().is_none());
    assert!(chain.crl_pem().is_none());
}

// =========================================================================
// Tempfile content consistency
// =========================================================================

#[test]
fn tempfile_der_content_matches_in_memory() {
    let fx = fx();
    let cert = fx.x509_self_signed("tf-der", X509Spec::self_signed("tf-der.example.com"));

    let tmpfile = cert.write_cert_der().unwrap();
    let file_bytes = std::fs::read(tmpfile.path()).unwrap();
    assert_eq!(file_bytes, cert.cert_der());
}

#[test]
fn tempfile_key_pem_matches_in_memory() {
    let fx = fx();
    let cert = fx.x509_self_signed("tf-key", X509Spec::self_signed("tf-key.example.com"));

    let tmpfile = cert.write_private_key_pem().unwrap();
    let file_content = std::fs::read_to_string(tmpfile.path()).unwrap();
    assert_eq!(file_content, cert.private_key_pkcs8_pem());
}

#[test]
fn tempfile_identity_pem_matches_in_memory() {
    let fx = fx();
    let cert = fx.x509_self_signed("tf-ident", X509Spec::self_signed("tf-ident.example.com"));

    let tmpfile = cert.write_identity_pem().unwrap();
    let file_content = std::fs::read_to_string(tmpfile.path()).unwrap();
    assert_eq!(file_content, cert.identity_pem());
}

#[test]
fn chain_tempfile_chain_pem_matches() {
    let fx = fx();
    let chain = fx.x509_chain("tf-chain", ChainSpec::new("tf-chain.example.com"));

    let tmpfile = chain.write_chain_pem().unwrap();
    let file_content = std::fs::read_to_string(tmpfile.path()).unwrap();
    assert_eq!(file_content, chain.chain_pem());
}

#[test]
fn chain_tempfile_full_chain_pem_matches() {
    let fx = fx();
    let chain = fx.x509_chain("tf-full", ChainSpec::new("tf-full.example.com"));

    let tmpfile = chain.write_full_chain_pem().unwrap();
    let file_content = std::fs::read_to_string(tmpfile.path()).unwrap();
    assert_eq!(file_content, chain.full_chain_pem());
}

// =========================================================================
// Determinism: certificates reproduce across cache clears
// =========================================================================

#[test]
fn self_signed_determinism_across_cache_clear() {
    let fx = det("det-ss-seed");
    let spec = X509Spec::self_signed("det-ss.example.com");

    let c1 = fx.x509_self_signed("det-ss", spec.clone());
    let pem1 = c1.cert_pem().to_string();
    let key1 = c1.private_key_pkcs8_pem().to_string();

    fx.clear_cache();
    let c2 = fx.x509_self_signed("det-ss", spec);
    assert_eq!(c2.cert_pem(), pem1);
    assert_eq!(c2.private_key_pkcs8_pem(), key1);
}

#[test]
fn chain_determinism_across_cache_clear() {
    let fx = det("det-chain-seed");
    let spec = ChainSpec::new("det-chain.example.com");

    let ch1 = fx.x509_chain("det-chain", spec.clone());
    let root1 = ch1.root_cert_pem().to_string();
    let int1 = ch1.intermediate_cert_pem().to_string();
    let leaf1 = ch1.leaf_cert_pem().to_string();

    fx.clear_cache();
    let ch2 = fx.x509_chain("det-chain", spec);
    assert_eq!(ch2.root_cert_pem(), root1);
    assert_eq!(ch2.intermediate_cert_pem(), int1);
    assert_eq!(ch2.leaf_cert_pem(), leaf1);
}

#[test]
fn negative_determinism_across_cache_clear() {
    let fx = det("det-neg-seed");
    let spec = X509Spec::self_signed("det-neg.example.com");

    let c1 = fx.x509_self_signed("det-neg", spec.clone());
    let exp1 = c1.expired();
    let exp1_pem = exp1.cert_pem().to_string();

    fx.clear_cache();
    let c2 = fx.x509_self_signed("det-neg", spec);
    let exp2 = c2.expired();
    assert_eq!(exp2.cert_pem(), exp1_pem);
}

// =========================================================================
// Different labels/specs produce different certs
// =========================================================================

#[test]
fn different_labels_produce_different_certs() {
    let fx = fx();
    let spec = X509Spec::self_signed("same-spec.example.com");

    let a = fx.x509_self_signed("label-alpha", spec.clone());
    let b = fx.x509_self_signed("label-beta", spec);
    assert_ne!(a.cert_der(), b.cert_der());
}

#[test]
fn different_specs_produce_different_certs() {
    let fx = fx();
    let spec_a = X509Spec::self_signed("spec-a.example.com");
    let spec_b = X509Spec::self_signed("spec-b.example.com");

    let a = fx.x509_self_signed("same-label", spec_a);
    let b = fx.x509_self_signed("same-label", spec_b);
    assert_ne!(a.cert_der(), b.cert_der());
}

#[test]
fn different_rsa_bits_produce_different_key_sizes() {
    let fx = fx();
    let small = fx.x509_self_signed(
        "small-key",
        X509Spec::self_signed("rsa-size.example.com").with_rsa_bits(2048),
    );
    let large = fx.x509_self_signed(
        "large-key",
        X509Spec::self_signed("rsa-size.example.com").with_rsa_bits(4096),
    );

    assert!(
        large.private_key_pkcs8_der().len() > small.private_key_pkcs8_der().len(),
        "4096-bit key should be larger than 2048-bit key"
    );
}

// =========================================================================
// Metadata accessors
// =========================================================================

#[test]
fn cert_spec_accessor_returns_original_spec() {
    let fx = fx();
    let spec = X509Spec::self_signed("meta.example.com")
        .with_validity_days(42)
        .with_rsa_bits(4096);
    let cert = fx.x509_self_signed("meta-test", spec.clone());

    assert_eq!(cert.spec(), &spec);
}

#[test]
fn cert_label_accessor_returns_original_label() {
    let fx = fx();
    let cert = fx.x509_self_signed("my-label", X509Spec::self_signed("label.example.com"));
    assert_eq!(cert.label(), "my-label");
}

#[test]
fn chain_spec_accessor_returns_original_spec() {
    let fx = fx();
    let spec = ChainSpec::new("chain-meta.example.com").with_rsa_bits(4096);
    let chain = fx.x509_chain("chain-meta", spec.clone());
    assert_eq!(chain.spec(), &spec);
}

#[test]
fn chain_label_accessor_returns_original_label() {
    let fx = fx();
    let chain = fx.x509_chain("chain-lbl", ChainSpec::new("chain-lbl.example.com"));
    assert_eq!(chain.label(), "chain-lbl");
}

// =========================================================================
// Debug: no key material leakage
// =========================================================================

#[test]
fn debug_output_does_not_contain_key_material() {
    let fx = fx();
    let cert = fx.x509_self_signed("debug-noleak", X509Spec::self_signed("noleak.example.com"));

    let dbg = format!("{:?}", cert);
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    assert!(!dbg.contains("BEGIN CERTIFICATE"));
    assert!(dbg.contains("X509Cert"));
}

#[test]
fn chain_debug_output_does_not_contain_key_material() {
    let fx = fx();
    let chain = fx.x509_chain("chain-noleak", ChainSpec::new("chain-noleak.example.com"));

    let dbg = format!("{:?}", chain);
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    assert!(!dbg.contains("BEGIN CERTIFICATE"));
    assert!(dbg.contains("X509Chain"));
}

// =========================================================================
// All X509Negative variants produce parseable certs
// =========================================================================

#[test]
fn all_x509_negative_variants_produce_parseable_certs() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-parse", X509Spec::self_signed("neg-parse.example.com"));

    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    for neg in &variants {
        let bad = cert.negative(*neg);
        let result = X509Certificate::from_der(bad.cert_der());
        assert!(
            result.is_ok(),
            "{:?} should produce a parseable certificate",
            neg
        );
    }
}

// =========================================================================
// All ChainNegative variants produce parseable chain certs
// =========================================================================

#[test]
fn all_chain_negative_variants_produce_parseable_certs() {
    let fx = fx();
    let chain = fx.x509_chain("neg-chain-p", ChainSpec::new("neg-chain-p.example.com"));

    type NegativeVariant<'a> = (&'a str, Box<dyn Fn() -> uselesskey_x509::X509Chain + 'a>);
    let variants: Vec<NegativeVariant<'_>> = vec![
        ("expired_leaf", Box::new(|| chain.expired_leaf())),
        (
            "not_yet_valid_leaf",
            Box::new(|| chain.not_yet_valid_leaf()),
        ),
        (
            "expired_intermediate",
            Box::new(|| chain.expired_intermediate()),
        ),
        (
            "not_yet_valid_intermediate",
            Box::new(|| chain.not_yet_valid_intermediate()),
        ),
        ("unknown_ca", Box::new(|| chain.unknown_ca())),
        (
            "hostname_mismatch",
            Box::new(|| chain.hostname_mismatch("wrong.example.com")),
        ),
        (
            "intermediate_not_ca",
            Box::new(|| chain.intermediate_not_ca()),
        ),
        (
            "intermediate_wrong_key_usage",
            Box::new(|| chain.intermediate_wrong_key_usage()),
        ),
        ("revoked_leaf", Box::new(|| chain.revoked_leaf())),
    ];

    for (name, make_variant) in &variants {
        let bad = make_variant();
        X509Certificate::from_der(bad.root_cert_der())
            .unwrap_or_else(|e| panic!("{name} root DER should parse: {e}"));
        X509Certificate::from_der(bad.intermediate_cert_der())
            .unwrap_or_else(|e| panic!("{name} intermediate DER should parse: {e}"));
        X509Certificate::from_der(bad.leaf_cert_der())
            .unwrap_or_else(|e| panic!("{name} leaf DER should parse: {e}"));
    }
}

// =========================================================================
// Cache: same identity returns same cert
// =========================================================================

#[test]
fn cached_cert_returns_same_der() {
    let fx = fx();
    let spec = X509Spec::self_signed("cache.example.com");

    let c1 = fx.x509_self_signed("cache-id", spec.clone());
    let c2 = fx.x509_self_signed("cache-id", spec);
    assert_eq!(c1.cert_der(), c2.cert_der());
    assert_eq!(c1.private_key_pkcs8_der(), c2.private_key_pkcs8_der());
}

#[test]
fn cached_chain_returns_same_der() {
    let fx = fx();
    let spec = ChainSpec::new("cache-chain.example.com");

    let ch1 = fx.x509_chain("cache-chain", spec.clone());
    let ch2 = fx.x509_chain("cache-chain", spec);
    assert_eq!(ch1.leaf_cert_der(), ch2.leaf_cert_der());
    assert_eq!(ch1.root_cert_der(), ch2.root_cert_der());
}
