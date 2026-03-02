//! PEM/DER Format Validation Tests
//!
//! Validates that all key types produce well-formed PEM and DER output:
//! - PEM headers/footers match expected labels
//! - PEM base64 body decodes cleanly
//! - DER output parses as valid ASN.1
//! - PEM↔DER roundtrip consistency
//! - PKCS#8 vs SPKI format differentiation
//! - X.509 certificate DER validation

mod testutil;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};
use x509_parser::prelude::*;

fn fx() -> Factory {
    testutil::fx()
}

// =========================================================================
// Helper: extract base64 body from PEM
// =========================================================================

/// Extract and decode the base64 body from a PEM string.
/// Returns the decoded bytes if valid, panics otherwise.
fn pem_body_bytes(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    STANDARD
        .decode(&body)
        .unwrap_or_else(|e| panic!("PEM body is not valid base64: {e}\nbody: {body}"))
}

/// Assert a PEM string has correct BEGIN/END labels and valid base64 body.
fn assert_valid_pem(pem: &str, expected_label: &str) {
    let begin = format!("-----BEGIN {expected_label}-----");
    let end = format!("-----END {expected_label}-----");

    assert!(
        pem.contains(&begin),
        "PEM missing header '{begin}'.\nActual PEM start: {}",
        &pem[..pem.len().min(120)]
    );
    assert!(
        pem.contains(&end),
        "PEM missing footer '{end}'.\nActual PEM end: {}",
        &pem[pem.len().saturating_sub(120)..]
    );

    let decoded = pem_body_bytes(pem);
    assert!(!decoded.is_empty(), "PEM body decoded to zero bytes");
}

/// Assert DER bytes start with an ASN.1 SEQUENCE tag (0x30).
fn assert_asn1_sequence(der: &[u8], what: &str) {
    assert!(!der.is_empty(), "{what}: DER is empty");
    assert_eq!(
        der[0], 0x30,
        "{what}: expected ASN.1 SEQUENCE tag (0x30), got 0x{:02x}",
        der[0]
    );
}

/// Decode PEM body and verify it matches the DER bytes.
fn assert_pem_der_roundtrip(pem: &str, der: &[u8], what: &str) {
    let decoded = pem_body_bytes(pem);
    assert_eq!(
        decoded.as_slice(),
        der,
        "{what}: PEM body decoded to different bytes than DER"
    );
}

// =========================================================================
// 1. PEM headers for all key types
// =========================================================================

#[test]
fn rsa_private_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.rsa("pem-hdr-rsa", RsaSpec::rs256());
    assert_valid_pem(kp.private_key_pkcs8_pem(), "PRIVATE KEY");
}

#[test]
fn rsa_public_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.rsa("pem-hdr-rsa-pub", RsaSpec::rs256());
    assert_valid_pem(kp.public_key_spki_pem(), "PUBLIC KEY");
}

#[test]
fn ecdsa_p256_private_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.ecdsa("pem-hdr-ec256", EcdsaSpec::es256());
    assert_valid_pem(kp.private_key_pkcs8_pem(), "PRIVATE KEY");
}

#[test]
fn ecdsa_p256_public_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.ecdsa("pem-hdr-ec256-pub", EcdsaSpec::es256());
    assert_valid_pem(kp.public_key_spki_pem(), "PUBLIC KEY");
}

#[test]
fn ecdsa_p384_private_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.ecdsa("pem-hdr-ec384", EcdsaSpec::es384());
    assert_valid_pem(kp.private_key_pkcs8_pem(), "PRIVATE KEY");
}

#[test]
fn ecdsa_p384_public_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.ecdsa("pem-hdr-ec384-pub", EcdsaSpec::es384());
    assert_valid_pem(kp.public_key_spki_pem(), "PUBLIC KEY");
}

#[test]
fn ed25519_private_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.ed25519("pem-hdr-ed", Ed25519Spec::new());
    assert_valid_pem(kp.private_key_pkcs8_pem(), "PRIVATE KEY");
}

#[test]
fn ed25519_public_key_pem_has_correct_header() {
    let fx = fx();
    let kp = fx.ed25519("pem-hdr-ed-pub", Ed25519Spec::new());
    assert_valid_pem(kp.public_key_spki_pem(), "PUBLIC KEY");
}

#[test]
fn x509_cert_pem_has_correct_header() {
    let fx = fx();
    let cert = fx.x509_self_signed("pem-hdr-x509", X509Spec::self_signed("test.example.com"));
    assert_valid_pem(cert.cert_pem(), "CERTIFICATE");
}

#[test]
fn x509_private_key_pem_has_correct_header() {
    let fx = fx();
    let cert = fx.x509_self_signed(
        "pem-hdr-x509-key",
        X509Spec::self_signed("test.example.com"),
    );
    assert_valid_pem(cert.private_key_pkcs8_pem(), "PRIVATE KEY");
}

// =========================================================================
// 2. PEM base64 body validation
// =========================================================================

#[test]
fn rsa_pem_base64_body_decodes() {
    let fx = fx();
    let kp = fx.rsa("b64-rsa", RsaSpec::rs256());

    let priv_bytes = pem_body_bytes(kp.private_key_pkcs8_pem());
    assert!(priv_bytes.len() > 100, "RSA private key DER too short");

    let pub_bytes = pem_body_bytes(kp.public_key_spki_pem());
    assert!(pub_bytes.len() > 30, "RSA public key DER too short");
}

#[test]
fn ecdsa_pem_base64_body_decodes() {
    let fx = fx();

    for (label, spec) in [
        ("b64-ec256", EcdsaSpec::es256()),
        ("b64-ec384", EcdsaSpec::es384()),
    ] {
        let kp = fx.ecdsa(label, spec);
        let priv_bytes = pem_body_bytes(kp.private_key_pkcs8_pem());
        assert!(
            priv_bytes.len() > 30,
            "{label}: ECDSA private key DER too short"
        );
        let pub_bytes = pem_body_bytes(kp.public_key_spki_pem());
        assert!(
            pub_bytes.len() > 20,
            "{label}: ECDSA public key DER too short"
        );
    }
}

#[test]
fn ed25519_pem_base64_body_decodes() {
    let fx = fx();
    let kp = fx.ed25519("b64-ed", Ed25519Spec::new());
    let priv_bytes = pem_body_bytes(kp.private_key_pkcs8_pem());
    assert!(priv_bytes.len() > 30, "Ed25519 private key DER too short");
    let pub_bytes = pem_body_bytes(kp.public_key_spki_pem());
    assert!(pub_bytes.len() > 10, "Ed25519 public key DER too short");
}

// =========================================================================
// 3. DER output is valid ASN.1
// =========================================================================

#[test]
fn rsa_private_key_der_is_valid_asn1() {
    let fx = fx();
    let kp = fx.rsa("der-rsa", RsaSpec::rs256());
    let der = kp.private_key_pkcs8_der();
    assert_asn1_sequence(der, "RSA PKCS#8 private key");

    // Full ASN.1 parse: PKCS#8 wraps an AlgorithmIdentifier + OctetString
    let (_, parsed) = der_parser::parse_der(der).expect("RSA PKCS#8 DER should parse as ASN.1");
    assert!(
        parsed.as_sequence().is_ok(),
        "RSA PKCS#8 DER top-level is not SEQUENCE"
    );
}

#[test]
fn rsa_public_key_der_is_valid_asn1() {
    let fx = fx();
    let kp = fx.rsa("der-rsa-pub", RsaSpec::rs256());
    let der = kp.public_key_spki_der();
    assert_asn1_sequence(der, "RSA SPKI public key");

    let (_, parsed) = der_parser::parse_der(der).expect("RSA SPKI DER should parse as ASN.1");
    assert!(
        parsed.as_sequence().is_ok(),
        "RSA SPKI DER top-level is not SEQUENCE"
    );
}

#[test]
fn ecdsa_private_key_der_is_valid_asn1() {
    let fx = fx();
    for (label, spec) in [
        ("der-ec256", EcdsaSpec::es256()),
        ("der-ec384", EcdsaSpec::es384()),
    ] {
        let kp = fx.ecdsa(label, spec);
        let der = kp.private_key_pkcs8_der();
        assert_asn1_sequence(der, &format!("{label} PKCS#8 private key"));

        let (_, parsed) = der_parser::parse_der(der)
            .unwrap_or_else(|e| panic!("{label} PKCS#8 DER parse failed: {e}"));
        assert!(
            parsed.as_sequence().is_ok(),
            "{label} PKCS#8 DER is not SEQUENCE"
        );
    }
}

#[test]
fn ecdsa_public_key_der_is_valid_asn1() {
    let fx = fx();
    for (label, spec) in [
        ("der-ec256-pub", EcdsaSpec::es256()),
        ("der-ec384-pub", EcdsaSpec::es384()),
    ] {
        let kp = fx.ecdsa(label, spec);
        let der = kp.public_key_spki_der();
        assert_asn1_sequence(der, &format!("{label} SPKI public key"));

        let (_, parsed) = der_parser::parse_der(der)
            .unwrap_or_else(|e| panic!("{label} SPKI DER parse failed: {e}"));
        assert!(
            parsed.as_sequence().is_ok(),
            "{label} SPKI DER is not SEQUENCE"
        );
    }
}

#[test]
fn ed25519_private_key_der_is_valid_asn1() {
    let fx = fx();
    let kp = fx.ed25519("der-ed", Ed25519Spec::new());
    let der = kp.private_key_pkcs8_der();
    assert_asn1_sequence(der, "Ed25519 PKCS#8 private key");

    let (_, parsed) = der_parser::parse_der(der).expect("Ed25519 PKCS#8 DER should parse as ASN.1");
    assert!(
        parsed.as_sequence().is_ok(),
        "Ed25519 PKCS#8 DER is not SEQUENCE"
    );
}

#[test]
fn ed25519_public_key_der_is_valid_asn1() {
    let fx = fx();
    let kp = fx.ed25519("der-ed-pub", Ed25519Spec::new());
    let der = kp.public_key_spki_der();
    assert_asn1_sequence(der, "Ed25519 SPKI public key");

    let (_, parsed) = der_parser::parse_der(der).expect("Ed25519 SPKI DER should parse as ASN.1");
    assert!(
        parsed.as_sequence().is_ok(),
        "Ed25519 SPKI DER is not SEQUENCE"
    );
}

// =========================================================================
// 4. PEM→DER roundtrip
// =========================================================================

#[test]
fn rsa_pem_der_roundtrip() {
    let fx = fx();
    let kp = fx.rsa("rt-rsa", RsaSpec::rs256());
    assert_pem_der_roundtrip(
        kp.private_key_pkcs8_pem(),
        kp.private_key_pkcs8_der(),
        "RSA PKCS#8",
    );
    assert_pem_der_roundtrip(
        kp.public_key_spki_pem(),
        kp.public_key_spki_der(),
        "RSA SPKI",
    );
}

#[test]
fn ecdsa_pem_der_roundtrip() {
    let fx = fx();
    for (label, spec) in [
        ("rt-ec256", EcdsaSpec::es256()),
        ("rt-ec384", EcdsaSpec::es384()),
    ] {
        let kp = fx.ecdsa(label, spec);
        assert_pem_der_roundtrip(
            kp.private_key_pkcs8_pem(),
            kp.private_key_pkcs8_der(),
            &format!("{label} PKCS#8"),
        );
        assert_pem_der_roundtrip(
            kp.public_key_spki_pem(),
            kp.public_key_spki_der(),
            &format!("{label} SPKI"),
        );
    }
}

#[test]
fn ed25519_pem_der_roundtrip() {
    let fx = fx();
    let kp = fx.ed25519("rt-ed", Ed25519Spec::new());
    assert_pem_der_roundtrip(
        kp.private_key_pkcs8_pem(),
        kp.private_key_pkcs8_der(),
        "Ed25519 PKCS#8",
    );
    assert_pem_der_roundtrip(
        kp.public_key_spki_pem(),
        kp.public_key_spki_der(),
        "Ed25519 SPKI",
    );
}

#[test]
fn x509_cert_pem_der_roundtrip() {
    let fx = fx();
    let cert = fx.x509_self_signed("rt-x509", X509Spec::self_signed("rt.example.com"));
    assert_pem_der_roundtrip(cert.cert_pem(), cert.cert_der(), "X.509 certificate");
}

#[test]
fn x509_private_key_pem_der_roundtrip() {
    let fx = fx();
    let cert = fx.x509_self_signed("rt-x509-key", X509Spec::self_signed("rt.example.com"));
    assert_pem_der_roundtrip(
        cert.private_key_pkcs8_pem(),
        cert.private_key_pkcs8_der(),
        "X.509 PKCS#8 private key",
    );
}

// =========================================================================
// 5. PKCS#8 vs PKCS#1 format differentiation
// =========================================================================

/// PKCS#8 wraps a PrivateKeyInfo SEQUENCE with:
///   version INTEGER, algorithm AlgorithmIdentifier, privateKey OCTET STRING
/// The PEM label is "PRIVATE KEY" (not "RSA PRIVATE KEY").
#[test]
fn rsa_private_key_is_pkcs8_not_pkcs1() {
    let fx = fx();
    let kp = fx.rsa("fmt-rsa-p8", RsaSpec::rs256());
    let pem = kp.private_key_pkcs8_pem();

    // PKCS#8 uses "PRIVATE KEY", PKCS#1 uses "RSA PRIVATE KEY"
    assert!(
        pem.contains("-----BEGIN PRIVATE KEY-----"),
        "Expected PKCS#8 label 'PRIVATE KEY'"
    );
    assert!(
        !pem.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "Got PKCS#1 label 'RSA PRIVATE KEY' instead of PKCS#8"
    );

    // Verify DER structure: PKCS#8 PrivateKeyInfo starts with version INTEGER(0)
    let der = kp.private_key_pkcs8_der();
    let (_, seq) = der_parser::parse_der(der).expect("parse PKCS#8");
    let items = seq.as_sequence().expect("top-level SEQUENCE");
    // First element should be version (INTEGER 0)
    assert!(
        items[0].as_u32().is_ok(),
        "PKCS#8 first field should be version INTEGER"
    );
    assert_eq!(items[0].as_u32().unwrap(), 0, "PKCS#8 version should be 0");
    // Second element should be AlgorithmIdentifier (SEQUENCE)
    assert!(
        items[1].as_sequence().is_ok(),
        "PKCS#8 second field should be AlgorithmIdentifier SEQUENCE"
    );
}

/// ECDSA private keys use PKCS#8 format, not SEC1/raw EC format.
#[test]
fn ecdsa_private_key_is_pkcs8_not_sec1() {
    let fx = fx();
    let kp = fx.ecdsa("fmt-ec-p8", EcdsaSpec::es256());
    let pem = kp.private_key_pkcs8_pem();

    assert!(
        pem.contains("-----BEGIN PRIVATE KEY-----"),
        "Expected PKCS#8 label"
    );
    assert!(
        !pem.contains("-----BEGIN EC PRIVATE KEY-----"),
        "Got SEC1 label instead of PKCS#8"
    );

    let der = kp.private_key_pkcs8_der();
    let (_, seq) = der_parser::parse_der(der).expect("parse PKCS#8");
    let items = seq.as_sequence().expect("top-level SEQUENCE");
    assert_eq!(
        items[0].as_u32().unwrap(),
        0,
        "ECDSA PKCS#8 version should be 0"
    );
}

/// Ed25519 private keys use PKCS#8 format.
#[test]
fn ed25519_private_key_is_pkcs8() {
    let fx = fx();
    let kp = fx.ed25519("fmt-ed-p8", Ed25519Spec::new());
    let pem = kp.private_key_pkcs8_pem();

    assert!(
        pem.contains("-----BEGIN PRIVATE KEY-----"),
        "Expected PKCS#8 label"
    );

    let der = kp.private_key_pkcs8_der();
    let (_, seq) = der_parser::parse_der(der).expect("parse PKCS#8");
    let items = seq.as_sequence().expect("top-level SEQUENCE");
    // Ed25519 uses PKCS#8 v2 (version=1) per RFC 8410
    let version = items[0].as_u32().unwrap();
    assert!(
        version == 0 || version == 1,
        "Ed25519 PKCS#8 version should be 0 or 1, got {version}"
    );
}

// =========================================================================
// 6. SPKI public key format validation
// =========================================================================

/// SPKI SubjectPublicKeyInfo has: algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING
#[test]
fn rsa_public_key_is_spki_format() {
    let fx = fx();
    let kp = fx.rsa("spki-rsa", RsaSpec::rs256());
    let pem = kp.public_key_spki_pem();

    assert!(
        pem.contains("-----BEGIN PUBLIC KEY-----"),
        "Expected SPKI label 'PUBLIC KEY'"
    );
    assert!(
        !pem.contains("-----BEGIN RSA PUBLIC KEY-----"),
        "Got PKCS#1 public key label instead of SPKI"
    );

    let der = kp.public_key_spki_der();
    let (_, seq) = der_parser::parse_der(der).expect("parse SPKI");
    let items = seq.as_sequence().expect("SPKI top-level SEQUENCE");
    assert!(
        items.len() >= 2,
        "SPKI should have at least 2 elements (algorithm + key)"
    );
    // AlgorithmIdentifier
    assert!(
        items[0].as_sequence().is_ok(),
        "SPKI first field should be AlgorithmIdentifier SEQUENCE"
    );
    // SubjectPublicKey is a BIT STRING
    assert!(
        items[1].as_bitstring().is_ok(),
        "SPKI second field should be BIT STRING"
    );
}

#[test]
fn ecdsa_public_key_is_spki_format() {
    let fx = fx();
    for (label, spec) in [
        ("spki-ec256", EcdsaSpec::es256()),
        ("spki-ec384", EcdsaSpec::es384()),
    ] {
        let kp = fx.ecdsa(label, spec);

        assert!(
            kp.public_key_spki_pem()
                .contains("-----BEGIN PUBLIC KEY-----"),
            "{label}: Expected SPKI label"
        );

        let der = kp.public_key_spki_der();
        let (_, seq) =
            der_parser::parse_der(der).unwrap_or_else(|e| panic!("{label} SPKI parse: {e}"));
        let items = seq
            .as_sequence()
            .unwrap_or_else(|e| panic!("{label} SPKI SEQUENCE: {e}"));
        assert!(items.len() >= 2, "{label}: SPKI needs ≥2 elements");
        assert!(
            items[0].as_sequence().is_ok(),
            "{label}: AlgorithmIdentifier"
        );
        assert!(items[1].as_bitstring().is_ok(), "{label}: BIT STRING");
    }
}

#[test]
fn ed25519_public_key_is_spki_format() {
    let fx = fx();
    let kp = fx.ed25519("spki-ed", Ed25519Spec::new());

    assert!(
        kp.public_key_spki_pem()
            .contains("-----BEGIN PUBLIC KEY-----"),
        "Expected SPKI label"
    );

    let der = kp.public_key_spki_der();
    let (_, seq) = der_parser::parse_der(der).expect("parse Ed25519 SPKI");
    let items = seq.as_sequence().expect("Ed25519 SPKI SEQUENCE");
    assert!(items.len() >= 2, "SPKI needs ≥2 elements");
    assert!(
        items[0].as_sequence().is_ok(),
        "Ed25519 AlgorithmIdentifier"
    );
    assert!(items[1].as_bitstring().is_ok(), "Ed25519 BIT STRING");
}

// =========================================================================
// 7. X.509 certificate DER validation
// =========================================================================

#[test]
fn x509_self_signed_der_parses_as_certificate() {
    let fx = fx();
    let cert = fx.x509_self_signed("x509-parse", X509Spec::self_signed("parse.example.com"));

    let (_, parsed) =
        X509Certificate::from_der(cert.cert_der()).expect("X.509 DER should parse as certificate");

    // Version should be v3 (encoded as 2)
    assert_eq!(
        parsed.version(),
        X509Version::V3,
        "Expected X.509 v3 certificate"
    );

    // Subject CN
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .expect("certificate should have Subject CN");
    assert_eq!(cn.as_str().unwrap(), "parse.example.com");

    // Self-signed: issuer == subject
    assert_eq!(
        parsed.issuer(),
        parsed.subject(),
        "self-signed cert: issuer should equal subject"
    );

    // Signature algorithm should be present
    assert!(
        !parsed.signature_algorithm.algorithm.to_string().is_empty(),
        "signature algorithm OID should be present"
    );
}

#[test]
fn x509_cert_der_has_valid_asn1_structure() {
    let fx = fx();
    let cert = fx.x509_self_signed("x509-asn1", X509Spec::self_signed("asn1.example.com"));

    let der = cert.cert_der();
    assert_asn1_sequence(der, "X.509 certificate");

    // Full ASN.1 parse
    let (_, parsed) = der_parser::parse_der(der).expect("X.509 DER should parse as ASN.1");
    let items = parsed.as_sequence().expect("X.509 top-level SEQUENCE");
    // X.509 Certificate has 3 elements: tbsCertificate, signatureAlgorithm, signatureValue
    assert_eq!(
        items.len(),
        3,
        "X.509 Certificate should have 3 top-level elements"
    );
}

#[test]
fn x509_cert_has_extensions() {
    let fx = fx();
    let cert = fx.x509_self_signed("x509-ext", X509Spec::self_signed("ext.example.com"));

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");

    // Should have Key Usage
    let extensions = parsed.extensions();
    let has_key_usage = extensions
        .iter()
        .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE);
    assert!(has_key_usage, "certificate should have Key Usage extension");

    // Should have Extended Key Usage (leaf cert)
    let has_eku = extensions
        .iter()
        .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE);
    assert!(
        has_eku,
        "leaf certificate should have Extended Key Usage extension"
    );
}

#[test]
fn x509_chain_leaf_der_is_valid() {
    let fx = fx();
    let chain = fx.x509_chain("x509-chain-leaf", ChainSpec::new("chain.example.com"));

    let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der())
        .expect("leaf certificate DER should parse");
    assert!(!leaf.is_ca(), "leaf certificate should not be CA");

    let cn = leaf
        .subject()
        .iter_common_name()
        .next()
        .expect("leaf should have CN");
    assert_eq!(cn.as_str().unwrap(), "chain.example.com");
}

#[test]
fn x509_chain_root_der_is_valid() {
    let fx = fx();
    let chain = fx.x509_chain("x509-chain-root", ChainSpec::new("chain-root.example.com"));

    let (_, root) = X509Certificate::from_der(chain.root_cert_der())
        .expect("root certificate DER should parse");
    assert!(root.is_ca(), "root certificate should be CA");
}

#[test]
fn x509_chain_intermediate_der_is_valid() {
    let fx = fx();
    let chain = fx.x509_chain("x509-chain-int", ChainSpec::new("chain-int.example.com"));

    let (_, intermediate) = X509Certificate::from_der(chain.intermediate_cert_der())
        .expect("intermediate certificate DER should parse");
    assert!(
        intermediate.is_ca(),
        "intermediate certificate should be CA"
    );
}

#[test]
fn x509_chain_pem_contains_expected_certs() {
    let fx = fx();
    let chain = fx.x509_chain("x509-chain-pem", ChainSpec::new("chain-pem.example.com"));

    let chain_pem = chain.chain_pem();
    let cert_count = chain_pem.matches("-----BEGIN CERTIFICATE-----").count();
    // chain_pem() = leaf + intermediate (not root)
    assert_eq!(
        cert_count, 2,
        "chain PEM should contain leaf + intermediate (2 certs)"
    );
}

#[test]
fn x509_chain_all_pems_have_correct_headers() {
    let fx = fx();
    let chain = fx.x509_chain("x509-chain-hdrs", ChainSpec::new("chain-hdrs.example.com"));

    assert_valid_pem(chain.leaf_cert_pem(), "CERTIFICATE");
    assert_valid_pem(chain.intermediate_cert_pem(), "CERTIFICATE");
    assert_valid_pem(chain.root_cert_pem(), "CERTIFICATE");
    assert_valid_pem(chain.leaf_private_key_pkcs8_pem(), "PRIVATE KEY");
}

#[test]
fn x509_chain_leaf_pem_der_roundtrip() {
    let fx = fx();
    let chain = fx.x509_chain("x509-chain-rt", ChainSpec::new("chain-rt.example.com"));

    assert_pem_der_roundtrip(
        chain.leaf_cert_pem(),
        chain.leaf_cert_der(),
        "chain leaf cert",
    );
    assert_pem_der_roundtrip(
        chain.root_cert_pem(),
        chain.root_cert_der(),
        "chain root cert",
    );
    assert_pem_der_roundtrip(
        chain.intermediate_cert_pem(),
        chain.intermediate_cert_der(),
        "chain intermediate cert",
    );
}

// =========================================================================
// 8. Cross-key-type format consistency
// =========================================================================

/// All key types produce PKCS#8 private keys with identical structural layout.
#[test]
fn all_key_types_produce_consistent_pkcs8_structure() {
    let fx = fx();

    let rsa_kp = fx.rsa("struct-rsa", RsaSpec::rs256());
    let ec_kp = fx.ecdsa("struct-ec", EcdsaSpec::es256());
    let ed_kp = fx.ed25519("struct-ed", Ed25519Spec::new());

    for (name, der) in [
        ("RSA", rsa_kp.private_key_pkcs8_der()),
        ("ECDSA", ec_kp.private_key_pkcs8_der()),
        ("Ed25519", ed_kp.private_key_pkcs8_der()),
    ] {
        let (_, seq) = der_parser::parse_der(der)
            .unwrap_or_else(|e| panic!("{name} PKCS#8 DER parse failed: {e}"));
        let items = seq
            .as_sequence()
            .unwrap_or_else(|e| panic!("{name} PKCS#8 not SEQUENCE: {e}"));

        // All PKCS#8: version(0 or 1), AlgorithmIdentifier, privateKey
        assert!(
            items.len() >= 3,
            "{name}: PKCS#8 should have ≥3 elements, got {}",
            items.len()
        );
        let version = items[0].as_u32().unwrap();
        assert!(
            version == 0 || version == 1,
            "{name}: PKCS#8 version should be 0 or 1, got {version}"
        );
        assert!(
            items[1].as_sequence().is_ok(),
            "{name}: PKCS#8 AlgorithmIdentifier should be SEQUENCE"
        );
    }
}

/// All key types produce SPKI public keys with consistent structure.
#[test]
fn all_key_types_produce_consistent_spki_structure() {
    let fx = fx();

    let rsa_kp = fx.rsa("spki-all-rsa", RsaSpec::rs256());
    let ec_kp = fx.ecdsa("spki-all-ec", EcdsaSpec::es256());
    let ed_kp = fx.ed25519("spki-all-ed", Ed25519Spec::new());

    for (name, der) in [
        ("RSA", rsa_kp.public_key_spki_der()),
        ("ECDSA", ec_kp.public_key_spki_der()),
        ("Ed25519", ed_kp.public_key_spki_der()),
    ] {
        let (_, seq) = der_parser::parse_der(der)
            .unwrap_or_else(|e| panic!("{name} SPKI DER parse failed: {e}"));
        let items = seq
            .as_sequence()
            .unwrap_or_else(|e| panic!("{name} SPKI not SEQUENCE: {e}"));

        assert_eq!(
            items.len(),
            2,
            "{name}: SPKI should have 2 elements (algorithm + key)"
        );
        assert!(
            items[0].as_sequence().is_ok(),
            "{name}: SPKI AlgorithmIdentifier should be SEQUENCE"
        );
        assert!(
            items[1].as_bitstring().is_ok(),
            "{name}: SPKI subjectPublicKey should be BIT STRING"
        );
    }
}

/// RSA keys should be larger than EC/Ed25519 keys in DER form.
#[test]
fn rsa_keys_are_larger_than_ec_and_ed25519() {
    let fx = fx();

    let rsa_kp = fx.rsa("size-rsa", RsaSpec::rs256());
    let ec_kp = fx.ecdsa("size-ec", EcdsaSpec::es256());
    let ed_kp = fx.ed25519("size-ed", Ed25519Spec::new());

    let rsa_len = rsa_kp.private_key_pkcs8_der().len();
    let ec_len = ec_kp.private_key_pkcs8_der().len();
    let ed_len = ed_kp.private_key_pkcs8_der().len();

    assert!(
        rsa_len > ec_len,
        "RSA 2048 private key ({rsa_len}) should be larger than ECDSA P-256 ({ec_len})"
    );
    assert!(
        rsa_len > ed_len,
        "RSA 2048 private key ({rsa_len}) should be larger than Ed25519 ({ed_len})"
    );
}

/// PEM output should end with a newline.
#[test]
fn pem_outputs_end_with_newline() {
    let fx = fx();

    let rsa = fx.rsa("nl-rsa", RsaSpec::rs256());
    assert!(
        rsa.private_key_pkcs8_pem().ends_with('\n'),
        "RSA private PEM should end with newline"
    );
    assert!(
        rsa.public_key_spki_pem().ends_with('\n'),
        "RSA public PEM should end with newline"
    );

    let ec = fx.ecdsa("nl-ec", EcdsaSpec::es256());
    assert!(
        ec.private_key_pkcs8_pem().ends_with('\n'),
        "ECDSA private PEM should end with newline"
    );
    assert!(
        ec.public_key_spki_pem().ends_with('\n'),
        "ECDSA public PEM should end with newline"
    );

    let ed = fx.ed25519("nl-ed", Ed25519Spec::new());
    assert!(
        ed.private_key_pkcs8_pem().ends_with('\n'),
        "Ed25519 private PEM should end with newline"
    );
    assert!(
        ed.public_key_spki_pem().ends_with('\n'),
        "Ed25519 public PEM should end with newline"
    );
}
