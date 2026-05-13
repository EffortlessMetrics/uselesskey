//! X.509 chain certificate and CRL assembly helpers.
//!
//! This module is responsible for turning prepared chain key material and a
//! [`ChainSpec`](super::spec::ChainSpec) into serialized root, intermediate,
//! leaf, and optional CRL artifacts.

use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose, RevocationReason, RevokedCertParams,
};
use time::{Duration as TimeDuration, OffsetDateTime};
use uselesskey_core::Seed;

use super::chain_keys::ChainKeyMaterial;
use super::derive::{deterministic_base_time_from_parts, deterministic_serial_number_with_rng};
use super::spec::{ChainSpec, KeyUsage, NotBeforeOffset};

/// Serialized chain outputs ready for the public `X509Chain` facade.
pub(crate) struct ChainArtifacts {
    pub(crate) root_cert_der: Arc<[u8]>,
    pub(crate) root_cert_pem: String,
    pub(crate) root_key_pkcs8_der: Arc<[u8]>,
    pub(crate) root_key_pkcs8_pem: String,

    pub(crate) intermediate_cert_der: Arc<[u8]>,
    pub(crate) intermediate_cert_pem: String,
    pub(crate) intermediate_key_pkcs8_der: Arc<[u8]>,
    pub(crate) intermediate_key_pkcs8_pem: String,

    pub(crate) leaf_cert_der: Arc<[u8]>,
    pub(crate) leaf_cert_pem: String,
    pub(crate) leaf_key_pkcs8_der: Arc<[u8]>,
    pub(crate) leaf_key_pkcs8_pem: String,

    pub(crate) crl_der: Option<Arc<[u8]>>,
    pub(crate) crl_pem: Option<String>,
}

/// Build a deterministic three-level certificate chain and optional CRL.
pub(crate) fn build_chain_artifacts(
    label: &str,
    spec: &ChainSpec,
    variant: &str,
    seed: Seed,
    keys: &ChainKeyMaterial,
) -> ChainArtifacts {
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
    let base_time = chain_base_time(label, spec);

    let root_params = root_params(spec, base_time, &mut rng);
    let root_cert = root_params
        .self_signed(&keys.root_kp)
        .expect("root cert gen");

    let intermediate_params = intermediate_params(spec, base_time, &mut rng);
    let root_issuer = Issuer::from_params(&root_params, &keys.root_kp);
    let intermediate_cert = intermediate_params
        .signed_by(&keys.intermediate_kp, &root_issuer)
        .expect("intermediate cert gen");

    let leaf_params = leaf_params(spec, base_time, &mut rng);
    let leaf_serial = leaf_params
        .serial_number
        .clone()
        .expect("leaf serial number");
    let intermediate_issuer = Issuer::from_params(&intermediate_params, &keys.intermediate_kp);
    let leaf_cert = leaf_params
        .signed_by(&keys.leaf_kp, &intermediate_issuer)
        .expect("leaf cert gen");

    let (crl_der, crl_pem) = revoked_leaf_crl(
        variant,
        base_time,
        leaf_serial,
        &intermediate_params,
        &keys.intermediate_kp,
        &mut rng,
    );

    ChainArtifacts {
        root_cert_der: Arc::from(root_cert.der().as_ref()),
        root_cert_pem: root_cert.pem(),
        root_key_pkcs8_der: Arc::from(keys.root_rsa.private_key_pkcs8_der()),
        root_key_pkcs8_pem: keys.root_rsa.private_key_pkcs8_pem().to_string(),

        intermediate_cert_der: Arc::from(intermediate_cert.der().as_ref()),
        intermediate_cert_pem: intermediate_cert.pem(),
        intermediate_key_pkcs8_der: Arc::from(keys.intermediate_rsa.private_key_pkcs8_der()),
        intermediate_key_pkcs8_pem: keys.intermediate_rsa.private_key_pkcs8_pem().to_string(),

        leaf_cert_der: Arc::from(leaf_cert.der().as_ref()),
        leaf_cert_pem: leaf_cert.pem(),
        leaf_key_pkcs8_der: Arc::from(keys.leaf_rsa.private_key_pkcs8_der()),
        leaf_key_pkcs8_pem: keys.leaf_rsa.private_key_pkcs8_pem().to_string(),

        crl_der,
        crl_pem,
    }
}

fn chain_base_time(label: &str, spec: &ChainSpec) -> OffsetDateTime {
    let rsa_bits = (spec.rsa_bits as u32).to_be_bytes();
    deterministic_base_time_from_parts(&[
        label.as_bytes(),
        spec.leaf_cn.as_bytes(),
        spec.root_cn.as_bytes(),
        &rsa_bits,
    ])
}

fn root_params(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut ChaCha20Rng,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, spec.root_cn.clone());
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = base_time - TimeDuration::days(1);
    params.not_after = params.not_before + TimeDuration::days(spec.root_validity_days as i64);
    params.serial_number = Some(next_serial(rng));
    params
}

fn intermediate_params(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut ChaCha20Rng,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, spec.intermediate_cn.clone());
    params.is_ca = if spec.intermediate_is_ca.unwrap_or(true) {
        IsCa::Ca(BasicConstraints::Constrained(0))
    } else {
        IsCa::NoCa
    };
    params.key_usages =
        key_usage_purposes(spec.intermediate_key_usage.unwrap_or_else(KeyUsage::ca));
    params.not_before = apply_not_before(base_time, spec.intermediate_not_before);
    params.not_after =
        params.not_before + TimeDuration::days(spec.intermediate_validity_days as i64);
    params.serial_number = Some(next_serial(rng));
    params
}

fn leaf_params(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut ChaCha20Rng,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, spec.leaf_cn.clone());
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    for san in sorted_leaf_sans(spec) {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            san.try_into().expect("valid DNS name"),
        ));
    }

    params.not_before = apply_not_before(base_time, spec.leaf_not_before);
    params.not_after = params.not_before + TimeDuration::days(spec.leaf_validity_days as i64);
    params.serial_number = Some(next_serial(rng));
    params
}

fn sorted_leaf_sans(spec: &ChainSpec) -> Vec<String> {
    let mut sorted_sans = spec.leaf_sans.clone();
    sorted_sans.sort();
    sorted_sans.dedup();
    sorted_sans
}

fn revoked_leaf_crl(
    variant: &str,
    base_time: OffsetDateTime,
    leaf_serial: rcgen::SerialNumber,
    intermediate_params: &CertificateParams,
    intermediate_kp: &rcgen::KeyPair,
    rng: &mut ChaCha20Rng,
) -> (Option<Arc<[u8]>>, Option<String>) {
    if variant != "revoked_leaf" {
        return (None, None);
    }

    let revoked = RevokedCertParams {
        serial_number: leaf_serial,
        revocation_time: base_time,
        reason_code: Some(RevocationReason::KeyCompromise),
        invalidity_date: None,
    };

    let crl_params = CertificateRevocationListParams {
        this_update: base_time,
        next_update: base_time + TimeDuration::days(30),
        crl_number: next_serial(rng),
        issuing_distribution_point: None,
        revoked_certs: vec![revoked],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let intermediate_issuer = Issuer::from_params(intermediate_params, intermediate_kp);
    let crl = crl_params.signed_by(&intermediate_issuer).expect("CRL gen");

    (
        Some(Arc::from(crl.der().as_ref())),
        Some(crl.pem().expect("CRL PEM")),
    )
}

fn next_serial(rng: &mut ChaCha20Rng) -> rcgen::SerialNumber {
    deterministic_serial_number_with_rng(|bytes| rng.fill_bytes(bytes))
}

fn apply_not_before(base_time: OffsetDateTime, offset: Option<NotBeforeOffset>) -> OffsetDateTime {
    match offset.unwrap_or(NotBeforeOffset::DaysAgo(1)) {
        NotBeforeOffset::DaysAgo(days) => base_time - TimeDuration::days(days as i64),
        NotBeforeOffset::DaysFromNow(days) => base_time + TimeDuration::days(days as i64),
    }
}

fn key_usage_purposes(key_usage: KeyUsage) -> Vec<KeyUsagePurpose> {
    let mut purposes = Vec::new();
    if key_usage.key_cert_sign {
        purposes.push(KeyUsagePurpose::KeyCertSign);
    }
    if key_usage.crl_sign {
        purposes.push(KeyUsagePurpose::CrlSign);
    }
    if key_usage.digital_signature {
        purposes.push(KeyUsagePurpose::DigitalSignature);
    }
    if key_usage.key_encipherment {
        purposes.push(KeyUsagePurpose::KeyEncipherment);
    }
    purposes
}
