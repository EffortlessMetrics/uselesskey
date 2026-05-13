//! Certificate parameter construction for X.509 chains.

use rand_core::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    SerialNumber,
};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::srp::derive::deterministic_serial_number_with_rng;
use crate::srp::spec::{ChainSpec, KeyUsage, NotBeforeOffset};

pub(crate) struct ChainParams {
    pub(crate) root: CertificateParams,
    pub(crate) intermediate: CertificateParams,
    pub(crate) leaf: CertificateParams,
    pub(crate) leaf_serial: SerialNumber,
}

pub(crate) fn build_chain_params<R: RngCore>(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut R,
) -> ChainParams {
    let root = build_root_params(spec, base_time, rng);
    let intermediate = build_intermediate_params(spec, base_time, rng);
    let leaf = build_leaf_params(spec, base_time, rng);
    let leaf_serial = leaf.serial_number.clone().expect("leaf serial number");

    ChainParams {
        root,
        intermediate,
        leaf,
        leaf_serial,
    }
}

fn build_root_params<R: RngCore>(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut R,
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
    params.serial_number = Some(next_serial_number(rng));
    params
}

fn build_intermediate_params<R: RngCore>(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut R,
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
    params.serial_number = Some(next_serial_number(rng));
    params
}

fn build_leaf_params<R: RngCore>(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut R,
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
    params.subject_alt_names = sorted_leaf_sans(spec);
    params.not_before = apply_not_before(base_time, spec.leaf_not_before);
    params.not_after = params.not_before + TimeDuration::days(spec.leaf_validity_days as i64);
    params.serial_number = Some(next_serial_number(rng));
    params
}

fn sorted_leaf_sans(spec: &ChainSpec) -> Vec<rcgen::SanType> {
    let mut sorted_sans = spec.leaf_sans.clone();
    sorted_sans.sort();
    sorted_sans.dedup();
    sorted_sans
        .into_iter()
        .map(|san| rcgen::SanType::DnsName(san.try_into().expect("valid DNS name")))
        .collect()
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

fn next_serial_number<R: RngCore>(rng: &mut R) -> SerialNumber {
    deterministic_serial_number_with_rng(|bytes| rng.fill_bytes(bytes))
}
