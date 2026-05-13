//! Certificate parameter builders for the chain roles.

use rand_core::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    SerialNumber,
};
use time::Duration as TimeDuration;
use time::OffsetDateTime;

use crate::srp::derive::{
    deterministic_base_time_from_parts, deterministic_serial_number_with_rng,
};
use crate::srp::spec::{ChainSpec, KeyUsage, NotBeforeOffset};

pub(crate) fn base_time(label: &str, spec: &ChainSpec) -> OffsetDateTime {
    let rsa_bits = (spec.rsa_bits as u32).to_be_bytes();
    deterministic_base_time_from_parts(&[
        label.as_bytes(),
        spec.leaf_cn.as_bytes(),
        spec.root_cn.as_bytes(),
        &rsa_bits,
    ])
}

pub(crate) fn root<R: RngCore>(
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
    params.serial_number = Some(serial_number(rng));
    params
}

pub(crate) fn intermediate<R: RngCore>(
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
    params.serial_number = Some(serial_number(rng));
    params
}

pub(crate) fn leaf<R: RngCore>(
    spec: &ChainSpec,
    base_time: OffsetDateTime,
    rng: &mut R,
) -> (CertificateParams, SerialNumber) {
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

    let mut sorted_sans = spec.leaf_sans.clone();
    sorted_sans.sort();
    sorted_sans.dedup();
    for san in &sorted_sans {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            san.clone().try_into().expect("valid DNS name"),
        ));
    }

    params.not_before = apply_not_before(base_time, spec.leaf_not_before);
    params.not_after = params.not_before + TimeDuration::days(spec.leaf_validity_days as i64);
    params.serial_number = Some(serial_number(rng));

    let serial = params.serial_number.clone().expect("leaf serial number");
    (params, serial)
}

pub(crate) fn serial_number<R: RngCore>(rng: &mut R) -> SerialNumber {
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
