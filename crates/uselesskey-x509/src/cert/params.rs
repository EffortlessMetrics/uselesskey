use rand_core::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};
use time::Duration as TimeDuration;
use time::OffsetDateTime;

use crate::srp::derive::{
    deterministic_base_time_from_parts, deterministic_serial_number_with_rng,
};
use crate::srp::spec::{KeyUsage, NotBeforeOffset, X509Spec};

pub(super) fn deterministic_base_time(label: &str, spec: &X509Spec) -> OffsetDateTime {
    let rsa_bits = (spec.rsa_bits as u32).to_be_bytes();
    deterministic_base_time_from_parts(&[
        label.as_bytes(),
        spec.subject_cn.as_bytes(),
        spec.issuer_cn.as_bytes(),
        &rsa_bits,
    ])
}

pub(super) fn self_signed_params(
    spec: &X509Spec,
    base_time: OffsetDateTime,
    rng: &mut impl RngCore,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, spec.subject_cn.clone());

    let not_before = apply_not_before(base_time, spec.not_before_offset);
    params.not_before = not_before;
    params.not_after = not_before + TimeDuration::days(spec.validity_days as i64);
    params.serial_number = Some(deterministic_serial_number_with_rng(|bytes| {
        rng.fill_bytes(bytes);
    }));

    params.is_ca = ca_constraint(spec.is_ca);
    params.key_usages = key_usage_purposes(spec.key_usage);
    if !spec.is_ca {
        params.extended_key_usages = tls_extended_key_usages();
    }
    add_sorted_dns_sans(&mut params, &spec.sans);

    params
}

fn apply_not_before(base_time: OffsetDateTime, offset: NotBeforeOffset) -> OffsetDateTime {
    match offset {
        NotBeforeOffset::DaysAgo(days) => base_time - TimeDuration::days(days as i64),
        NotBeforeOffset::DaysFromNow(days) => base_time + TimeDuration::days(days as i64),
    }
}

fn ca_constraint(is_ca: bool) -> IsCa {
    if is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    }
}

fn key_usage_purposes(key_usage: KeyUsage) -> Vec<KeyUsagePurpose> {
    let mut purposes = Vec::new();
    if key_usage.digital_signature {
        purposes.push(KeyUsagePurpose::DigitalSignature);
    }
    if key_usage.key_encipherment {
        purposes.push(KeyUsagePurpose::KeyEncipherment);
    }
    if key_usage.key_cert_sign {
        purposes.push(KeyUsagePurpose::KeyCertSign);
    }
    if key_usage.crl_sign {
        purposes.push(KeyUsagePurpose::CrlSign);
    }
    purposes
}

fn tls_extended_key_usages() -> Vec<ExtendedKeyUsagePurpose> {
    vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ]
}

fn add_sorted_dns_sans(params: &mut CertificateParams, sans: &[String]) {
    let mut sorted_sans = sans.to_vec();
    sorted_sans.sort();
    sorted_sans.dedup();

    for san in &sorted_sans {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            san.clone().try_into().expect("valid DNS name"),
        ));
    }
}
