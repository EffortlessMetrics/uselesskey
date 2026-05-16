//! Single-responsibility helpers for self-signed certificate material.

use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use time::Duration as TimeDuration;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

use crate::srp::derive::{
    deterministic_base_time_from_parts, deterministic_serial_number_with_rng,
};
use crate::srp::spec::{NotBeforeOffset, X509Spec};

/// Generated certificate and private-key bytes for one self-signed fixture.
pub(crate) struct SelfSignedCertMaterial {
    pub(crate) cert_der: Arc<[u8]>,
    pub(crate) cert_pem: String,
    pub(crate) private_key_pkcs8_der: Arc<[u8]>,
    pub(crate) private_key_pkcs8_pem: String,
}

/// Build deterministic self-signed certificate material for an already-derived artifact seed.
pub(crate) fn build_self_signed_cert_material(
    factory: &Factory,
    label: &str,
    spec: &X509Spec,
    seed: Seed,
) -> SelfSignedCertMaterial {
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
    let rsa_keypair = deterministic_rsa_keypair(factory, label, spec);
    let pkcs8_der = rsa_keypair.private_key_pkcs8_der();
    let key_pair = rcgen_key_pair_from_pkcs8(pkcs8_der);

    let params = certificate_params(label, spec, &mut rng);
    let cert = params.self_signed(&key_pair).expect("cert generation");

    SelfSignedCertMaterial {
        cert_der: Arc::from(cert.der().as_ref()),
        cert_pem: cert.pem(),
        private_key_pkcs8_der: Arc::from(pkcs8_der),
        private_key_pkcs8_pem: rsa_keypair.private_key_pkcs8_pem().to_string(),
    }
}

fn deterministic_rsa_keypair(
    factory: &Factory,
    label: &str,
    spec: &X509Spec,
) -> uselesskey_rsa::RsaKeyPair {
    // Generate RSA key using uselesskey-rsa for deterministic key generation.
    // The certificate cache variant is intentionally not part of the key identity so
    // negative certificate variants keep the same key while changing certificate metadata.
    let key_label = format!("{}-key", label);
    factory.rsa(&key_label, RsaSpec::new(spec.rsa_bits))
}

fn rcgen_key_pair_from_pkcs8(pkcs8_der: &[u8]) -> KeyPair {
    let pkcs8_key = PrivatePkcs8KeyDer::from(pkcs8_der.to_vec());
    KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key, &PKCS_RSA_SHA256).expect("key parse")
}

fn certificate_params(label: &str, spec: &X509Spec, rng: &mut ChaCha20Rng) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, spec.subject_cn.clone());

    set_validity(label, spec, &mut params);
    params.serial_number = Some(deterministic_serial_number_with_rng(|bytes| {
        rng.fill_bytes(bytes);
    }));
    set_ca_status(spec, &mut params);
    set_key_usages(spec, &mut params);
    set_extended_key_usages(spec, &mut params);
    set_subject_alt_names(spec, &mut params);

    params
}

fn set_validity(label: &str, spec: &X509Spec, params: &mut CertificateParams) {
    let rsa_bits = (spec.rsa_bits as u32).to_be_bytes();
    let base_time = deterministic_base_time_from_parts(&[
        label.as_bytes(),
        spec.subject_cn.as_bytes(),
        spec.issuer_cn.as_bytes(),
        &rsa_bits,
    ]);

    let not_before = match spec.not_before_offset {
        NotBeforeOffset::DaysAgo(days) => base_time - TimeDuration::days(days as i64),
        NotBeforeOffset::DaysFromNow(days) => base_time + TimeDuration::days(days as i64),
    };

    params.not_before = not_before;
    params.not_after = not_before + TimeDuration::days(spec.validity_days as i64);
}

fn set_ca_status(spec: &X509Spec, params: &mut CertificateParams) {
    params.is_ca = if spec.is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    };
}

fn set_key_usages(spec: &X509Spec, params: &mut CertificateParams) {
    let mut key_usages = Vec::new();
    if spec.key_usage.digital_signature {
        key_usages.push(KeyUsagePurpose::DigitalSignature);
    }
    if spec.key_usage.key_encipherment {
        key_usages.push(KeyUsagePurpose::KeyEncipherment);
    }
    if spec.key_usage.key_cert_sign {
        key_usages.push(KeyUsagePurpose::KeyCertSign);
    }
    if spec.key_usage.crl_sign {
        key_usages.push(KeyUsagePurpose::CrlSign);
    }
    params.key_usages = key_usages;
}

fn set_extended_key_usages(spec: &X509Spec, params: &mut CertificateParams) {
    if !spec.is_ca {
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
    }
}

fn set_subject_alt_names(spec: &X509Spec, params: &mut CertificateParams) {
    let mut sorted_sans = spec.sans.clone();
    sorted_sans.sort();
    sorted_sans.dedup();
    for san in &sorted_sans {
        params.subject_alt_names.push(rcgen::SanType::DnsName(
            san.clone().try_into().expect("valid DNS name"),
        ));
    }
}
