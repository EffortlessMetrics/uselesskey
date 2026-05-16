use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use time::Duration as TimeDuration;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

use super::{DOMAIN_X509_CERT, X509Cert};
use crate::srp::derive::{
    deterministic_base_time_from_parts, deterministic_serial_number_with_rng,
};
use crate::srp::spec::{NotBeforeOffset, X509Spec};

pub(super) struct Inner {
    pub(super) cert_der: Arc<[u8]>,
    pub(super) cert_pem: String,
    pub(super) private_key_pkcs8_der: Arc<[u8]>,
    pub(super) private_key_pkcs8_pem: String,
}

impl X509Cert {
    pub(super) fn new(factory: Factory, label: &str, spec: X509Spec) -> Self {
        let inner = load_inner(&factory, label, &spec, "good");
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    #[allow(
        dead_code,
        reason = "reserved for future variant-based negative fixtures"
    )]
    pub(super) fn load_variant(&self, variant: &str) -> Arc<Inner> {
        load_inner(&self.factory, &self.label, &self.spec, variant)
    }
}

pub(super) fn load_inner(
    factory: &Factory,
    label: &str,
    spec: &X509Spec,
    variant: &str,
) -> Arc<Inner> {
    load_inner_with_spec(factory, label, spec, variant)
}

pub(super) fn load_inner_with_spec(
    factory: &Factory,
    label: &str,
    spec: &X509Spec,
    variant: &str,
) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_X509_CERT, label, &spec_bytes, variant, |seed| {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
        // Generate RSA key using uselesskey-rsa for deterministic key generation.
        // We use the label + variant to derive a unique key.
        let key_label = format!("{}-key", label);
        let rsa_spec = RsaSpec::new(spec.rsa_bits);
        let rsa_keypair = factory.rsa(&key_label, rsa_spec);

        // Get the PKCS#8 DER key and convert it to rcgen's KeyPair
        let pkcs8_der = rsa_keypair.private_key_pkcs8_der();
        let pkcs8_key = PrivatePkcs8KeyDer::from(pkcs8_der.to_vec());
        let key_pair =
            KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key, &PKCS_RSA_SHA256).expect("key parse");

        // Build certificate parameters
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, spec.subject_cn.clone());

        // Set validity period based on spec
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

        let not_after = not_before + TimeDuration::days(spec.validity_days as i64);

        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(deterministic_serial_number_with_rng(|bytes| {
            rng.fill_bytes(bytes);
        }));

        // Set CA status
        if spec.is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        } else {
            params.is_ca = IsCa::NoCa;
        }

        // Set key usage
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

        // Add extended key usage for TLS
        if !spec.is_ca {
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
        }

        // Add Subject Alternative Names
        let mut sorted_sans = spec.sans.clone();
        sorted_sans.sort();
        sorted_sans.dedup();
        for san in &sorted_sans {
            params.subject_alt_names.push(rcgen::SanType::DnsName(
                san.clone().try_into().expect("valid DNS name"),
            ));
        }

        // Generate the self-signed certificate
        let cert = params.self_signed(&key_pair).expect("cert generation");

        let cert_der: Arc<[u8]> = Arc::from(cert.der().as_ref());
        let cert_pem = cert.pem();

        let private_key_pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der);
        let private_key_pkcs8_pem = rsa_keypair.private_key_pkcs8_pem().to_string();

        Inner {
            cert_der,
            cert_pem,
            private_key_pkcs8_der,
            private_key_pkcs8_pem,
        }
    })
}
