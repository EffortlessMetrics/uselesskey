//! Revocation-list generation for certificate-chain negative fixtures.

use std::sync::Arc;

use rand_core::RngCore;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, Issuer, KeyPair, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use time::Duration as TimeDuration;
use time::OffsetDateTime;

use crate::srp::chain::params::next_serial;

pub(crate) struct CrlMaterial {
    pub(crate) der: Option<Arc<[u8]>>,
    pub(crate) pem: Option<String>,
}

impl CrlMaterial {
    pub(crate) fn none() -> Self {
        Self {
            der: None,
            pem: None,
        }
    }
}

pub(crate) fn revoked_leaf_crl(
    variant: &str,
    leaf_serial: SerialNumber,
    issuer_params: &CertificateParams,
    issuer_key: &KeyPair,
    base_time: OffsetDateTime,
    rng: &mut impl RngCore,
) -> CrlMaterial {
    if variant != "revoked_leaf" {
        return CrlMaterial::none();
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

    let issuer = Issuer::from_params(issuer_params, issuer_key);
    let crl = crl_params.signed_by(&issuer).expect("CRL gen");

    CrlMaterial {
        der: Some(Arc::from(crl.der().as_ref())),
        pem: Some(crl.pem().expect("CRL PEM")),
    }
}
