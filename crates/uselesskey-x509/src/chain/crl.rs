use std::sync::Arc;

use rand_core::RngCore;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, Issuer, KeyPair, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use time::Duration as TimeDuration;
use time::OffsetDateTime;

use crate::srp::derive::deterministic_serial_number_with_rng;

pub(super) struct CrlOutput {
    pub(super) der: Option<Arc<[u8]>>,
    pub(super) pem: Option<String>,
}

pub(super) fn maybe_revoked_leaf_crl(
    variant: &str,
    base_time: OffsetDateTime,
    leaf_serial: SerialNumber,
    issuer_params: &CertificateParams,
    issuer_key_pair: &KeyPair,
    rng: &mut impl RngCore,
) -> CrlOutput {
    if variant != "revoked_leaf" {
        return CrlOutput {
            der: None,
            pem: None,
        };
    }

    let crl_number = deterministic_serial_number_with_rng(|bytes| rng.fill_bytes(bytes));
    let revoked = RevokedCertParams {
        serial_number: leaf_serial,
        revocation_time: base_time,
        reason_code: Some(RevocationReason::KeyCompromise),
        invalidity_date: None,
    };
    let crl_params = CertificateRevocationListParams {
        this_update: base_time,
        next_update: base_time + TimeDuration::days(30),
        crl_number,
        issuing_distribution_point: None,
        revoked_certs: vec![revoked],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let issuer = Issuer::from_params(issuer_params, issuer_key_pair);
    let crl = crl_params.signed_by(&issuer).expect("CRL gen");

    CrlOutput {
        der: Some(Arc::from(crl.der().as_ref())),
        pem: Some(crl.pem().expect("CRL PEM")),
    }
}
