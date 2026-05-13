//! Certificate revocation list generation for X.509 chain negatives.

use std::sync::Arc;

use rand_core::RngCore;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, Issuer, KeyPair, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::srp::derive::deterministic_serial_number_with_rng;

pub(crate) struct RevocationListBytes {
    pub(crate) der: Arc<[u8]>,
    pub(crate) pem: String,
}

pub(crate) fn maybe_revoked_leaf_crl<R: RngCore>(
    variant: &str,
    leaf_serial: SerialNumber,
    base_time: OffsetDateTime,
    intermediate_params: &CertificateParams,
    intermediate_key: &KeyPair,
    rng: &mut R,
) -> Option<RevocationListBytes> {
    (variant == "revoked_leaf").then(|| {
        revoked_leaf_crl(
            leaf_serial,
            base_time,
            intermediate_params,
            intermediate_key,
            rng,
        )
    })
}

fn revoked_leaf_crl<R: RngCore>(
    leaf_serial: SerialNumber,
    base_time: OffsetDateTime,
    intermediate_params: &CertificateParams,
    intermediate_key: &KeyPair,
    rng: &mut R,
) -> RevocationListBytes {
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

    let issuer = Issuer::from_params(intermediate_params, intermediate_key);
    let crl = crl_params.signed_by(&issuer).expect("CRL gen");

    RevocationListBytes {
        der: Arc::from(crl.der().as_ref()),
        pem: crl.pem().expect("CRL PEM"),
    }
}
