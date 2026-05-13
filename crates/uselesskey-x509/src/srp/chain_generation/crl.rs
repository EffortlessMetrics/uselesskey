//! Certificate revocation list generation for X.509 chain negative fixtures.

use std::sync::Arc;

use rand_core::RngCore;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, Issuer, KeyPair, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use time::Duration as TimeDuration;
use time::OffsetDateTime;

use super::params;

pub(crate) fn revoked_leaf<R: RngCore>(
    variant: &str,
    rng: &mut R,
    base_time: OffsetDateTime,
    leaf_serial: SerialNumber,
    intermediate_params: &CertificateParams,
    intermediate_key_pair: &KeyPair,
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
        crl_number: params::serial_number(rng),
        issuing_distribution_point: None,
        revoked_certs: vec![revoked],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let int_issuer = Issuer::from_params(intermediate_params, intermediate_key_pair);
    let crl = crl_params.signed_by(&int_issuer).expect("CRL gen");

    (
        Some(Arc::from(crl.der().as_ref())),
        Some(crl.pem().expect("CRL PEM")),
    )
}
