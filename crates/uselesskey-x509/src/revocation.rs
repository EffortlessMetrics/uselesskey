//! Deterministic revocation fixtures (CRL / OCSP-shape payloads).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, DistinguishedName, DnType, Issuer,
    KeyPair, RevocationReason, RevokedCertParams,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use time::Duration as TimeDuration;
use time::OffsetDateTime;
use uselesskey_core_x509::{
    CrlIssuerKind, CrlReasonCode, CrlSpec, NotBeforeOffset, OcspCertStatus, OcspSpec,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::chain::X509Chain;

/// Cache domain for explicit CRL fixtures.
pub const DOMAIN_X509_REVOCATION_CRL: &str = "uselesskey:x509:revocation:crl";
/// Cache domain for explicit OCSP fixtures.
pub const DOMAIN_X509_REVOCATION_OCSP: &str = "uselesskey:x509:revocation:ocsp";

/// Explicit deterministic revocation artifact payload.
#[derive(Clone, Debug)]
pub struct RevocationFixture {
    der: Arc<[u8]>,
    pem: Option<String>,
    base64: String,
    issuer_binding: String,
    serial_bindings: Vec<Vec<u8>>,
}

impl RevocationFixture {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn pem(&self) -> Option<&str> {
        self.pem.as_deref()
    }

    pub fn base64(&self) -> &str {
        &self.base64
    }

    pub fn issuer_binding(&self) -> &str {
        &self.issuer_binding
    }

    pub fn serial_bindings(&self) -> &[Vec<u8>] {
        &self.serial_bindings
    }
}

impl X509Chain {
    /// Build a deterministic CRL fixture for the current leaf cert serial.
    pub fn crl_for_leaf(&self) -> RevocationFixture {
        let (_, leaf) = X509Certificate::from_der(self.leaf_cert_der()).expect("leaf parse");
        let spec = CrlSpec::for_serial(leaf.raw_serial().to_vec());
        self.crl_with_spec(spec, "leaf")
    }

    /// Build a deterministic CRL fixture for the current intermediate cert serial.
    pub fn crl_for_intermediate(&self) -> RevocationFixture {
        let (_, cert) =
            X509Certificate::from_der(self.intermediate_cert_der()).expect("intermediate parse");
        let spec = CrlSpec::for_serial(cert.raw_serial().to_vec());
        self.crl_with_spec(spec, "intermediate")
    }

    /// Build a deterministic OCSP-shape fixture for the current leaf cert serial.
    pub fn ocsp_for_leaf(&self, status: OcspCertStatus) -> RevocationFixture {
        let (_, leaf) = X509Certificate::from_der(self.leaf_cert_der()).expect("leaf parse");
        self.ocsp_with_spec(OcspSpec::new(status), "leaf", leaf.raw_serial().to_vec())
    }

    /// Build a deterministic OCSP-shape fixture for the current intermediate cert serial.
    pub fn ocsp_for_intermediate(&self, status: OcspCertStatus) -> RevocationFixture {
        let (_, cert) =
            X509Certificate::from_der(self.intermediate_cert_der()).expect("intermediate parse");
        self.ocsp_with_spec(
            OcspSpec::new(status),
            "intermediate",
            cert.raw_serial().to_vec(),
        )
    }

    fn crl_with_spec(&self, spec: CrlSpec, target_label: &str) -> RevocationFixture {
        let mut spec_bytes = self.spec().stable_bytes();
        spec_bytes.extend_from_slice(&spec.stable_bytes());
        let variant = format!("crl:{target_label}");
        let cached = self.factory().get_or_init(
            DOMAIN_X509_REVOCATION_CRL,
            self.label(),
            &spec_bytes,
            &variant,
            |_| build_crl_fixture(self, &spec),
        );
        (*cached).clone()
    }

    fn ocsp_with_spec(
        &self,
        spec: OcspSpec,
        target_label: &str,
        target_serial: Vec<u8>,
    ) -> RevocationFixture {
        let mut spec_bytes = self.spec().stable_bytes();
        spec_bytes.extend_from_slice(&spec.stable_bytes());
        spec_bytes.extend_from_slice(&(target_serial.len() as u32).to_be_bytes());
        spec_bytes.extend_from_slice(&target_serial);
        let variant = format!("ocsp:{target_label}");
        let cached = self.factory().get_or_init(
            DOMAIN_X509_REVOCATION_OCSP,
            self.label(),
            &spec_bytes,
            &variant,
            |_| build_ocsp_fixture(self, &spec, target_serial.clone()),
        );
        (*cached).clone()
    }
}

fn build_crl_fixture(chain: &X509Chain, spec: &CrlSpec) -> RevocationFixture {
    let base_time = deterministic_revocation_base_time(chain);
    let this_update = apply_offset(base_time, spec.this_update);
    let next_update = apply_offset(base_time, spec.next_update);

    let (issuer_cn, issuer_key_der) = match spec.issuer_kind {
        CrlIssuerKind::Intermediate => (
            cert_cn(chain.intermediate_cert_der()),
            chain.intermediate_private_key_pkcs8_der(),
        ),
        CrlIssuerKind::Root => (cert_cn(chain.root_cert_der()), chain.root_private_key_pkcs8_der()),
    };
    let issuer_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(issuer_key_der.to_vec()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .expect("issuer key parse");

    let mut issuer_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, issuer_cn.clone());
    issuer_params.distinguished_name = dn;
    let issuer = Issuer::from_params(&issuer_params, &issuer_key);

    let revoked_certs = spec
        .revoked_serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: rcgen::SerialNumber::from_slice(serial),
            revocation_time: this_update,
            reason_code: Some(map_reason(spec.reason_code)),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: rcgen::SerialNumber::from(spec.crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl = params.signed_by(&issuer).expect("crl sign");
    let der: Arc<[u8]> = Arc::from(crl.der().as_ref());
    let pem = crl.pem().ok();
    let base64 = B64.encode(der.as_ref());

    RevocationFixture {
        der,
        pem,
        base64,
        issuer_binding: issuer_cn,
        serial_bindings: spec.revoked_serials.clone(),
    }
}

fn build_ocsp_fixture(chain: &X509Chain, spec: &OcspSpec, target_serial: Vec<u8>) -> RevocationFixture {
    let responder_cn = cert_cn(chain.intermediate_cert_der());
    let payload = format!(
        "UK-OCSP/1|responder={responder_cn}|status={:?}|produced_at={:?}|this_update={:?}|next_update={:?}|serial={}",
        spec.cert_status,
        spec.produced_at,
        spec.this_update,
        spec.next_update,
        B64.encode(&target_serial),
    );
    let der = Arc::<[u8]>::from(payload.into_bytes());
    let base64 = B64.encode(der.as_ref());
    RevocationFixture {
        der,
        pem: None,
        base64,
        issuer_binding: responder_cn,
        serial_bindings: vec![target_serial],
    }
}

fn apply_offset(base: OffsetDateTime, offset: NotBeforeOffset) -> OffsetDateTime {
    match offset {
        NotBeforeOffset::DaysAgo(days) => base - TimeDuration::days(days as i64),
        NotBeforeOffset::DaysFromNow(days) => base + TimeDuration::days(days as i64),
    }
}

fn map_reason(reason: CrlReasonCode) -> RevocationReason {
    match reason {
        CrlReasonCode::Unspecified => RevocationReason::Unspecified,
        CrlReasonCode::KeyCompromise => RevocationReason::KeyCompromise,
        CrlReasonCode::CaCompromise => RevocationReason::CaCompromise,
        CrlReasonCode::AffiliationChanged => RevocationReason::AffiliationChanged,
        CrlReasonCode::Superseded => RevocationReason::Superseded,
        CrlReasonCode::CessationOfOperation => RevocationReason::CessationOfOperation,
        CrlReasonCode::CertificateHold => RevocationReason::CertificateHold,
        CrlReasonCode::PrivilegeWithdrawn => RevocationReason::PrivilegeWithdrawn,
        CrlReasonCode::AaCompromise => RevocationReason::AaCompromise,
        // rcgen does not currently expose remove_from_crl.
    }
}

fn cert_cn(cert_der: &[u8]) -> String {
    let (_, cert) = X509Certificate::from_der(cert_der).expect("cert parse");
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

fn deterministic_revocation_base_time(chain: &X509Chain) -> OffsetDateTime {
    let seed = uselesskey_core_x509::deterministic_base_time_from_parts(&[
        chain.label().as_bytes(),
        chain.spec().leaf_cn.as_bytes(),
        b"revocation",
    ]);
    seed
}
