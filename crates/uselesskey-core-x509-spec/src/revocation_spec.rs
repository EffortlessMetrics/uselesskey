//! Revocation fixture specification models (CRL/OCSP).

use crate::NotBeforeOffset;

/// Which issuer signs a generated CRL fixture.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum CrlIssuerKind {
    /// Sign with the chain intermediate CA (default).
    Intermediate,
    /// Sign with the chain root CA.
    Root,
}

/// CRL reason code for revoked serial entries.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum CrlReasonCode {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    PrivilegeWithdrawn,
    AaCompromise,
}

/// Deterministic CRL fixture specification.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlSpec {
    pub issuer_kind: CrlIssuerKind,
    pub this_update: NotBeforeOffset,
    pub next_update: NotBeforeOffset,
    pub revoked_serials: Vec<Vec<u8>>,
    pub reason_code: CrlReasonCode,
    pub crl_number: u64,
}

impl CrlSpec {
    /// Default CRL spec for a single target serial.
    pub fn for_serial(serial: Vec<u8>) -> Self {
        Self {
            issuer_kind: CrlIssuerKind::Intermediate,
            this_update: NotBeforeOffset::DaysAgo(0),
            next_update: NotBeforeOffset::DaysFromNow(30),
            revoked_serials: vec![serial],
            reason_code: CrlReasonCode::KeyCompromise,
            crl_number: 1,
        }
    }

    /// Stable bytes used in deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        out.push(match self.issuer_kind {
            CrlIssuerKind::Intermediate => 1,
            CrlIssuerKind::Root => 2,
        });
        encode_offset(&mut out, self.this_update);
        encode_offset(&mut out, self.next_update);
        out.extend_from_slice(&self.crl_number.to_be_bytes());
        out.push(match self.reason_code {
            CrlReasonCode::Unspecified => 0,
            CrlReasonCode::KeyCompromise => 1,
            CrlReasonCode::CaCompromise => 2,
            CrlReasonCode::AffiliationChanged => 3,
            CrlReasonCode::Superseded => 4,
            CrlReasonCode::CessationOfOperation => 5,
            CrlReasonCode::CertificateHold => 6,
            CrlReasonCode::PrivilegeWithdrawn => 7,
            CrlReasonCode::AaCompromise => 8,
        });
        out.extend_from_slice(&(self.revoked_serials.len() as u32).to_be_bytes());
        for serial in &self.revoked_serials {
            out.extend_from_slice(&(serial.len() as u32).to_be_bytes());
            out.extend_from_slice(serial);
        }
        out
    }
}

/// Which responder identity is represented by an OCSP fixture.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum OcspResponderKind {
    Intermediate,
    Root,
}

/// Status encoded for each OCSP target serial.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

/// Whether a nonce is emitted in deterministic OCSP fixture payloads.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum OcspNoncePolicy {
    Omit,
    IncludeDeterministic,
}

/// Deterministic OCSP fixture specification.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspSpec {
    pub responder_kind: OcspResponderKind,
    pub produced_at: NotBeforeOffset,
    pub this_update: NotBeforeOffset,
    pub next_update: NotBeforeOffset,
    pub cert_status: OcspCertStatus,
    pub revocation_reason: Option<CrlReasonCode>,
    pub nonce_policy: OcspNoncePolicy,
}

impl OcspSpec {
    pub fn new(cert_status: OcspCertStatus) -> Self {
        Self {
            responder_kind: OcspResponderKind::Intermediate,
            produced_at: NotBeforeOffset::DaysAgo(0),
            this_update: NotBeforeOffset::DaysAgo(0),
            next_update: NotBeforeOffset::DaysFromNow(1),
            cert_status,
            revocation_reason: None,
            nonce_policy: OcspNoncePolicy::Omit,
        }
    }

    /// Stable bytes used in deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        out.push(match self.responder_kind {
            OcspResponderKind::Intermediate => 1,
            OcspResponderKind::Root => 2,
        });
        encode_offset(&mut out, self.produced_at);
        encode_offset(&mut out, self.this_update);
        encode_offset(&mut out, self.next_update);
        out.push(match self.cert_status {
            OcspCertStatus::Good => 1,
            OcspCertStatus::Revoked => 2,
            OcspCertStatus::Unknown => 3,
        });
        match self.revocation_reason {
            None => out.push(0),
            Some(reason) => {
                out.push(1);
                out.push(match reason {
                    CrlReasonCode::Unspecified => 0,
                    CrlReasonCode::KeyCompromise => 1,
                    CrlReasonCode::CaCompromise => 2,
                    CrlReasonCode::AffiliationChanged => 3,
                    CrlReasonCode::Superseded => 4,
                    CrlReasonCode::CessationOfOperation => 5,
                    CrlReasonCode::CertificateHold => 6,
                    CrlReasonCode::PrivilegeWithdrawn => 7,
                    CrlReasonCode::AaCompromise => 8,
                });
            }
        }
        out.push(match self.nonce_policy {
            OcspNoncePolicy::Omit => 0,
            OcspNoncePolicy::IncludeDeterministic => 1,
        });
        out
    }
}

fn encode_offset(out: &mut Vec<u8>, offset: NotBeforeOffset) {
    match offset {
        NotBeforeOffset::DaysAgo(days) => {
            out.push(1);
            out.extend_from_slice(&days.to_be_bytes());
        }
        NotBeforeOffset::DaysFromNow(days) => {
            out.push(2);
            out.extend_from_slice(&days.to_be_bytes());
        }
    }
}
