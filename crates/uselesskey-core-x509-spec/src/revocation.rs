//! Revocation fixture specifications.

/// Which certificate authority signs a CRL fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CrlIssuerKind {
    /// Root CA signs the CRL.
    Root,
    /// Intermediate CA signs the CRL.
    Intermediate,
}

/// Which certificate signs OCSP responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OcspResponderKind {
    /// Issuer certificate signs the response.
    Issuer,
    /// Root CA signs the response.
    Root,
    /// Intermediate CA signs the response.
    Intermediate,
}

/// Certificate status carried by an OCSP fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

/// Revocation reason code used by CRL/OCSP fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RevocationReasonCode {
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

/// Nonce policy used by OCSP fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OcspNoncePolicy {
    Absent,
    Deterministic,
}

/// Relative time offset in days from deterministic base time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TimeOffsetDays {
    pub days_from_base: i32,
}

impl TimeOffsetDays {
    pub const fn from_base(days_from_base: i32) -> Self {
        Self { days_from_base }
    }

    fn stable_bytes(self) -> [u8; 4] {
        self.days_from_base.to_be_bytes()
    }
}

/// Deterministic CRL fixture specification.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlSpec {
    pub issuer_kind: CrlIssuerKind,
    pub this_update: TimeOffsetDays,
    pub next_update: TimeOffsetDays,
    pub revoked_serials: Vec<Vec<u8>>,
    pub reason_code: Option<RevocationReasonCode>,
    pub crl_number: u64,
}

impl CrlSpec {
    pub fn for_intermediate(revoked_serial: Vec<u8>) -> Self {
        Self {
            issuer_kind: CrlIssuerKind::Intermediate,
            this_update: TimeOffsetDays::from_base(0),
            next_update: TimeOffsetDays::from_base(30),
            revoked_serials: vec![revoked_serial],
            reason_code: Some(RevocationReasonCode::KeyCompromise),
            crl_number: 1,
        }
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1);
        out.push(match self.issuer_kind {
            CrlIssuerKind::Root => 1,
            CrlIssuerKind::Intermediate => 2,
        });
        out.extend_from_slice(&self.this_update.stable_bytes());
        out.extend_from_slice(&self.next_update.stable_bytes());
        out.extend_from_slice(&self.crl_number.to_be_bytes());
        out.push(match self.reason_code {
            None => 0,
            Some(code) => 1 + reason_code_to_u8(code),
        });
        let mut serials = self.revoked_serials.clone();
        serials.sort();
        serials.dedup();
        out.extend_from_slice(&(serials.len() as u32).to_be_bytes());
        for serial in serials {
            out.extend_from_slice(&(serial.len() as u32).to_be_bytes());
            out.extend_from_slice(&serial);
        }
        out
    }
}

/// Deterministic OCSP fixture specification.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspSpec {
    pub responder_kind: OcspResponderKind,
    pub produced_at: TimeOffsetDays,
    pub this_update: TimeOffsetDays,
    pub next_update: Option<TimeOffsetDays>,
    pub cert_status: OcspCertStatus,
    pub revocation_reason: Option<RevocationReasonCode>,
    pub nonce_policy: OcspNoncePolicy,
}

impl OcspSpec {
    pub fn for_issuer(status: OcspCertStatus) -> Self {
        Self {
            responder_kind: OcspResponderKind::Issuer,
            produced_at: TimeOffsetDays::from_base(0),
            this_update: TimeOffsetDays::from_base(0),
            next_update: Some(TimeOffsetDays::from_base(7)),
            cert_status: status,
            revocation_reason: match status {
                OcspCertStatus::Revoked => Some(RevocationReasonCode::KeyCompromise),
                _ => None,
            },
            nonce_policy: OcspNoncePolicy::Deterministic,
        }
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1);
        out.push(match self.responder_kind {
            OcspResponderKind::Issuer => 1,
            OcspResponderKind::Root => 2,
            OcspResponderKind::Intermediate => 3,
        });
        out.extend_from_slice(&self.produced_at.stable_bytes());
        out.extend_from_slice(&self.this_update.stable_bytes());
        match self.next_update {
            None => out.push(0),
            Some(offset) => {
                out.push(1);
                out.extend_from_slice(&offset.stable_bytes());
            }
        }
        out.push(match self.cert_status {
            OcspCertStatus::Good => 1,
            OcspCertStatus::Revoked => 2,
            OcspCertStatus::Unknown => 3,
        });
        out.push(match self.revocation_reason {
            None => 0,
            Some(code) => 1 + reason_code_to_u8(code),
        });
        out.push(match self.nonce_policy {
            OcspNoncePolicy::Absent => 0,
            OcspNoncePolicy::Deterministic => 1,
        });
        out
    }
}

fn reason_code_to_u8(code: RevocationReasonCode) -> u8 {
    match code {
        RevocationReasonCode::Unspecified => 0,
        RevocationReasonCode::KeyCompromise => 1,
        RevocationReasonCode::CaCompromise => 2,
        RevocationReasonCode::AffiliationChanged => 3,
        RevocationReasonCode::Superseded => 4,
        RevocationReasonCode::CessationOfOperation => 5,
        RevocationReasonCode::CertificateHold => 6,
        RevocationReasonCode::PrivilegeWithdrawn => 7,
        RevocationReasonCode::AaCompromise => 8,
    }
}
