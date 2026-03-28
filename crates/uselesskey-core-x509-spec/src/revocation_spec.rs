//! Deterministic revocation fixture models for X.509 test artifacts.

/// Which certificate/key identity signs or responds for a revocation artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RevocationIssuerKind {
    /// Use the root CA from the chain.
    Root,
    /// Use the intermediate CA from the chain.
    Intermediate,
}

impl RevocationIssuerKind {
    fn tag(self) -> u8 {
        match self {
            Self::Root => 0,
            Self::Intermediate => 1,
        }
    }
}

/// Supported revocation reason codes for deterministic fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RevocationReasonCode {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevocationReasonCode {
    fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }
}

/// Deterministic CRL fixture options.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlSpec {
    pub issuer_kind: RevocationIssuerKind,
    pub this_update_days_offset: i32,
    pub next_update_days_offset: i32,
    pub revoked_serials: Vec<Vec<u8>>,
    pub reason_codes: Vec<RevocationReasonCode>,
    pub crl_number: u64,
}

impl CrlSpec {
    pub fn for_chain_default() -> Self {
        Self {
            issuer_kind: RevocationIssuerKind::Intermediate,
            this_update_days_offset: 0,
            next_update_days_offset: 30,
            revoked_serials: Vec::new(),
            reason_codes: vec![RevocationReasonCode::KeyCompromise],
            crl_number: 1,
        }
    }

    /// Stable encoding used by deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = vec![1, self.issuer_kind.tag()];
        out.extend_from_slice(&self.this_update_days_offset.to_be_bytes());
        out.extend_from_slice(&self.next_update_days_offset.to_be_bytes());
        out.extend_from_slice(&self.crl_number.to_be_bytes());

        out.extend_from_slice(&(self.revoked_serials.len() as u32).to_be_bytes());
        for serial in &self.revoked_serials {
            out.extend_from_slice(&(serial.len() as u32).to_be_bytes());
            out.extend_from_slice(serial);
        }

        out.extend_from_slice(&(self.reason_codes.len() as u32).to_be_bytes());
        for reason in &self.reason_codes {
            out.push(reason.code());
        }

        out
    }
}

/// OCSP status selection for deterministic fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

impl OcspCertStatus {
    fn tag(self) -> u8 {
        match self {
            Self::Good => 0,
            Self::Revoked => 1,
            Self::Unknown => 2,
        }
    }
}

/// OCSP nonce inclusion policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OcspNoncePolicy {
    None,
    Deterministic,
}

impl OcspNoncePolicy {
    fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Deterministic => 1,
        }
    }
}

/// Deterministic OCSP fixture options.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspSpec {
    pub responder_kind: RevocationIssuerKind,
    pub produced_at_days_offset: i32,
    pub this_update_days_offset: i32,
    pub next_update_days_offset: i32,
    pub cert_status: OcspCertStatus,
    pub revocation_reason: Option<RevocationReasonCode>,
    pub nonce_policy: OcspNoncePolicy,
}

impl OcspSpec {
    pub fn for_chain_default(status: OcspCertStatus) -> Self {
        Self {
            responder_kind: RevocationIssuerKind::Intermediate,
            produced_at_days_offset: 0,
            this_update_days_offset: 0,
            next_update_days_offset: 1,
            cert_status: status,
            revocation_reason: Some(RevocationReasonCode::KeyCompromise),
            nonce_policy: OcspNoncePolicy::Deterministic,
        }
    }

    /// Stable encoding used by deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = vec![1, self.responder_kind.tag()];
        out.extend_from_slice(&self.produced_at_days_offset.to_be_bytes());
        out.extend_from_slice(&self.this_update_days_offset.to_be_bytes());
        out.extend_from_slice(&self.next_update_days_offset.to_be_bytes());
        out.push(self.cert_status.tag());
        match self.revocation_reason {
            None => out.push(0),
            Some(reason) => {
                out.push(1);
                out.push(reason.code());
            }
        }
        out.push(self.nonce_policy.tag());
        out
    }
}
