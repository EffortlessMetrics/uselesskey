//! X.509 revocation fixture specification models.

/// Issuer identity for CRL fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CrlIssuerKind {
    /// CRL is signed by the root CA.
    Root,
    /// CRL is signed by the intermediate CA.
    Intermediate,
}

/// Revocation reason code for CRL/OCSP fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CrlReasonCode {
    /// No specific reason was supplied.
    Unspecified,
    /// Key compromise.
    KeyCompromise,
    /// CA compromise.
    CaCompromise,
    /// Affiliation changed.
    AffiliationChanged,
    /// Certificate superseded.
    Superseded,
    /// Operation ceased.
    CessationOfOperation,
    /// Certificate hold.
    CertificateHold,
}

impl CrlReasonCode {
    /// Stable byte representation for deterministic derivation.
    pub fn stable_byte(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
        }
    }
}

/// Deterministic CRL generation policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlSpec {
    /// Which issuer signs the CRL.
    pub issuer_kind: CrlIssuerKind,
    /// Offset in days from deterministic base time for `this_update`.
    pub this_update_offset_days: i32,
    /// Offset in days from deterministic base time for `next_update`.
    pub next_update_offset_days: i32,
    /// Which chain serials are listed as revoked ("leaf", "intermediate").
    pub revoked_serials: Vec<String>,
    /// Optional reason code used for each revoked serial.
    pub reason_codes: Vec<CrlReasonCode>,
    /// Whether to include a deterministic CRL number extension.
    pub include_crl_number: bool,
}

impl Default for CrlSpec {
    fn default() -> Self {
        Self {
            issuer_kind: CrlIssuerKind::Intermediate,
            this_update_offset_days: 0,
            next_update_offset_days: 30,
            revoked_serials: vec!["leaf".to_string()],
            reason_codes: vec![CrlReasonCode::KeyCompromise],
            include_crl_number: true,
        }
    }
}

impl CrlSpec {
    /// Stable encoding for cache keys / deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1); // version
        out.push(match self.issuer_kind {
            CrlIssuerKind::Root => 0,
            CrlIssuerKind::Intermediate => 1,
        });
        out.extend_from_slice(&self.this_update_offset_days.to_be_bytes());
        out.extend_from_slice(&self.next_update_offset_days.to_be_bytes());
        out.push(self.include_crl_number as u8);

        out.extend_from_slice(&(self.revoked_serials.len() as u32).to_be_bytes());
        for serial in &self.revoked_serials {
            let bytes = serial.as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }

        out.extend_from_slice(&(self.reason_codes.len() as u32).to_be_bytes());
        for reason in &self.reason_codes {
            out.push(reason.stable_byte());
        }

        out
    }
}

/// OCSP responder identity for deterministic fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OcspResponderKind {
    /// Response signed by root.
    Root,
    /// Response signed by intermediate.
    Intermediate,
}

/// OCSP nonce handling policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NoncePolicy {
    /// No nonce extension.
    Omit,
    /// Include deterministic nonce bytes.
    Deterministic,
}

/// OCSP cert status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CertStatus {
    /// Certificate is valid.
    Good,
    /// Certificate is revoked.
    Revoked,
    /// Certificate status is unknown.
    Unknown,
}

/// Deterministic OCSP fixture generation policy.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspSpec {
    /// Which responder signs the payload.
    pub responder_kind: OcspResponderKind,
    /// Offset in days from deterministic base time for `produced_at`.
    pub produced_at_offset_days: i32,
    /// Offset in days from deterministic base time for `this_update`.
    pub this_update_offset_days: i32,
    /// Offset in days from deterministic base time for `next_update`.
    pub next_update_offset_days: i32,
    /// Certificate status.
    pub cert_status: CertStatus,
    /// Optional revocation reason when status is `Revoked`.
    pub revocation_reason: Option<CrlReasonCode>,
    /// Nonce behavior.
    pub nonce_policy: NoncePolicy,
}

impl Default for OcspSpec {
    fn default() -> Self {
        Self {
            responder_kind: OcspResponderKind::Intermediate,
            produced_at_offset_days: 0,
            this_update_offset_days: 0,
            next_update_offset_days: 7,
            cert_status: CertStatus::Good,
            revocation_reason: None,
            nonce_policy: NoncePolicy::Omit,
        }
    }
}

impl OcspSpec {
    /// Stable encoding for cache keys / deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1); // version
        out.push(match self.responder_kind {
            OcspResponderKind::Root => 0,
            OcspResponderKind::Intermediate => 1,
        });
        out.extend_from_slice(&self.produced_at_offset_days.to_be_bytes());
        out.extend_from_slice(&self.this_update_offset_days.to_be_bytes());
        out.extend_from_slice(&self.next_update_offset_days.to_be_bytes());
        out.push(match self.cert_status {
            CertStatus::Good => 0,
            CertStatus::Revoked => 1,
            CertStatus::Unknown => 2,
        });
        match self.revocation_reason {
            None => out.push(0),
            Some(reason) => {
                out.push(1);
                out.push(reason.stable_byte());
            }
        }
        out.push(match self.nonce_policy {
            NoncePolicy::Omit => 0,
            NoncePolicy::Deterministic => 1,
        });
        out
    }
}
