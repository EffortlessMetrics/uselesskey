#![forbid(unsafe_code)]

//! X.509 negative-fixture helpers.
//!
//! This crate keeps certificate-scoped negative fixture adapters separate from
//! certificate generation concerns.

pub use uselesskey_core_x509::X509Negative;

/// Corrupt a PEM-encoded certificate.
pub fn corrupt_cert_pem(pem: &str, how: uselesskey_core::negative::CorruptPem) -> String {
    uselesskey_core::negative::corrupt_pem(pem, how)
}

/// Corrupt a PEM-encoded certificate using a deterministic variant string.
pub fn corrupt_cert_pem_deterministic(pem: &str, variant: &str) -> String {
    uselesskey_core::negative::corrupt_pem_deterministic(pem, variant)
}

/// Truncate a DER-encoded certificate.
pub fn truncate_cert_der(der: &[u8], len: usize) -> Vec<u8> {
    uselesskey_core::negative::truncate_der(der, len)
}

/// Corrupt a DER-encoded certificate using a deterministic variant string.
pub fn corrupt_cert_der_deterministic(der: &[u8], variant: &str) -> Vec<u8> {
    uselesskey_core::negative::corrupt_der_deterministic(der, variant)
}
