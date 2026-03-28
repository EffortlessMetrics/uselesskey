#![forbid(unsafe_code)]

//! webpki verification helpers for uselesskey X.509 fixtures.
//!
//! This crate provides thin adapter helpers for trust-anchor conversion and
//! end-entity verification against uselesskey-generated certificate fixtures.

#[cfg(feature = "x509")]
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(feature = "x509")]
use webpki::{EndEntityCert, Error, KeyUsage, anchor_from_trusted_cert};

/// Verify X.509 fixtures with `rustls-webpki`.
#[cfg(feature = "x509")]
pub trait WebPkiX509Ext {
    /// Verify a server certificate chain for a DNS name at the supplied time.
    fn verify_server_cert_webpki(&self, dns_name: &str, time: UnixTime) -> Result<(), Error>;
}

#[cfg(feature = "x509")]
impl WebPkiX509Ext for uselesskey_x509::X509Cert {
    fn verify_server_cert_webpki(&self, dns_name: &str, time: UnixTime) -> Result<(), Error> {
        let leaf = CertificateDer::from(self.cert_der());
        let anchor = anchor_from_trusted_cert(&leaf)?;
        let anchors = [anchor];
        let intermediates: [CertificateDer<'_>; 0] = [];

        let cert = EndEntityCert::try_from(&leaf)?;
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )?;

        let server_name = ServerName::try_from(dns_name).map_err(|_| Error::MalformedDnsIdentifier)?;
        cert.verify_is_valid_for_subject_name(&server_name)
    }
}

#[cfg(feature = "x509")]
impl WebPkiX509Ext for uselesskey_x509::X509Chain {
    fn verify_server_cert_webpki(&self, dns_name: &str, time: UnixTime) -> Result<(), Error> {
        let leaf_der = CertificateDer::from(self.leaf_cert_der());
        let intermediates = vec![CertificateDer::from(self.intermediate_cert_der())];
        let root_der = CertificateDer::from(self.root_cert_der());
        let anchor = anchor_from_trusted_cert(&root_der)?;
        let anchors = [anchor];

        let cert = EndEntityCert::try_from(&leaf_der)?;
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )?;

        let server_name = ServerName::try_from(dns_name).map_err(|_| Error::MalformedDnsIdentifier)?;
        cert.verify_is_valid_for_subject_name(&server_name)
    }
}
