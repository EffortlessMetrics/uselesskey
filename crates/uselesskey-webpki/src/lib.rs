#![forbid(unsafe_code)]

//! webpki adapters for uselesskey X.509 fixtures.
//!
//! This crate only converts and verifies existing fixture certificate bytes.

use rustls_pki_types::UnixTime;
use webpki::{EndEntityCert, TrustAnchor};

#[cfg(feature = "x509")]
pub trait WebPkiX509Ext {
    fn webpki_end_entity(&self) -> EndEntityCert<'_>;
    fn webpki_intermediates(&self) -> Vec<&[u8]>;
    fn webpki_root_anchor(&self) -> TrustAnchor<'_>;

    fn verify_tls_server_cert_webpki(&self, server_name: &str, now: UnixTime) -> Result<(), webpki::Error>;
}

#[cfg(feature = "x509")]
impl WebPkiX509Ext for uselesskey_x509::X509Chain {
    fn webpki_end_entity(&self) -> EndEntityCert<'_> {
        EndEntityCert::try_from(self.leaf_cert_der()).expect("valid leaf cert der")
    }

    fn webpki_intermediates(&self) -> Vec<&[u8]> {
        vec![self.intermediate_cert_der()]
    }

    fn webpki_root_anchor(&self) -> TrustAnchor<'_> {
        TrustAnchor::try_from_cert_der(self.root_cert_der()).expect("valid root cert der")
    }

    fn verify_tls_server_cert_webpki(
        &self,
        server_name: &str,
        now: UnixTime,
    ) -> Result<(), webpki::Error> {
        let end_entity = self.webpki_end_entity();
        let intermediates = self.webpki_intermediates();
        let anchors = [self.webpki_root_anchor()];
        let dns_name = webpki::DnsNameRef::try_from_ascii_str(server_name)
            .map_err(|_| webpki::Error::BadDer)?;

        end_entity.verify_is_valid_tls_server_cert(
            &[&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P384_SHA384, &webpki::ED25519, &webpki::RSA_PKCS1_2048_8192_SHA256],
            &webpki::TlsServerTrustAnchors(&anchors),
            &intermediates,
            webpki::Time::from_seconds_since_unix_epoch(now.as_secs()),
        )?;

        end_entity.verify_is_valid_for_dns_name(dns_name)
    }
}
