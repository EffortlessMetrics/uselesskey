#![forbid(unsafe_code)]

//! webpki verification helpers for uselesskey X.509 fixtures.

use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use webpki;

pub trait WebPkiChainExt {
    fn verify_leaf_for_server_name_webpki(&self, server_name: &str) -> Result<(), webpki::Error> {
        let leaf = CertificateDer::from(self.leaf_cert_der().to_vec());
        let intermediate = CertificateDer::from(self.intermediate_cert_der().to_vec());
        let root = CertificateDer::from(self.root_cert_der().to_vec());
        let anchors = vec![webpki::anchor_from_trusted_cert(&root)?];
        let intermediates = vec![intermediate];

        let end_entity = webpki::EndEntityCert::try_from(&leaf)?;
        end_entity.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;

        let server_name =
            ServerName::try_from(server_name).map_err(|_| webpki::Error::MalformedDnsIdentifier)?;
        end_entity.verify_is_valid_for_subject_name(&server_name)
    }

    fn verify_leaf_rejected_webpki(&self, server_name: &str) -> bool {
        self.verify_leaf_for_server_name_webpki(server_name)
            .is_err()
    }

    fn leaf_cert_der(&self) -> &[u8];
    fn intermediate_cert_der(&self) -> &[u8];
    fn root_cert_der(&self) -> &[u8];
}

impl WebPkiChainExt for uselesskey_x509::X509Chain {
    fn leaf_cert_der(&self) -> &[u8] {
        self.leaf_cert_der()
    }

    fn intermediate_cert_der(&self) -> &[u8] {
        self.intermediate_cert_der()
    }

    fn root_cert_der(&self) -> &[u8] {
        self.root_cert_der()
    }
}

#[cfg(test)]
mod tests {
    use uselesskey_core::Factory;
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    use crate::WebPkiChainExt;

    #[test]
    fn webpki_accepts_good_chain() {
        let chain = Factory::random().x509_chain("webpki-good", ChainSpec::new("svc.example.com"));
        chain
            .verify_leaf_for_server_name_webpki("svc.example.com")
            .expect("webpki should verify valid chain");
    }

    #[test]
    fn webpki_rejects_hostname_mismatch() {
        let chain =
            Factory::random().x509_chain("webpki-hostname", ChainSpec::new("svc.example.com"));
        assert!(chain.verify_leaf_rejected_webpki("different.example.com"));
    }

    #[test]
    fn webpki_rejects_expired_leaf_variant() {
        let chain =
            Factory::random().x509_chain("webpki-expired", ChainSpec::new("svc.example.com"));
        let expired = chain.expired_leaf();
        assert!(expired.verify_leaf_rejected_webpki("svc.example.com"));
    }
}
