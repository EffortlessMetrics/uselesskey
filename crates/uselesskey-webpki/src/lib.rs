#![forbid(unsafe_code)]

//! webpki adapters for uselesskey X.509 fixtures.

use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

pub fn root_cert_der_owned(chain: &uselesskey_x509::X509Chain) -> CertificateDer<'static> {
    CertificateDer::from(chain.root_cert_der().to_vec())
}

pub fn verify_server_cert(
    chain: &uselesskey_x509::X509Chain,
    host: &str,
) -> Result<(), webpki::Error> {
    let leaf = CertificateDer::from(chain.leaf_cert_der());
    let end_entity = webpki::EndEntityCert::try_from(&leaf)?;

    let intermediate = CertificateDer::from(chain.intermediate_cert_der());
    let intermediates = [intermediate];

    let root_cert = root_cert_der_owned(chain);
    let anchor = webpki::anchor_from_trusted_cert(&root_cert)?;
    let anchors = [anchor];

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
        ServerName::try_from(host.to_owned()).map_err(|_| webpki::Error::MalformedDnsIdentifier)?;
    end_entity.verify_is_valid_for_subject_name(&server_name)
}
