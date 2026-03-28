#![forbid(unsafe_code)]

//! OpenSSL adapters for uselesskey test fixtures.
//!
//! This crate only converts existing fixture bytes to native OpenSSL types.
//! It does not generate new key material.

use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    sign::{Signer, Verifier},
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};

#[cfg(feature = "rsa")]
pub trait OpensslRsaExt {
    fn openssl_private_key(&self) -> PKey<Private>;
    fn openssl_public_key(&self) -> PKey<Public>;
}

#[cfg(feature = "rsa")]
impl OpensslRsaExt for uselesskey_rsa::RsaKeyPair {
    fn openssl_private_key(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid RSA PKCS#8 DER")
    }

    fn openssl_public_key(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid RSA SPKI DER")
    }
}

#[cfg(feature = "ecdsa")]
pub trait OpensslEcdsaExt {
    fn openssl_private_key(&self) -> PKey<Private>;
    fn openssl_public_key(&self) -> PKey<Public>;
}

#[cfg(feature = "ecdsa")]
impl OpensslEcdsaExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn openssl_private_key(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid ECDSA PKCS#8 DER")
    }

    fn openssl_public_key(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid ECDSA SPKI DER")
    }
}

#[cfg(feature = "ed25519")]
pub trait OpensslEd25519Ext {
    fn openssl_private_key(&self) -> PKey<Private>;
    fn openssl_public_key(&self) -> PKey<Public>;
}

#[cfg(feature = "ed25519")]
impl OpensslEd25519Ext for uselesskey_ed25519::Ed25519KeyPair {
    fn openssl_private_key(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid Ed25519 PKCS#8 DER")
    }

    fn openssl_public_key(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid Ed25519 SPKI DER")
    }
}

#[cfg(feature = "x509")]
pub trait OpensslX509Ext {
    fn openssl_leaf_cert(&self) -> X509;
    fn openssl_chain_certs(&self) -> Vec<X509>;
    fn openssl_leaf_private_key(&self) -> PKey<Private>;

    fn openssl_server_acceptor(&self) -> Result<SslAcceptor, ErrorStack>;
    fn openssl_client_connector(&self) -> Result<SslConnector, ErrorStack>;
}

#[cfg(feature = "x509")]
impl OpensslX509Ext for uselesskey_x509::X509Chain {
    fn openssl_leaf_cert(&self) -> X509 {
        X509::from_der(self.leaf_cert_der()).expect("valid leaf x509 der")
    }

    fn openssl_chain_certs(&self) -> Vec<X509> {
        vec![
            X509::from_der(self.intermediate_cert_der()).expect("valid intermediate x509 der"),
            X509::from_der(self.root_cert_der()).expect("valid root x509 der"),
        ]
    }

    fn openssl_leaf_private_key(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.leaf_private_key_pkcs8_der()).expect("valid leaf PKCS#8 DER")
    }

    fn openssl_server_acceptor(&self) -> Result<SslAcceptor, ErrorStack> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        builder.set_private_key(&self.openssl_leaf_private_key())?;
        builder.set_certificate(&self.openssl_leaf_cert())?;

        for cert in self.openssl_chain_certs() {
            builder.add_extra_chain_cert(cert)?;
        }

        Ok(builder.build())
    }

    fn openssl_client_connector(&self) -> Result<SslConnector, ErrorStack> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.cert_store_mut().add_cert(
            X509::from_der(self.root_cert_der()).expect("valid root x509 der"),
        )?;
        Ok(builder.build())
    }
}

pub fn openssl_sign(
    key: &PKey<Private>,
    digest: MessageDigest,
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut signer = Signer::new(digest, key)?;
    signer.update(message)?;
    signer.sign_to_vec()
}

pub fn openssl_verify(
    key: &PKey<Public>,
    digest: MessageDigest,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, ErrorStack> {
    let mut verifier = Verifier::new(digest, key)?;
    verifier.update(message)?;
    verifier.verify(signature)
}
