#![forbid(unsafe_code)]

//! OpenSSL adapters for uselesskey fixtures.
//!
//! This crate converts existing uselesskey fixture material into OpenSSL-native
//! types for test harnesses that still use OpenSSL APIs.

#[cfg(any(feature = "rsa", feature = "ecdsa", feature = "ed25519", feature = "x509"))]
use openssl::pkey::{PKey, Private, Public};
#[cfg(any(feature = "rsa", feature = "ecdsa", feature = "ed25519", feature = "x509"))]
use openssl::x509::X509;

/// Parse private/public keys into OpenSSL native `PKey` values.
#[cfg(any(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
pub trait OpensslKeyExt {
    /// Convert PKCS#8 private key DER into `openssl::pkey::PKey<Private>`.
    fn private_key_openssl(&self) -> PKey<Private>;

    /// Convert SPKI public key DER into `openssl::pkey::PKey<Public>`.
    fn public_key_openssl(&self) -> PKey<Public>;
}

#[cfg(feature = "rsa")]
impl OpensslKeyExt for uselesskey_rsa::RsaKeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid RSA PKCS#8 key")
    }

    fn public_key_openssl(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid RSA SPKI key")
    }
}

#[cfg(feature = "ecdsa")]
impl OpensslKeyExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der())
            .expect("valid ECDSA PKCS#8 key")
    }

    fn public_key_openssl(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid ECDSA SPKI key")
    }
}

#[cfg(feature = "ed25519")]
impl OpensslKeyExt for uselesskey_ed25519::Ed25519KeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("valid Ed25519 PKCS#8 PEM key")
    }

    fn public_key_openssl(&self) -> PKey<Public> {
        PKey::public_key_from_pem(self.public_key_spki_pem().as_bytes())
            .expect("valid Ed25519 SPKI PEM key")
    }
}

/// Convert X.509 fixtures into OpenSSL certificate/key chain types.
#[cfg(feature = "x509")]
pub trait OpensslX509Ext {
    /// Convert fixture leaf cert into `openssl::x509::X509`.
    fn leaf_cert_openssl(&self) -> X509;

    /// Convert fixture chain into leaf + intermediates (no root).
    fn chain_openssl(&self) -> Vec<X509>;

    /// Convert fixture trust/root cert into `openssl::x509::X509`.
    fn root_cert_openssl(&self) -> X509;

    /// Convert leaf private key into `openssl::pkey::PKey<Private>`.
    fn leaf_private_key_openssl(&self) -> PKey<Private>;
}

#[cfg(feature = "x509")]
impl OpensslX509Ext for uselesskey_x509::X509Cert {
    fn leaf_cert_openssl(&self) -> X509 {
        X509::from_der(self.cert_der()).expect("valid DER certificate")
    }

    fn chain_openssl(&self) -> Vec<X509> {
        vec![self.leaf_cert_openssl()]
    }

    fn root_cert_openssl(&self) -> X509 {
        self.leaf_cert_openssl()
    }

    fn leaf_private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der())
            .expect("valid PKCS#8 private key")
    }
}

#[cfg(feature = "x509")]
impl OpensslX509Ext for uselesskey_x509::X509Chain {
    fn leaf_cert_openssl(&self) -> X509 {
        X509::from_der(self.leaf_cert_der()).expect("valid leaf DER certificate")
    }

    fn chain_openssl(&self) -> Vec<X509> {
        vec![
            X509::from_der(self.leaf_cert_der()).expect("valid leaf DER certificate"),
            X509::from_der(self.intermediate_cert_der())
                .expect("valid intermediate DER certificate"),
        ]
    }

    fn root_cert_openssl(&self) -> X509 {
        X509::from_der(self.root_cert_der()).expect("valid root DER certificate")
    }

    fn leaf_private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.leaf_private_key_pkcs8_der())
            .expect("valid leaf PKCS#8 private key")
    }
}

/// Sign/verify helper operations using OpenSSL EVP.
#[cfg(any(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
pub trait OpensslSignVerifyExt: OpensslKeyExt {
    /// Sign message bytes with SHA-256 when applicable.
    fn sign_sha256_openssl(&self, message: &[u8]) -> Vec<u8>;

    /// Verify signature for message bytes with SHA-256 when applicable.
    fn verify_sha256_openssl(&self, message: &[u8], signature: &[u8]) -> bool;
}

#[cfg(feature = "rsa")]
impl OpensslSignVerifyExt for uselesskey_rsa::RsaKeyPair {
    fn sign_sha256_openssl(&self, message: &[u8]) -> Vec<u8> {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;

        let key = self.private_key_openssl();
        let mut signer = Signer::new(MessageDigest::sha256(), &key).expect("valid signer");
        signer.update(message).expect("signer update");
        signer.sign_to_vec().expect("sign success")
    }

    fn verify_sha256_openssl(&self, message: &[u8], signature: &[u8]) -> bool {
        use openssl::hash::MessageDigest;
        use openssl::sign::Verifier;

        let key = self.public_key_openssl();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).expect("valid verifier");
        verifier.update(message).expect("verifier update");
        verifier.verify(signature).unwrap_or(false)
    }
}

#[cfg(feature = "ecdsa")]
impl OpensslSignVerifyExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn sign_sha256_openssl(&self, message: &[u8]) -> Vec<u8> {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;

        let digest = if self.spec().curve_name() == "P-384" {
            MessageDigest::sha384()
        } else {
            MessageDigest::sha256()
        };
        let key = self.private_key_openssl();
        let mut signer = Signer::new(digest, &key).expect("valid signer");
        signer.update(message).expect("signer update");
        signer.sign_to_vec().expect("sign success")
    }

    fn verify_sha256_openssl(&self, message: &[u8], signature: &[u8]) -> bool {
        use openssl::hash::MessageDigest;
        use openssl::sign::Verifier;

        let digest = if self.spec().curve_name() == "P-384" {
            MessageDigest::sha384()
        } else {
            MessageDigest::sha256()
        };
        let key = self.public_key_openssl();
        let mut verifier = Verifier::new(digest, &key).expect("valid verifier");
        verifier.update(message).expect("verifier update");
        verifier.verify(signature).unwrap_or(false)
    }
}

#[cfg(feature = "ed25519")]
impl OpensslSignVerifyExt for uselesskey_ed25519::Ed25519KeyPair {
    fn sign_sha256_openssl(&self, message: &[u8]) -> Vec<u8> {
        use openssl::sign::Signer;

        let key = self.private_key_openssl();
        let mut signer = Signer::new_without_digest(&key).expect("valid ed25519 signer");
        signer.sign_oneshot_to_vec(message).expect("sign success")
    }

    fn verify_sha256_openssl(&self, message: &[u8], signature: &[u8]) -> bool {
        use openssl::sign::Verifier;

        let key = self.public_key_openssl();
        let mut verifier = Verifier::new_without_digest(&key).expect("valid ed25519 verifier");
        verifier.verify_oneshot(signature, message).unwrap_or(false)
    }
}
