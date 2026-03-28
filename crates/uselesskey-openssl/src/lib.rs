#![forbid(unsafe_code)]

//! OpenSSL native-type conversions for uselesskey fixtures.

use openssl::pkey::{PKey, Private};

#[cfg(any(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
use openssl::pkey::Public;
#[cfg(any(feature = "rsa", feature = "ecdsa"))]
use openssl::hash::MessageDigest;
#[cfg(any(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
use openssl::sign::{Signer, Verifier};

#[cfg(feature = "rsa")]
pub trait OpenSslRsaExt {
    fn private_key_openssl(&self) -> PKey<Private>;
    fn public_key_openssl(&self) -> PKey<Public>;
    fn sign_sha256_openssl(&self, msg: &[u8]) -> Vec<u8> {
        let key = self.private_key_openssl();
        let mut signer = Signer::new(MessageDigest::sha256(), &key).expect("openssl signer");
        signer.update(msg).expect("signer update");
        signer.sign_to_vec().expect("sign")
    }
    fn verify_sha256_openssl(&self, msg: &[u8], signature: &[u8]) -> bool {
        let key = self.public_key_openssl();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).expect("openssl verifier");
        verifier.update(msg).expect("verifier update");
        verifier.verify(signature).unwrap_or(false)
    }
}

#[cfg(feature = "rsa")]
impl OpenSslRsaExt for uselesskey_rsa::RsaKeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid PKCS#8 DER")
    }

    fn public_key_openssl(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid SPKI DER")
    }
}

#[cfg(feature = "ecdsa")]
pub trait OpenSslEcdsaExt {
    fn private_key_openssl(&self) -> PKey<Private>;
    fn public_key_openssl(&self) -> PKey<Public>;
    fn sign_sha256_openssl(&self, msg: &[u8]) -> Vec<u8>;
    fn verify_openssl(&self, msg: &[u8], signature: &[u8]) -> bool;
}

#[cfg(feature = "ecdsa")]
impl OpenSslEcdsaExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid PKCS#8 DER")
    }

    fn public_key_openssl(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid SPKI DER")
    }

    fn sign_sha256_openssl(&self, msg: &[u8]) -> Vec<u8> {
        let key = self.private_key_openssl();
        let digest = match self.spec() {
            uselesskey_ecdsa::EcdsaSpec::Es256 => MessageDigest::sha256(),
            uselesskey_ecdsa::EcdsaSpec::Es384 => MessageDigest::sha384(),
        };
        let mut signer = Signer::new(digest, &key).expect("openssl signer");
        signer.update(msg).expect("signer update");
        signer.sign_to_vec().expect("sign")
    }

    fn verify_openssl(&self, msg: &[u8], signature: &[u8]) -> bool {
        let key = self.public_key_openssl();
        let digest = match self.spec() {
            uselesskey_ecdsa::EcdsaSpec::Es256 => MessageDigest::sha256(),
            uselesskey_ecdsa::EcdsaSpec::Es384 => MessageDigest::sha384(),
        };
        let mut verifier = Verifier::new(digest, &key).expect("openssl verifier");
        verifier.update(msg).expect("verifier update");
        verifier.verify(signature).unwrap_or(false)
    }
}

#[cfg(feature = "ed25519")]
pub trait OpenSslEd25519Ext {
    fn private_key_openssl(&self) -> PKey<Private>;
    fn public_key_openssl(&self) -> PKey<Public>;
    fn sign_openssl(&self, msg: &[u8]) -> Vec<u8> {
        let key = self.private_key_openssl();
        let mut signer = Signer::new_without_digest(&key).expect("openssl signer");
        signer.sign_oneshot_to_vec(msg).expect("sign")
    }
    fn verify_openssl(&self, msg: &[u8], signature: &[u8]) -> bool {
        let key = self.public_key_openssl();
        let mut verifier = Verifier::new_without_digest(&key).expect("openssl verifier");
        verifier.verify_oneshot(signature, msg).unwrap_or(false)
    }
}

#[cfg(feature = "ed25519")]
impl OpenSslEd25519Ext for uselesskey_ed25519::Ed25519KeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid PKCS#8 DER")
    }

    fn public_key_openssl(&self) -> PKey<Public> {
        PKey::public_key_from_der(self.public_key_spki_der()).expect("valid SPKI DER")
    }
}

#[cfg(feature = "x509")]
pub trait OpenSslX509Ext {
    fn cert_openssl(&self) -> openssl::x509::X509;
    fn private_key_openssl(&self) -> PKey<Private>;
}

#[cfg(feature = "x509")]
impl OpenSslX509Ext for uselesskey_x509::X509Cert {
    fn cert_openssl(&self) -> openssl::x509::X509 {
        openssl::x509::X509::from_der(self.cert_der()).expect("valid cert DER")
    }

    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid PKCS#8 DER")
    }
}

#[cfg(feature = "x509")]
pub trait OpenSslX509ChainExt {
    fn leaf_cert_openssl(&self) -> openssl::x509::X509;
    fn intermediate_cert_openssl(&self) -> openssl::x509::X509;
    fn root_cert_openssl(&self) -> openssl::x509::X509;
    fn leaf_private_key_openssl(&self) -> PKey<Private>;
    fn cert_chain_stack_openssl(&self) -> openssl::stack::Stack<openssl::x509::X509>;
}

#[cfg(feature = "x509")]
impl OpenSslX509ChainExt for uselesskey_x509::X509Chain {
    fn leaf_cert_openssl(&self) -> openssl::x509::X509 {
        openssl::x509::X509::from_der(self.leaf_cert_der()).expect("valid leaf DER")
    }

    fn intermediate_cert_openssl(&self) -> openssl::x509::X509 {
        openssl::x509::X509::from_der(self.intermediate_cert_der()).expect("valid intermediate DER")
    }

    fn root_cert_openssl(&self) -> openssl::x509::X509 {
        openssl::x509::X509::from_der(self.root_cert_der()).expect("valid root DER")
    }

    fn leaf_private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.leaf_private_key_pkcs8_der()).expect("valid leaf PKCS#8 DER")
    }

    fn cert_chain_stack_openssl(&self) -> openssl::stack::Stack<openssl::x509::X509> {
        let mut stack = openssl::stack::Stack::new().expect("stack");
        stack.push(self.intermediate_cert_openssl()).expect("push intermediate");
        stack.push(self.root_cert_openssl()).expect("push root");
        stack
    }
}

#[cfg(test)]
mod tests {
    use uselesskey_core::Factory;

    #[cfg(feature = "rsa")]
    #[test]
    fn rsa_conversion_and_verify() {
        use uselesskey_openssl::OpenSslRsaExt;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let kp = Factory::random().rsa("openssl-rsa", RsaSpec::rs256());
        let sig = kp.sign_sha256_openssl(b"msg");
        assert!(kp.verify_sha256_openssl(b"msg", &sig));
        assert!(!kp.verify_sha256_openssl(b"wrong", &sig));
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn ecdsa_conversion_and_verify() {
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
        use uselesskey_openssl::OpenSslEcdsaExt;

        let kp = Factory::random().ecdsa("openssl-ecdsa", EcdsaSpec::es256());
        let sig = kp.sign_sha256_openssl(b"msg");
        assert!(kp.verify_openssl(b"msg", &sig));
        assert!(!kp.verify_openssl(b"wrong", &sig));
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_conversion_and_verify() {
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
        use uselesskey_openssl::OpenSslEd25519Ext;

        let kp = Factory::random().ed25519("openssl-ed25519", Ed25519Spec::new());
        let sig = kp.sign_openssl(b"msg");
        assert!(kp.verify_openssl(b"msg", &sig));
        assert!(!kp.verify_openssl(b"wrong", &sig));
    }

    #[cfg(feature = "x509")]
    #[test]
    fn x509_chain_conversions_parse() {
        use crate::OpenSslX509ChainExt;
        use uselesskey_x509::{ChainSpec, X509FactoryExt};

        let chain = Factory::random().x509_chain("openssl-chain", ChainSpec::new("svc.example.com"));
        assert!(chain.leaf_cert_openssl().subject_name().entries().next().is_some());
        assert!(chain.root_cert_openssl().subject_name().entries().next().is_some());
        assert!(!chain.cert_chain_stack_openssl().is_empty());
    }
}
