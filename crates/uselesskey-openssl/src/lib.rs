#![forbid(unsafe_code)]

//! OpenSSL adapters for uselesskey test fixtures.
//!
//! This crate converts fixture outputs from uselesskey into OpenSSL-native
//! key/certificate types without generating new key material.

#[cfg(feature = "ed25519")]
use openssl::pkey::Id;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509StoreContext, X509};

#[cfg(feature = "rsa")]
pub trait OpensslRsaExt {
    fn private_key_openssl(&self) -> PKey<Private>;
}

#[cfg(feature = "rsa")]
impl OpensslRsaExt for uselesskey_rsa::RsaKeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der()).expect("valid RSA PKCS#8")
    }
}

#[cfg(feature = "ecdsa")]
pub trait OpensslEcdsaExt {
    fn private_key_openssl(&self) -> PKey<Private>;
}

#[cfg(feature = "ecdsa")]
impl OpensslEcdsaExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.private_key_pkcs8_der())
            .expect("valid ECDSA PKCS#8 DER")
    }
}

#[cfg(feature = "ed25519")]
pub trait OpensslEd25519Ext {
    fn private_key_openssl(&self) -> PKey<Private>;
}

#[cfg(feature = "ed25519")]
impl OpensslEd25519Ext for uselesskey_ed25519::Ed25519KeyPair {
    fn private_key_openssl(&self) -> PKey<Private> {
        let pkey = PKey::private_key_from_der(self.private_key_pkcs8_der())
            .expect("valid Ed25519 PKCS#8 DER");
        assert_eq!(pkey.id(), Id::ED25519, "fixture must decode as Ed25519");
        pkey
    }
}

#[cfg(feature = "x509")]
pub trait OpensslX509Ext {
    fn cert_openssl(&self) -> X509;
}

#[cfg(feature = "x509")]
impl OpensslX509Ext for uselesskey_x509::X509Cert {
    fn cert_openssl(&self) -> X509 {
        X509::from_der(self.cert_der()).expect("valid X.509 DER")
    }
}

#[cfg(feature = "x509")]
pub trait OpensslChainExt {
    fn leaf_cert_openssl(&self) -> X509;
    fn intermediate_cert_openssl(&self) -> X509;
    fn root_cert_openssl(&self) -> X509;
    fn leaf_private_key_openssl(&self) -> PKey<Private>;
}

#[cfg(feature = "x509")]
impl OpensslChainExt for uselesskey_x509::X509Chain {
    fn leaf_cert_openssl(&self) -> X509 {
        X509::from_der(self.leaf_cert_der()).expect("valid leaf X.509 DER")
    }

    fn intermediate_cert_openssl(&self) -> X509 {
        X509::from_der(self.intermediate_cert_der()).expect("valid intermediate X.509 DER")
    }

    fn root_cert_openssl(&self) -> X509 {
        X509::from_der(self.root_cert_der()).expect("valid root X.509 DER")
    }

    fn leaf_private_key_openssl(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.leaf_private_key_pkcs8_der())
            .expect("valid leaf PKCS#8 key DER")
    }
}

#[cfg(feature = "x509")]
pub fn verify_chain(chain: &uselesskey_x509::X509Chain) -> bool {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;

    let root = chain.root_cert_openssl();
    let intermediate = chain.intermediate_cert_openssl();
    let leaf = chain.leaf_cert_openssl();

    let mut store = X509StoreBuilder::new().expect("create store");
    store.add_cert(root).expect("add root");
    let store = store.build();

    let mut stack = Stack::new().expect("create stack");
    stack.push(intermediate).expect("push intermediate");

    let mut ctx = X509StoreContext::new().expect("create store context");
    ctx.init(&store, &leaf, &stack, |c| c.verify_cert())
        .expect("verify call should execute")
}
