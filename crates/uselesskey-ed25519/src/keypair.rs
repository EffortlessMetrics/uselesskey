use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey, SigningKey, VerifyingKey};
use pkcs8::LineEnding;
use rand_core::RngCore;
use uselesskey_core::negative::{corrupt_pem, truncate_der, CorruptPem};
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};

use crate::Ed25519Spec;

/// Cache domain for Ed25519 keypair fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_ED25519_KEYPAIR: &str = "uselesskey:ed25519:keypair";

#[derive(Clone)]
pub struct Ed25519KeyPair {
    factory: Factory,
    label: String,
    spec: Ed25519Spec,
    inner: Arc<Inner>,
}

struct Inner {
    /// Kept for potential signing methods; not currently used.
    _private: SigningKey,
    public: VerifyingKey,
    pkcs8_der: Arc<[u8]>,
    pkcs8_pem: String,
    spki_der: Arc<[u8]>,
    spki_pem: String,
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// Extension trait to hang Ed25519 helpers off the core [`Factory`].
pub trait Ed25519FactoryExt {
    fn ed25519(&self, label: impl AsRef<str>, spec: Ed25519Spec) -> Ed25519KeyPair;
}

impl Ed25519FactoryExt for Factory {
    fn ed25519(&self, label: impl AsRef<str>, spec: Ed25519Spec) -> Ed25519KeyPair {
        Ed25519KeyPair::new(self.clone(), label.as_ref(), spec)
    }
}

impl Ed25519KeyPair {
    fn new(factory: Factory, label: &str, spec: Ed25519Spec) -> Self {
        let inner = load_inner(&factory, label, spec, "good");
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    fn load_variant(&self, variant: &str) -> Arc<Inner> {
        load_inner(&self.factory, &self.label, self.spec, variant)
    }

    /// PKCS#8 DER-encoded private key bytes.
    pub fn private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.pkcs8_der
    }

    /// PKCS#8 PEM-encoded private key.
    pub fn private_key_pkcs8_pem(&self) -> &str {
        &self.inner.pkcs8_pem
    }

    /// SPKI DER-encoded public key bytes.
    pub fn public_key_spki_der(&self) -> &[u8] {
        &self.inner.spki_der
    }

    /// SPKI PEM-encoded public key.
    pub fn public_key_spki_pem(&self) -> &str {
        &self.inner.spki_pem
    }

    /// Write the PKCS#8 PEM private key to a tempfile and return the handle.
    pub fn write_private_key_pkcs8_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".pkcs8.pem", self.private_key_pkcs8_pem())
    }

    /// Write the SPKI PEM public key to a tempfile and return the handle.
    pub fn write_public_key_spki_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".spki.pem", self.public_key_spki_pem())
    }

    /// Produce a corrupted variant of the PKCS#8 PEM.
    pub fn private_key_pkcs8_pem_corrupt(&self, how: CorruptPem) -> String {
        corrupt_pem(self.private_key_pkcs8_pem(), how)
    }

    /// Produce a truncated variant of the PKCS#8 DER.
    pub fn private_key_pkcs8_der_truncated(&self, len: usize) -> Vec<u8> {
        truncate_der(self.private_key_pkcs8_der(), len)
    }

    /// Return a valid (parseable) public key that does *not* match this private key.
    pub fn mismatched_public_key_spki_der(&self) -> Vec<u8> {
        let other = self.load_variant("mismatch");
        other.spki_der.as_ref().to_vec()
    }

    /// A stable key identifier derived from the public key (base64url blake3 hash prefix).
    #[cfg(feature = "jwk")]
    pub fn kid(&self) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let h = blake3::hash(self.public_key_spki_der());
        let short = &h.as_bytes()[..12]; // 96 bits is plenty for tests.
        URL_SAFE_NO_PAD.encode(short)
    }

    /// Public JWK for this keypair (kty=OKP, crv=Ed25519, use=sig, kid=...).
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_jwk(&self) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        // Ed25519 public key is 32 bytes
        let x = self.inner.public.as_bytes();

        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": self.kid(),
            "x": URL_SAFE_NO_PAD.encode(x),
        })
    }

    /// JWKS containing a single public key.
    #[cfg(feature = "jwk")]
    pub fn public_jwks(&self) -> serde_json::Value {
        serde_json::json!({ "keys": [ self.public_jwk() ] })
    }
}

fn load_inner(factory: &Factory, label: &str, spec: Ed25519Spec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_ED25519_KEYPAIR, label, &spec_bytes, variant, |rng| {
        // Generate 32 random bytes for Ed25519 secret key
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);

        let private = SigningKey::from_bytes(&secret_bytes);
        let public = private.verifying_key();

        let pkcs8_der_doc = private
            .to_pkcs8_der()
            .expect("failed to encode Ed25519 private key as PKCS#8 DER");
        let pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der_doc.as_bytes());

        let pkcs8_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("failed to encode Ed25519 private key as PKCS#8 PEM")
            .to_string();

        let spki_der_doc = public
            .to_public_key_der()
            .expect("failed to encode Ed25519 public key as SPKI DER");
        let spki_der: Arc<[u8]> = Arc::from(spki_der_doc.as_ref());

        let spki_pem = public
            .to_public_key_pem(LineEnding::LF)
            .expect("failed to encode Ed25519 public key as SPKI PEM");

        Inner {
            _private: private,
            public,
            pkcs8_der,
            pkcs8_pem,
            spki_der,
            spki_pem,
        }
    })
}
