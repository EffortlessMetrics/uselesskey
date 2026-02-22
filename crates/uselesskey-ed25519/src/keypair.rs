use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey};
use pkcs8::LineEnding;
use rand_core::RngCore;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;

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
    #[cfg_attr(not(feature = "jwk"), allow(dead_code))]
    public: VerifyingKey,
    material: Pkcs8SpkiKeyMaterial,
    /// Raw secret bytes (for private JWK).
    #[cfg_attr(not(feature = "jwk"), allow(dead_code))]
    secret_bytes: [u8; 32],
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
        self.inner.material.private_key_pkcs8_der()
    }

    /// PKCS#8 PEM-encoded private key.
    pub fn private_key_pkcs8_pem(&self) -> &str {
        self.inner.material.private_key_pkcs8_pem()
    }

    /// SPKI DER-encoded public key bytes.
    pub fn public_key_spki_der(&self) -> &[u8] {
        self.inner.material.public_key_spki_der()
    }

    /// SPKI PEM-encoded public key.
    pub fn public_key_spki_pem(&self) -> &str {
        self.inner.material.public_key_spki_pem()
    }

    /// Write the PKCS#8 PEM private key to a tempfile and return the handle.
    pub fn write_private_key_pkcs8_pem(&self) -> Result<TempArtifact, Error> {
        self.inner.material.write_private_key_pkcs8_pem()
    }

    /// Write the SPKI PEM public key to a tempfile and return the handle.
    pub fn write_public_key_spki_pem(&self) -> Result<TempArtifact, Error> {
        self.inner.material.write_public_key_spki_pem()
    }

    /// Produce a corrupted variant of the PKCS#8 PEM.
    pub fn private_key_pkcs8_pem_corrupt(&self, how: CorruptPem) -> String {
        self.inner.material.private_key_pkcs8_pem_corrupt(how)
    }

    /// Produce a deterministic corrupted PKCS#8 PEM using a variant string.
    pub fn private_key_pkcs8_pem_corrupt_deterministic(&self, variant: &str) -> String {
        self.inner
            .material
            .private_key_pkcs8_pem_corrupt_deterministic(variant)
    }

    /// Produce a truncated variant of the PKCS#8 DER.
    pub fn private_key_pkcs8_der_truncated(&self, len: usize) -> Vec<u8> {
        self.inner.material.private_key_pkcs8_der_truncated(len)
    }

    /// Produce a deterministic corrupted PKCS#8 DER using a variant string.
    pub fn private_key_pkcs8_der_corrupt_deterministic(&self, variant: &str) -> Vec<u8> {
        self.inner
            .material
            .private_key_pkcs8_der_corrupt_deterministic(variant)
    }

    /// Return a valid (parseable) public key that does *not* match this private key.
    pub fn mismatched_public_key_spki_der(&self) -> Vec<u8> {
        let other = self.load_variant("mismatch");
        other.material.public_key_spki_der().to_vec()
    }

    /// A stable key identifier derived from the public key (base64url blake3 hash prefix).
    #[cfg(feature = "jwk")]
    pub fn kid(&self) -> String {
        self.inner.material.kid()
    }

    /// Alias for [`public_jwk`].
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_key_jwk(&self) -> uselesskey_jwk::PublicJwk {
        self.public_jwk()
    }

    /// Public JWK for this keypair (kty=OKP, crv=Ed25519, use=sig, kid=...).
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_jwk(&self) -> uselesskey_jwk::PublicJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use uselesskey_jwk::{OkpPublicJwk, PublicJwk};

        // Ed25519 public key is 32 bytes
        let x = self.inner.public.as_bytes();

        PublicJwk::Okp(OkpPublicJwk {
            kty: "OKP",
            crv: "Ed25519",
            use_: "sig",
            alg: "EdDSA",
            kid: self.kid(),
            x: URL_SAFE_NO_PAD.encode(x),
        })
    }

    /// Private JWK for this keypair (kty=OKP, crv=Ed25519, d=...).
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn private_key_jwk(&self) -> uselesskey_jwk::PrivateJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use uselesskey_jwk::{OkpPrivateJwk, PrivateJwk};

        let x = self.inner.public.as_bytes();
        let d = &self.inner.secret_bytes;

        PrivateJwk::Okp(OkpPrivateJwk {
            kty: "OKP",
            crv: "Ed25519",
            use_: "sig",
            alg: "EdDSA",
            kid: self.kid(),
            x: URL_SAFE_NO_PAD.encode(x),
            d: URL_SAFE_NO_PAD.encode(d),
        })
    }

    /// JWKS containing a single public key.
    #[cfg(feature = "jwk")]
    pub fn public_jwks(&self) -> uselesskey_jwk::Jwks {
        use uselesskey_jwk::JwksBuilder;

        let mut builder = JwksBuilder::new();
        builder.push_public(self.public_jwk());
        builder.build()
    }

    /// Public JWK serialized to `serde_json::Value`.
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_jwk_json(&self) -> serde_json::Value {
        self.public_jwk().to_value()
    }

    /// JWKS serialized to `serde_json::Value`.
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_jwks_json(&self) -> serde_json::Value {
        self.public_jwks().to_value()
    }

    /// Private JWK serialized to `serde_json::Value`.
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn private_key_jwk_json(&self) -> serde_json::Value {
        self.private_key_jwk().to_value()
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

        let material = Pkcs8SpkiKeyMaterial::new(pkcs8_der, pkcs8_pem, spki_der, spki_pem);

        Inner {
            _private: private,
            public,
            material,
            secret_bytes,
        }
    })
}
