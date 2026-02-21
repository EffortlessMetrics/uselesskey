use std::fmt;
use std::sync::Arc;

use rsa::pkcs8::LineEnding;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey};
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;

use crate::RsaSpec;

/// Cache domain for RSA keypair fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_RSA_KEYPAIR: &str = "uselesskey:rsa:keypair";

/// An RSA keypair fixture with various output formats.
///
/// Created via [`RsaFactoryExt::rsa()`]. Provides access to:
/// - Private key in PKCS#8 PEM and DER formats
/// - Public key in SPKI PEM and DER formats
/// - Negative fixtures (corrupted PEM, truncated DER, mismatched keys)
/// - JWK output (with the `jwk` feature)
///
/// # Examples
///
/// ```
/// use uselesskey_core::Factory;
/// use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
///
/// let fx = Factory::random();
/// let keypair = fx.rsa("my-service", RsaSpec::rs256());
///
/// // Access key material
/// let private_pem = keypair.private_key_pkcs8_pem();
/// let public_der = keypair.public_key_spki_der();
///
/// assert!(private_pem.contains("BEGIN PRIVATE KEY"));
/// assert!(!public_der.is_empty());
/// ```
#[derive(Clone)]
pub struct RsaKeyPair {
    factory: Factory,
    label: String,
    spec: RsaSpec,
    inner: Arc<Inner>,
}

struct Inner {
    /// Kept for potential signing methods; not currently used.
    _private: RsaPrivateKey,
    #[cfg(feature = "jwk")]
    public: RsaPublicKey,
    material: Pkcs8SpkiKeyMaterial,
}

impl fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// Extension trait to hang RSA helpers off the core [`Factory`].
pub trait RsaFactoryExt {
    fn rsa(&self, label: impl AsRef<str>, spec: RsaSpec) -> RsaKeyPair;
}

impl RsaFactoryExt for Factory {
    fn rsa(&self, label: impl AsRef<str>, spec: RsaSpec) -> RsaKeyPair {
        RsaKeyPair::new(self.clone(), label.as_ref(), spec)
    }
}

impl RsaKeyPair {
    fn new(factory: Factory, label: &str, spec: RsaSpec) -> Self {
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

    #[cfg(feature = "jwk")]
    fn jwk_alg(&self) -> &'static str {
        match self.spec.bits {
            3072 => "RS384",
            4096 => "RS512",
            _ => "RS256",
        }
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

    /// Public JWK for this keypair (kty=RSA, use=sig, kid=...).
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_jwk(&self) -> uselesskey_jwk::PublicJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa::traits::PublicKeyParts;
        use uselesskey_jwk::{PublicJwk, RsaPublicJwk};

        let n = self.inner.public.n().to_bytes_be();
        let e = self.inner.public.e().to_bytes_be();

        PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: self.jwk_alg(),
            kid: self.kid(),
            n: URL_SAFE_NO_PAD.encode(n),
            e: URL_SAFE_NO_PAD.encode(e),
        })
    }

    /// Private JWK for this keypair (kty=RSA, use=sig, kid=...).
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn private_key_jwk(&self) -> uselesskey_jwk::PrivateJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        use uselesskey_jwk::{PrivateJwk, RsaPrivateJwk};

        let private = &self.inner._private;
        let primes = private.primes();
        assert!(primes.len() >= 2, "expected at least two RSA primes");

        let n = private.n().to_bytes_be();
        let e = private.e().to_bytes_be();
        let d = private.d().to_bytes_be();
        let p = primes[0].to_bytes_be();
        let q = primes[1].to_bytes_be();
        let dp = private.dp().expect("dp").to_bytes_be();
        let dq = private.dq().expect("dq").to_bytes_be();
        let qi = private.qinv().expect("qinv").to_bytes_be().1;

        PrivateJwk::Rsa(RsaPrivateJwk {
            kty: "RSA",
            use_: "sig",
            alg: self.jwk_alg(),
            kid: self.kid(),
            n: URL_SAFE_NO_PAD.encode(n),
            e: URL_SAFE_NO_PAD.encode(e),
            d: URL_SAFE_NO_PAD.encode(d),
            p: URL_SAFE_NO_PAD.encode(p),
            q: URL_SAFE_NO_PAD.encode(q),
            dp: URL_SAFE_NO_PAD.encode(dp),
            dq: URL_SAFE_NO_PAD.encode(dq),
            qi: URL_SAFE_NO_PAD.encode(qi),
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

fn load_inner(factory: &Factory, label: &str, spec: RsaSpec, variant: &str) -> Arc<Inner> {
    // Validate what we can, up front.
    assert!(
        spec.bits >= 1024,
        "RSA bits too small for most parsers; got {}",
        spec.bits
    );
    assert!(
        spec.exponent == 65537,
        "custom RSA public exponent not supported in v1; got {}",
        spec.exponent
    );

    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_RSA_KEYPAIR, label, &spec_bytes, variant, |rng| {
        let private = RsaPrivateKey::new(rng, spec.bits).expect("RSA keygen failed");
        let public = RsaPublicKey::from(&private);

        let pkcs8_der_doc = private
            .to_pkcs8_der()
            .expect("failed to encode RSA private key as PKCS#8 DER");
        let pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der_doc.as_bytes());

        let pkcs8_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("failed to encode RSA private key as PKCS#8 PEM")
            .to_string();

        let spki_der_doc = public
            .to_public_key_der()
            .expect("failed to encode RSA public key as SPKI DER");
        let spki_der: Arc<[u8]> = Arc::from(spki_der_doc.as_bytes());

        let spki_pem = public
            .to_public_key_pem(LineEnding::LF)
            .expect("failed to encode RSA public key as SPKI PEM")
            .to_string();

        let material = Pkcs8SpkiKeyMaterial::new(pkcs8_der, pkcs8_pem, spki_der, spki_pem);

        Inner {
            _private: private,
            #[cfg(feature = "jwk")]
            public,
            material,
        }
    })
}
