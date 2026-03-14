use std::fmt;
use std::sync::Arc;

use elliptic_curve::{
    Generate,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use rand_chacha10::ChaCha20Rng;
use rand_core10::SeedableRng;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};
use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

use crate::EcdsaSpec;

/// Cache domain for ECDSA keypair fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_ECDSA_KEYPAIR: &str = "uselesskey:ecdsa:keypair";

/// An ECDSA keypair fixture with various output formats.
///
/// Created via [`EcdsaFactoryExt::ecdsa()`]. Provides access to:
/// - Private key in PKCS#8 PEM and DER formats
/// - Public key in SPKI PEM and DER formats
/// - Negative fixtures (corrupted PEM, truncated DER, mismatched keys)
/// - JWK output (with the `jwk` feature)
///
/// # Examples
///
/// ```
/// use uselesskey_core::Factory;
/// use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
///
/// let fx = Factory::random();
/// let keypair = fx.ecdsa("my-service", EcdsaSpec::es256());
///
/// let private_pem = keypair.private_key_pkcs8_pem();
/// let public_der = keypair.public_key_spki_der();
///
/// assert!(private_pem.contains("BEGIN PRIVATE KEY"));
/// assert!(!public_der.is_empty());
/// ```
#[derive(Clone)]
pub struct EcdsaKeyPair {
    factory: Factory,
    label: String,
    spec: EcdsaSpec,
    inner: Arc<Inner>,
}

/// Inner storage for computed key material.
struct Inner {
    /// Kept for potential use; not currently read outside JWK feature.
    #[allow(dead_code)]
    spec: EcdsaSpec,
    material: Pkcs8SpkiKeyMaterial,
    /// Raw public key bytes (uncompressed point, for JWK).
    #[cfg_attr(not(feature = "jwk"), allow(dead_code))]
    public_key_bytes: Vec<u8>,
    /// Raw private scalar bytes (for private JWK).
    #[cfg_attr(not(feature = "jwk"), allow(dead_code))]
    private_key_bytes: Vec<u8>,
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// Extension trait to hang ECDSA helpers off the core [`Factory`].
pub trait EcdsaFactoryExt {
    /// Generate (or retrieve from cache) an ECDSA keypair fixture.
    ///
    /// The `label` identifies this keypair within your test suite.
    /// In deterministic mode, `seed + label + spec` always produces the same key.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::{Factory, Seed};
    /// use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    ///
    /// let seed = Seed::from_env_value("test-seed").unwrap();
    /// let fx = Factory::deterministic(seed);
    /// let keypair = fx.ecdsa("auth-service", EcdsaSpec::es256());
    ///
    /// let pem = keypair.private_key_pkcs8_pem();
    /// assert!(pem.contains("BEGIN PRIVATE KEY"));
    /// ```
    fn ecdsa(&self, label: impl AsRef<str>, spec: EcdsaSpec) -> EcdsaKeyPair;
}

impl EcdsaFactoryExt for Factory {
    fn ecdsa(&self, label: impl AsRef<str>, spec: EcdsaSpec) -> EcdsaKeyPair {
        EcdsaKeyPair::new(self.clone(), label.as_ref(), spec)
    }
}

impl EcdsaKeyPair {
    fn new(factory: Factory, label: &str, spec: EcdsaSpec) -> Self {
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

    /// Returns the spec used to create this keypair.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// assert_eq!(kp.spec(), EcdsaSpec::es256());
    /// ```
    pub fn spec(&self) -> EcdsaSpec {
        self.spec
    }

    /// PKCS#8 DER-encoded private key bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let der = kp.private_key_pkcs8_der();
    /// assert!(!der.is_empty());
    /// ```
    pub fn private_key_pkcs8_der(&self) -> &[u8] {
        self.inner.material.private_key_pkcs8_der()
    }

    /// PKCS#8 PEM-encoded private key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let pem = kp.private_key_pkcs8_pem();
    /// assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    /// ```
    pub fn private_key_pkcs8_pem(&self) -> &str {
        self.inner.material.private_key_pkcs8_pem()
    }

    /// SPKI DER-encoded public key bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let der = kp.public_key_spki_der();
    /// assert!(!der.is_empty());
    /// ```
    pub fn public_key_spki_der(&self) -> &[u8] {
        self.inner.material.public_key_spki_der()
    }

    /// SPKI PEM-encoded public key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let pem = kp.public_key_spki_pem();
    /// assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    /// ```
    pub fn public_key_spki_pem(&self) -> &str {
        self.inner.material.public_key_spki_pem()
    }

    /// Write the PKCS#8 PEM private key to a tempfile and return the handle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let temp = kp.write_private_key_pkcs8_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_private_key_pkcs8_pem(&self) -> Result<TempArtifact, Error> {
        self.inner.material.write_private_key_pkcs8_pem()
    }

    /// Write the SPKI PEM public key to a tempfile and return the handle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let temp = kp.write_public_key_spki_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_public_key_spki_pem(&self) -> Result<TempArtifact, Error> {
        self.inner.material.write_public_key_spki_pem()
    }

    /// Produce a corrupted variant of the PKCS#8 PEM.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_core::negative::CorruptPem;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    /// assert!(bad.contains("CORRUPTED"));
    /// ```
    pub fn private_key_pkcs8_pem_corrupt(&self, how: CorruptPem) -> String {
        self.inner.material.private_key_pkcs8_pem_corrupt(how)
    }

    /// Produce a deterministic corrupted PKCS#8 PEM using a variant string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let bad = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    /// assert!(!bad.is_empty());
    /// ```
    pub fn private_key_pkcs8_pem_corrupt_deterministic(&self, variant: &str) -> String {
        self.inner
            .material
            .private_key_pkcs8_pem_corrupt_deterministic(variant)
    }

    /// Produce a truncated variant of the PKCS#8 DER.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let truncated = kp.private_key_pkcs8_der_truncated(10);
    /// assert_eq!(truncated.len(), 10);
    /// ```
    pub fn private_key_pkcs8_der_truncated(&self, len: usize) -> Vec<u8> {
        self.inner.material.private_key_pkcs8_der_truncated(len)
    }

    /// Produce a deterministic corrupted PKCS#8 DER using a variant string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let bad = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    /// assert!(!bad.is_empty());
    /// ```
    pub fn private_key_pkcs8_der_corrupt_deterministic(&self, variant: &str) -> Vec<u8> {
        self.inner
            .material
            .private_key_pkcs8_der_corrupt_deterministic(variant)
    }

    /// Return a valid (parseable) public key that does *not* match this private key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let wrong_pub = kp.mismatched_public_key_spki_der();
    /// assert_ne!(wrong_pub, kp.public_key_spki_der());
    /// ```
    pub fn mismatched_public_key_spki_der(&self) -> Vec<u8> {
        let other = self.load_variant("mismatch");
        other.material.public_key_spki_der().to_vec()
    }

    /// A stable key identifier derived from the public key (base64url blake3 hash prefix).
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let kid = kp.kid();
    /// assert!(!kid.is_empty());
    /// ```
    #[cfg(feature = "jwk")]
    pub fn kid(&self) -> String {
        self.inner.material.kid()
    }

    /// Alias for [`Self::public_jwk`].
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let jwk = kp.public_key_jwk();
    /// assert_eq!(jwk.to_value()["kty"], "EC");
    /// ```
    #[cfg(feature = "jwk")]
    pub fn public_key_jwk(&self) -> uselesskey_jwk::PublicJwk {
        self.public_jwk()
    }

    /// Public JWK for this keypair (kty=EC, crv=P-256 or P-384, alg=ES256 or ES384).
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let jwk = kp.public_jwk();
    /// let val = jwk.to_value();
    /// assert_eq!(val["kty"], "EC");
    /// assert_eq!(val["crv"], "P-256");
    /// ```
    #[cfg(feature = "jwk")]
    pub fn public_jwk(&self) -> uselesskey_jwk::PublicJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use uselesskey_jwk::{EcPublicJwk, PublicJwk};

        // Public key bytes are in uncompressed form: 0x04 || x || y
        let bytes = &self.inner.public_key_bytes;
        assert_eq!(bytes[0], 0x04, "expected uncompressed point");
        let coord_len = self.spec.coordinate_len_bytes();
        assert_eq!(
            bytes.len(),
            1 + (coord_len * 2),
            "unexpected EC point length for {:?}",
            self.spec
        );
        let x = &bytes[1..1 + coord_len];
        let y = &bytes[1 + coord_len..];

        PublicJwk::Ec(EcPublicJwk {
            kty: "EC",
            use_: "sig",
            alg: self.spec.alg_name(),
            crv: self.spec.curve_name(),
            kid: self.kid(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        })
    }

    /// Private JWK for this keypair (kty=EC, crv=..., alg=..., d=...).
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let jwk = kp.private_key_jwk();
    /// let val = jwk.to_value();
    /// assert_eq!(val["kty"], "EC");
    /// assert!(val["d"].is_string());
    /// ```
    #[cfg(feature = "jwk")]
    pub fn private_key_jwk(&self) -> uselesskey_jwk::PrivateJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use uselesskey_jwk::{EcPrivateJwk, PrivateJwk};

        // Public key bytes are in uncompressed form: 0x04 || x || y
        let bytes = &self.inner.public_key_bytes;
        assert_eq!(bytes[0], 0x04, "expected uncompressed point");
        let coord_len = self.spec.coordinate_len_bytes();
        assert_eq!(
            bytes.len(),
            1 + (coord_len * 2),
            "unexpected EC point length for {:?}",
            self.spec
        );
        let x = &bytes[1..1 + coord_len];
        let y = &bytes[1 + coord_len..];

        PrivateJwk::Ec(EcPrivateJwk {
            kty: "EC",
            use_: "sig",
            alg: self.spec.alg_name(),
            crv: self.spec.curve_name(),
            kid: self.kid(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
            d: URL_SAFE_NO_PAD.encode(&self.inner.private_key_bytes),
        })
    }

    /// JWKS containing a single public key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let jwks = kp.public_jwks();
    /// assert!(jwks.to_value()["keys"].is_array());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let val = kp.public_jwk_json();
    /// assert_eq!(val["kty"], "EC");
    /// ```
    #[cfg(feature = "jwk")]
    pub fn public_jwk_json(&self) -> serde_json::Value {
        self.public_jwk().to_value()
    }

    /// JWKS serialized to `serde_json::Value`.
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let val = kp.public_jwks_json();
    /// assert!(val["keys"].is_array());
    /// ```
    #[cfg(feature = "jwk")]
    pub fn public_jwks_json(&self) -> serde_json::Value {
        self.public_jwks().to_value()
    }

    /// Private JWK serialized to `serde_json::Value`.
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.ecdsa("svc", EcdsaSpec::es256());
    /// let val = kp.private_key_jwk_json();
    /// assert_eq!(val["kty"], "EC");
    /// assert!(val["d"].is_string());
    /// ```
    #[cfg(feature = "jwk")]
    pub fn private_key_jwk_json(&self) -> serde_json::Value {
        self.private_key_jwk().to_value()
    }
}

fn load_inner(factory: &Factory, label: &str, spec: EcdsaSpec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_ECDSA_KEYPAIR, label, &spec_bytes, variant, |seed| {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
        match spec {
            EcdsaSpec::Es256 => generate_p256(spec, &mut rng),
            EcdsaSpec::Es384 => generate_p384(spec, &mut rng),
        }
    })
}

fn generate_p256(spec: EcdsaSpec, rng: &mut impl rand_core10::CryptoRng) -> Inner {
    use p256::ecdsa::SigningKey;

    let signing_key =
        SigningKey::try_generate_from_rng(rng).expect("failed to generate deterministic P-256 key");
    let verifying_key = signing_key.verifying_key();

    let pkcs8_der_doc = signing_key
        .to_pkcs8_der()
        .expect("failed to encode P-256 private key as PKCS#8 DER");
    let pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der_doc.as_bytes());

    let pkcs8_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("failed to encode P-256 private key as PKCS#8 PEM")
        .to_string();

    let spki_der_doc = verifying_key
        .to_public_key_der()
        .expect("failed to encode P-256 public key as SPKI DER");
    let spki_der: Arc<[u8]> = Arc::from(spki_der_doc.as_bytes());

    let spki_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .expect("failed to encode P-256 public key as SPKI PEM");

    // Get uncompressed point for JWK
    let point = verifying_key.to_sec1_point(false);
    let public_key_bytes = point.as_bytes().to_vec();
    let private_key_bytes = signing_key.to_bytes().to_vec();

    let material = Pkcs8SpkiKeyMaterial::new(pkcs8_der, pkcs8_pem, spki_der, spki_pem);

    Inner {
        spec,
        material,
        public_key_bytes,
        private_key_bytes,
    }
}

fn generate_p384(spec: EcdsaSpec, rng: &mut impl rand_core10::CryptoRng) -> Inner {
    use p384::ecdsa::SigningKey;

    let signing_key =
        SigningKey::try_generate_from_rng(rng).expect("failed to generate deterministic P-384 key");
    let verifying_key = signing_key.verifying_key();

    let pkcs8_der_doc = signing_key
        .to_pkcs8_der()
        .expect("failed to encode P-384 private key as PKCS#8 DER");
    let pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der_doc.as_bytes());

    let pkcs8_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("failed to encode P-384 private key as PKCS#8 PEM")
        .to_string();

    let spki_der_doc = verifying_key
        .to_public_key_der()
        .expect("failed to encode P-384 public key as SPKI DER");
    let spki_der: Arc<[u8]> = Arc::from(spki_der_doc.as_bytes());

    let spki_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .expect("failed to encode P-384 public key as SPKI PEM");

    // Get uncompressed point for JWK
    let point = verifying_key.to_sec1_point(false);
    let public_key_bytes = point.as_bytes().to_vec();
    let private_key_bytes = signing_key.to_bytes().to_vec();

    let material = Pkcs8SpkiKeyMaterial::new(pkcs8_der, pkcs8_pem, spki_der, spki_pem);

    Inner {
        spec,
        material,
        public_key_bytes,
        private_key_bytes,
    }
}
