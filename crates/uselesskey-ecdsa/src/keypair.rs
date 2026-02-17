use std::fmt;
use std::sync::Arc;

use elliptic_curve::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use uselesskey_core::negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, truncate_der,
};
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};

use crate::EcdsaSpec;

/// Cache domain for ECDSA keypair fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_ECDSA_KEYPAIR: &str = "uselesskey:ecdsa:keypair";

/// An ECDSA keypair fixture.
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
    pkcs8_der: Arc<[u8]>,
    pkcs8_pem: String,
    spki_der: Arc<[u8]>,
    spki_pem: String,
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
    pub fn spec(&self) -> EcdsaSpec {
        self.spec
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

    /// Produce a deterministic corrupted PKCS#8 PEM using a variant string.
    pub fn private_key_pkcs8_pem_corrupt_deterministic(&self, variant: &str) -> String {
        corrupt_pem_deterministic(self.private_key_pkcs8_pem(), variant)
    }

    /// Produce a truncated variant of the PKCS#8 DER.
    pub fn private_key_pkcs8_der_truncated(&self, len: usize) -> Vec<u8> {
        truncate_der(self.private_key_pkcs8_der(), len)
    }

    /// Produce a deterministic corrupted PKCS#8 DER using a variant string.
    pub fn private_key_pkcs8_der_corrupt_deterministic(&self, variant: &str) -> Vec<u8> {
        corrupt_der_deterministic(self.private_key_pkcs8_der(), variant)
    }

    /// Return a valid (parseable) public key that does *not* match this private key.
    pub fn mismatched_public_key_spki_der(&self) -> Vec<u8> {
        let other = self.load_variant("mismatch");
        other.spki_der.as_ref().to_vec()
    }

    /// A stable key identifier derived from the public key (base64url blake3 hash prefix).
    #[cfg(feature = "jwk")]
    pub fn kid(&self) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let h = blake3::hash(self.public_key_spki_der());
        let short = &h.as_bytes()[..12]; // 96 bits is plenty for tests.
        URL_SAFE_NO_PAD.encode(short)
    }

    /// Alias for [`public_jwk`].
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_key_jwk(&self) -> uselesskey_jwk::PublicJwk {
        self.public_jwk()
    }

    /// Public JWK for this keypair (kty=EC, crv=P-256 or P-384, alg=ES256 or ES384).
    ///
    /// Requires the `jwk` feature.
    #[cfg(feature = "jwk")]
    pub fn public_jwk(&self) -> uselesskey_jwk::PublicJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use uselesskey_jwk::{EcPublicJwk, PublicJwk};

        // Public key bytes are in uncompressed form: 0x04 || x || y
        let bytes = &self.inner.public_key_bytes;
        assert_eq!(bytes[0], 0x04, "expected uncompressed point");

        let coord_len = (bytes.len() - 1) / 2;
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
    #[cfg(feature = "jwk")]
    pub fn private_key_jwk(&self) -> uselesskey_jwk::PrivateJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use uselesskey_jwk::{EcPrivateJwk, PrivateJwk};

        // Public key bytes are in uncompressed form: 0x04 || x || y
        let bytes = &self.inner.public_key_bytes;
        assert_eq!(bytes[0], 0x04, "expected uncompressed point");

        let coord_len = (bytes.len() - 1) / 2;
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

fn load_inner(factory: &Factory, label: &str, spec: EcdsaSpec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(
        DOMAIN_ECDSA_KEYPAIR,
        label,
        &spec_bytes,
        variant,
        |rng| match spec {
            EcdsaSpec::Es256 => generate_p256(spec, rng),
            EcdsaSpec::Es384 => generate_p384(spec, rng),
        },
    )
}

fn generate_p256(spec: EcdsaSpec, rng: &mut impl rand_core::CryptoRngCore) -> Inner {
    use p256::ecdsa::SigningKey;

    let signing_key = SigningKey::random(rng);
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
    let point = verifying_key.to_encoded_point(false);
    let public_key_bytes = point.as_bytes().to_vec();
    let private_key_bytes = signing_key.to_bytes().to_vec();

    Inner {
        spec,
        pkcs8_der,
        pkcs8_pem,
        spki_der,
        spki_pem,
        public_key_bytes,
        private_key_bytes,
    }
}

fn generate_p384(spec: EcdsaSpec, rng: &mut impl rand_core::CryptoRngCore) -> Inner {
    use p384::ecdsa::SigningKey;

    let signing_key = SigningKey::random(rng);
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
    let point = verifying_key.to_encoded_point(false);
    let public_key_bytes = point.as_bytes().to_vec();
    let private_key_bytes = signing_key.to_bytes().to_vec();

    Inner {
        spec,
        pkcs8_der,
        pkcs8_pem,
        spki_der,
        spki_pem,
        public_key_bytes,
        private_key_bytes,
    }
}
