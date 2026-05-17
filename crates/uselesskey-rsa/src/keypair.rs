use std::fmt;
use std::sync::Arc;

#[cfg(feature = "legacy-rsa09")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "legacy-rsa09")]
use rand_chacha::rand_core::SeedableRng;
#[cfg(not(feature = "legacy-rsa09"))]
use rand_chacha10::ChaCha20Rng;
#[cfg(not(feature = "legacy-rsa09"))]
use rand_chacha10::rand_core::SeedableRng;
use rsa as rsa10;
#[cfg(feature = "legacy-rsa09")]
use rsa09::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
#[cfg(feature = "legacy-rsa09")]
use rsa09::{RsaPrivateKey, RsaPublicKey};
#[cfg(feature = "legacy-rsa09")]
use rsa10::pkcs8::DecodePrivateKey;
#[cfg(feature = "jwk")]
use rsa10::pkcs8::DecodePublicKey;
#[cfg(not(feature = "legacy-rsa09"))]
use rsa10::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use uselesskey_core::Factory;
use uselesskey_core::srp::keypair_material::Pkcs8SpkiKeyMaterial;

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
    _private: rsa10::RsaPrivateKey,
    #[cfg(feature = "jwk")]
    public: rsa10::RsaPublicKey,
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
    /// Generate (or retrieve from cache) an RSA keypair fixture.
    ///
    /// The `label` identifies this keypair within your test suite.
    /// In deterministic mode, `seed + label + spec` always produces the same key.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::{Factory, Seed};
    /// use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    ///
    /// let seed = Seed::from_env_value("test-seed").unwrap();
    /// let fx = Factory::deterministic(seed);
    /// let keypair = fx.rsa("my-service", RsaSpec::rs256());
    ///
    /// let pem = keypair.private_key_pkcs8_pem();
    /// assert!(pem.contains("BEGIN PRIVATE KEY"));
    /// ```
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

    /// Returns the spec used to create this keypair.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
    /// assert_eq!(kp.spec(), RsaSpec::rs256());
    /// ```
    pub fn spec(&self) -> RsaSpec {
        self.spec
    }

    /// Returns the label used to create this keypair.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::random();
    /// let kp = fx.rsa("my-svc", RsaSpec::rs256());
    /// assert_eq!(kp.label(), "my-svc");
    /// ```
    pub fn label(&self) -> &str {
        &self.label
    }

    #[cfg(feature = "jwk")]
    fn jwk_alg(&self) -> &'static str {
        match self.spec.bits {
            3072 => "RS384",
            4096 => "RS512",
            _ => "RS256",
        }
    }

    uselesskey_core::impl_pkcs8_spki_fixture_accessors!();

    /// Alias for [`Self::public_jwk`].
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
    /// let jwk = kp.public_key_jwk();
    /// assert_eq!(jwk.to_value()["kty"], "RSA");
    /// ```
    #[cfg(feature = "jwk")]
    pub fn public_key_jwk(&self) -> uselesskey_jwk::PublicJwk {
        self.public_jwk()
    }

    /// Public JWK for this keypair (kty=RSA, use=sig, kid=...).
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
    /// let jwk = kp.public_jwk();
    /// let val = jwk.to_value();
    /// assert_eq!(val["kty"], "RSA");
    /// assert_eq!(val["alg"], "RS256");
    /// ```
    #[cfg(feature = "jwk")]
    pub fn public_jwk(&self) -> uselesskey_jwk::PublicJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa10::traits::PublicKeyParts;
        use uselesskey_jwk::{PublicJwk, RsaPublicJwk};

        let n = self.inner.public.n_bytes();
        let e = self.inner.public.e_bytes();

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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
    /// let jwk = kp.private_key_jwk();
    /// let val = jwk.to_value();
    /// assert_eq!(val["kty"], "RSA");
    /// assert!(val["d"].is_string());
    /// ```
    #[cfg(feature = "jwk")]
    pub fn private_key_jwk(&self) -> uselesskey_jwk::PrivateJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rsa10::traits::{PrivateKeyParts, PublicKeyParts};
        use uselesskey_jwk::{PrivateJwk, RsaPrivateJwk};

        let private = &self.inner._private;
        let primes = private.primes();
        assert!(primes.len() >= 2, "expected at least two RSA primes");

        let n = private.n_bytes();
        let e = private.e_bytes();
        let d = private.d().to_be_bytes_trimmed_vartime();
        let p = primes[0].to_be_bytes_trimmed_vartime();
        let q = primes[1].to_be_bytes_trimmed_vartime();
        let dp = private.dp().expect("dp").to_be_bytes_trimmed_vartime();
        let dq = private.dq().expect("dq").to_be_bytes_trimmed_vartime();
        let qi = private
            .qinv()
            .expect("qinv")
            .retrieve()
            .to_be_bytes_trimmed_vartime();

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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
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
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
    /// let val = kp.public_jwk_json();
    /// assert_eq!(val["kty"], "RSA");
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
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
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
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let kp = fx.rsa("svc", RsaSpec::rs256());
    /// let val = kp.private_key_jwk_json();
    /// assert_eq!(val["kty"], "RSA");
    /// assert!(val["d"].is_string());
    /// ```
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

    factory.get_or_init(DOMAIN_RSA_KEYPAIR, label, &spec_bytes, variant, |seed| {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

        #[cfg(feature = "legacy-rsa09")]
        let private09 = RsaPrivateKey::new(&mut rng, spec.bits).expect("RSA keygen failed");
        #[cfg(feature = "legacy-rsa09")]
        let public09 = RsaPublicKey::from(&private09);

        #[cfg(feature = "legacy-rsa09")]
        let pkcs8_der_doc = private09
            .to_pkcs8_der()
            .expect("failed to encode RSA private key as PKCS#8 DER");
        #[cfg(feature = "legacy-rsa09")]
        let pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der_doc.as_bytes());

        #[cfg(feature = "legacy-rsa09")]
        let pkcs8_pem = private09
            .to_pkcs8_pem(LineEnding::LF)
            .expect("failed to encode RSA private key as PKCS#8 PEM")
            .to_string();

        #[cfg(feature = "legacy-rsa09")]
        let spki_der_doc = public09
            .to_public_key_der()
            .expect("failed to encode RSA public key as SPKI DER");
        #[cfg(feature = "legacy-rsa09")]
        let spki_der: Arc<[u8]> = Arc::from(spki_der_doc.as_bytes());

        #[cfg(feature = "legacy-rsa09")]
        let spki_pem = public09
            .to_public_key_pem(LineEnding::LF)
            .expect("failed to encode RSA public key as SPKI PEM")
            .to_string();

        #[cfg(feature = "legacy-rsa09")]
        let private = rsa10::RsaPrivateKey::from_pkcs8_der(&pkcs8_der)
            .expect("failed to parse V1 RSA private key into rsa 0.10");
        #[cfg(feature = "jwk")]
        #[cfg(feature = "legacy-rsa09")]
        let public = rsa10::RsaPublicKey::from_public_key_der(&spki_der)
            .expect("failed to parse V1 RSA public key into rsa 0.10");
        #[cfg(not(feature = "legacy-rsa09"))]
        let private = rsa10::RsaPrivateKey::new(&mut rng, spec.bits).expect("RSA keygen failed");
        #[cfg(not(feature = "legacy-rsa09"))]
        let public = rsa10::RsaPublicKey::from(&private);
        #[cfg(not(feature = "legacy-rsa09"))]
        let pkcs8_der_doc = private
            .to_pkcs8_der()
            .expect("failed to encode RSA private key as PKCS#8 DER");
        #[cfg(not(feature = "legacy-rsa09"))]
        let pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der_doc.as_bytes());
        #[cfg(not(feature = "legacy-rsa09"))]
        let pkcs8_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("failed to encode RSA private key as PKCS#8 PEM")
            .to_string();
        #[cfg(not(feature = "legacy-rsa09"))]
        let spki_der_doc = public
            .to_public_key_der()
            .expect("failed to encode RSA public key as SPKI DER");
        #[cfg(not(feature = "legacy-rsa09"))]
        let spki_der: Arc<[u8]> = Arc::from(spki_der_doc.as_bytes());
        #[cfg(not(feature = "legacy-rsa09"))]
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
