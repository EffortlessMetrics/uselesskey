use std::fmt;
use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use uselesskey_core::Factory;
#[cfg(feature = "jwk")]
use uselesskey_core_kid::kid_from_bytes;

use crate::HmacSpec;

/// Cache domain for HMAC secret fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_HMAC_SECRET: &str = "uselesskey:hmac:secret";

/// An HMAC secret fixture.
///
/// Created via [`HmacFactoryExt::hmac()`]. Provides access to raw secret bytes
/// and JWK output (with the `jwk` feature).
///
/// # Examples
///
/// ```
/// use uselesskey_core::Factory;
/// use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
///
/// let fx = Factory::random();
/// let secret = fx.hmac("jwt-signing", HmacSpec::hs256());
///
/// assert_eq!(secret.secret_bytes().len(), 32);
/// ```
#[derive(Clone)]
pub struct HmacSecret {
    factory: Factory,
    label: String,
    spec: HmacSpec,
    inner: Arc<Inner>,
}

struct Inner {
    secret: Arc<[u8]>,
}

impl fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSecret")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// Extension trait to hang HMAC helpers off the core [`Factory`].
pub trait HmacFactoryExt {
    /// Generate (or retrieve from cache) an HMAC secret fixture.
    ///
    /// The `label` identifies this secret within your test suite.
    /// In deterministic mode, `seed + label + spec` always produces the same secret.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::{Factory, Seed};
    /// use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    ///
    /// let seed = Seed::from_env_value("test-seed").unwrap();
    /// let fx = Factory::deterministic(seed);
    /// let secret = fx.hmac("jwt-signing", HmacSpec::hs256());
    ///
    /// // Same seed + label + spec = same secret
    /// let secret2 = fx.hmac("jwt-signing", HmacSpec::hs256());
    /// assert_eq!(secret.secret_bytes(), secret2.secret_bytes());
    /// ```
    fn hmac(&self, label: impl AsRef<str>, spec: HmacSpec) -> HmacSecret;
}

impl HmacFactoryExt for Factory {
    fn hmac(&self, label: impl AsRef<str>, spec: HmacSpec) -> HmacSecret {
        HmacSecret::new(self.clone(), label.as_ref(), spec)
    }
}

impl HmacSecret {
    fn new(factory: Factory, label: &str, spec: HmacSpec) -> Self {
        let inner = load_inner(&factory, label, spec, "good");
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    #[allow(dead_code)]
    fn load_variant(&self, variant: &str) -> Arc<Inner> {
        load_inner(&self.factory, &self.label, self.spec, variant)
    }

    /// Returns the spec used to create this secret.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    /// let fx = Factory::random();
    /// let secret = fx.hmac("jwt", HmacSpec::hs256());
    /// assert_eq!(secret.spec(), HmacSpec::hs256());
    /// ```
    pub fn spec(&self) -> HmacSpec {
        self.spec
    }

    /// Returns the label used to create this secret.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    /// let fx = Factory::random();
    /// let secret = fx.hmac("my-jwt", HmacSpec::hs256());
    /// assert_eq!(secret.label(), "my-jwt");
    /// ```
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Access raw secret bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let secret = fx.hmac("jwt-signing", HmacSpec::hs256());
    /// assert_eq!(secret.secret_bytes().len(), 32);
    ///
    /// let secret512 = fx.hmac("jwt-signing", HmacSpec::hs512());
    /// assert_eq!(secret512.secret_bytes().len(), 64);
    /// ```
    pub fn secret_bytes(&self) -> &[u8] {
        &self.inner.secret
    }

    /// A stable key identifier derived from the secret bytes (base64url blake3 hash prefix).
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    /// let fx = Factory::random();
    /// let secret = fx.hmac("jwt", HmacSpec::hs256());
    /// let kid = secret.kid();
    /// assert!(!kid.is_empty());
    /// ```
    #[cfg(feature = "jwk")]
    pub fn kid(&self) -> String {
        kid_from_bytes(self.secret_bytes())
    }

    /// HMAC secret as an octet JWK (kty=oct).
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    /// let fx = Factory::random();
    /// let secret = fx.hmac("jwt", HmacSpec::hs256());
    /// let jwk = secret.jwk();
    /// let val = jwk.to_value();
    /// assert_eq!(val["kty"], "oct");
    /// assert_eq!(val["alg"], "HS256");
    /// ```
    #[cfg(feature = "jwk")]
    pub fn jwk(&self) -> uselesskey_jwk::PrivateJwk {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use uselesskey_jwk::{OctJwk, PrivateJwk};

        let k = URL_SAFE_NO_PAD.encode(self.secret_bytes());

        PrivateJwk::Oct(OctJwk {
            kty: "oct",
            use_: "sig",
            alg: self.spec.alg_name(),
            kid: self.kid(),
            k,
        })
    }

    /// JWKS containing this HMAC secret as an octet key.
    ///
    /// Requires the `jwk` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    /// let fx = Factory::random();
    /// let secret = fx.hmac("jwt", HmacSpec::hs256());
    /// let jwks = secret.jwks();
    /// let val = jwks.to_value();
    /// assert!(val["keys"].is_array());
    /// ```
    #[cfg(feature = "jwk")]
    pub fn jwks(&self) -> uselesskey_jwk::Jwks {
        use uselesskey_jwk::JwksBuilder;

        let mut builder = JwksBuilder::new();
        builder.push_private(self.jwk());
        builder.build()
    }
}

fn load_inner(factory: &Factory, label: &str, spec: HmacSpec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_HMAC_SECRET, label, &spec_bytes, variant, |seed| {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
        let mut buf = vec![0u8; spec.byte_len()];
        rng.fill_bytes(&mut buf);
        Inner {
            secret: Arc::from(buf),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn secret_length_matches_spec() {
        let fx = Factory::random();
        let secret = fx.hmac("test", HmacSpec::hs256());
        assert_eq!(secret.secret_bytes().len(), 32);
    }

    #[test]
    fn deterministic_secret_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("hmac-seed").unwrap());
        let s1 = fx.hmac("issuer", HmacSpec::hs384());
        let s2 = fx.hmac("issuer", HmacSpec::hs384());
        assert_eq!(s1.secret_bytes(), s2.secret_bytes());
    }

    #[test]
    fn different_variants_produce_different_secrets() {
        let fx = Factory::deterministic(Seed::from_env_value("hmac-variant").unwrap());
        let secret = fx.hmac("issuer", HmacSpec::hs256());
        let other = secret.load_variant("other");

        assert_ne!(secret.secret_bytes(), other.secret.as_ref());
    }

    #[test]
    #[cfg(feature = "jwk")]
    fn jwk_contains_expected_fields() {
        let fx = Factory::random();
        let secret = fx.hmac("jwt", HmacSpec::hs512());
        let jwk = secret.jwk().to_value();

        assert_eq!(jwk["kty"], "oct");
        assert_eq!(jwk["alg"], "HS512");
        assert_eq!(jwk["use"], "sig");
        assert!(jwk["kid"].is_string());
        assert!(jwk["k"].is_string());
    }

    #[test]
    #[cfg(feature = "jwk")]
    fn jwk_k_is_base64url() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = Factory::random();
        let secret = fx.hmac("jwt", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();

        let k = jwk["k"].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(k).expect("valid base64url");
        assert_eq!(decoded.len(), HmacSpec::hs256().byte_len());
    }

    #[test]
    #[cfg(feature = "jwk")]
    fn jwks_wraps_jwk() {
        let fx = Factory::random();
        let secret = fx.hmac("jwt", HmacSpec::hs256());

        let jwk = secret.jwk().to_value();
        let jwks = secret.jwks().to_value();

        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], jwk);
    }

    #[test]
    #[cfg(feature = "jwk")]
    fn kid_is_deterministic() {
        let fx = Factory::deterministic(Seed::from_env_value("hmac-kid").unwrap());
        let s1 = fx.hmac("issuer", HmacSpec::hs512());
        let s2 = fx.hmac("issuer", HmacSpec::hs512());
        assert_eq!(s1.kid(), s2.kid());
    }

    #[test]
    fn debug_includes_label_and_type() {
        let fx = Factory::random();
        let secret = fx.hmac("debug-label", HmacSpec::hs256());

        let dbg = format!("{:?}", secret);
        assert!(dbg.contains("HmacSecret"));
        assert!(dbg.contains("debug-label"));
    }
}
