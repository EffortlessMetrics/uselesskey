use std::fmt;
use std::sync::Arc;

use rand_core::RngCore;
use uselesskey_core::Factory;

use crate::HmacSpec;

/// Cache domain for HMAC secret fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_HMAC_SECRET: &str = "uselesskey:hmac:secret";

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

    /// Access raw secret bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.inner.secret
    }

    /// A stable key identifier derived from the secret bytes (base64url blake3 hash prefix).
    #[cfg(feature = "jwk")]
    pub fn kid(&self) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let h = blake3::hash(self.secret_bytes());
        let short = &h.as_bytes()[..12]; // 96 bits is plenty for tests.
        URL_SAFE_NO_PAD.encode(short)
    }

    /// HMAC secret as an octet JWK (kty=oct).
    ///
    /// Requires the `jwk` feature.
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

    factory.get_or_init(DOMAIN_HMAC_SECRET, label, &spec_bytes, variant, |rng| {
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
