use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::RngCore;
use uselesskey_core::Factory;

use crate::TokenSpec;

/// Cache domain for token fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_TOKEN_FIXTURE: &str = "uselesskey:token:fixture";

const BASE62: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Clone)]
pub struct TokenFixture {
    label: String,
    spec: TokenSpec,
    inner: Arc<Inner>,
}

struct Inner {
    value: String,
}

impl fmt::Debug for TokenFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenFixture")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// Extension trait to hang token helpers off the core [`Factory`].
pub trait TokenFactoryExt {
    fn token(&self, label: impl AsRef<str>, spec: TokenSpec) -> TokenFixture;
}

impl TokenFactoryExt for Factory {
    fn token(&self, label: impl AsRef<str>, spec: TokenSpec) -> TokenFixture {
        TokenFixture::new(self, label.as_ref(), spec)
    }
}

impl TokenFixture {
    fn new(factory: &Factory, label: &str, spec: TokenSpec) -> Self {
        let inner = load_inner(factory, label, spec, "good");
        Self {
            label: label.to_string(),
            spec,
            inner,
        }
    }

    /// Access the token value.
    pub fn value(&self) -> &str {
        &self.inner.value
    }

    /// Returns an HTTP `Authorization` header value for this token.
    ///
    /// - API keys use `ApiKey <token>`
    /// - Bearer and OAuth access tokens use `Bearer <token>`
    pub fn authorization_header(&self) -> String {
        let scheme = match self.spec {
            TokenSpec::ApiKey => "ApiKey",
            TokenSpec::Bearer | TokenSpec::OAuthAccessToken => "Bearer",
        };
        format!("{scheme} {}", self.value())
    }
}

fn load_inner(factory: &Factory, label: &str, spec: TokenSpec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_TOKEN_FIXTURE, label, &spec_bytes, variant, |rng| {
        let value = generate_token(label, spec, rng);
        Inner { value }
    })
}

fn generate_token(label: &str, spec: TokenSpec, rng: &mut impl RngCore) -> String {
    match spec {
        TokenSpec::ApiKey => generate_api_key(rng),
        TokenSpec::Bearer => generate_bearer_token(rng),
        TokenSpec::OAuthAccessToken => generate_oauth_access_token(label, rng),
    }
}

fn generate_api_key(rng: &mut impl RngCore) -> String {
    let mut out = String::from("uk_test_");
    out.push_str(&random_base62(rng, 32));
    out
}

fn generate_bearer_token(rng: &mut impl RngCore) -> String {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_oauth_access_token(label: &str, rng: &mut impl RngCore) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);

    let mut jti = [0u8; 16];
    rng.fill_bytes(&mut jti);

    let payload = serde_json::json!({
        "iss": "uselesskey",
        "sub": label,
        "aud": "tests",
        "scope": "fixture.read",
        "jti": URL_SAFE_NO_PAD.encode(jti),
        "exp": 4_102_444_800u64,
    });
    let payload_json = serde_json::to_vec(&payload).expect("payload JSON");
    let payload_segment = URL_SAFE_NO_PAD.encode(payload_json);

    let mut signature = [0u8; 32];
    rng.fill_bytes(&mut signature);
    let signature_segment = URL_SAFE_NO_PAD.encode(signature);

    format!("{header}.{payload_segment}.{signature_segment}")
}

fn random_base62(rng: &mut impl RngCore, len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut byte = [0u8; 1];

    while out.len() < len {
        rng.fill_bytes(&mut byte);
        let idx = byte[0] as usize % BASE62.len();
        out.push(BASE62[idx] as char);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn deterministic_token_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("token-det").unwrap());
        let t1 = fx.token("svc", TokenSpec::api_key());
        let t2 = fx.token("svc", TokenSpec::api_key());
        assert_eq!(t1.value(), t2.value());
    }

    #[test]
    fn random_mode_still_caches_per_identity() {
        let fx = Factory::random();
        let t1 = fx.token("svc", TokenSpec::bearer());
        let t2 = fx.token("svc", TokenSpec::bearer());
        assert_eq!(t1.value(), t2.value());
    }

    #[test]
    fn different_labels_produce_different_tokens() {
        let fx = Factory::deterministic(Seed::from_env_value("token-label").unwrap());
        let a = fx.token("a", TokenSpec::bearer());
        let b = fx.token("b", TokenSpec::bearer());
        assert_ne!(a.value(), b.value());
    }

    #[test]
    fn api_key_shape_is_realistic() {
        let fx = Factory::random();
        let token = fx.token("svc", TokenSpec::api_key());

        assert!(token.value().starts_with("uk_test_"));
        let suffix = &token.value()["uk_test_".len()..];
        assert_eq!(suffix.len(), 32);
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn bearer_header_uses_bearer_scheme() {
        let fx = Factory::random();
        let token = fx.token("svc", TokenSpec::bearer());
        let header = token.authorization_header();
        assert!(header.starts_with("Bearer "));
        assert!(header.ends_with(token.value()));
    }

    #[test]
    fn oauth_token_has_three_segments_and_json_header() {
        let fx = Factory::deterministic(Seed::from_env_value("token-oauth").unwrap());
        let token = fx.token("issuer", TokenSpec::oauth_access_token());

        let parts: Vec<&str> = token.value().split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("decode JWT header segment");
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("decode JWT payload segment");

        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("header json");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("payload json");

        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(payload["sub"], "issuer");
        assert_eq!(payload["iss"], "uselesskey");
    }

    #[test]
    fn debug_does_not_include_token_value() {
        let fx = Factory::random();
        let token = fx.token("debug-label", TokenSpec::api_key());
        let dbg = format!("{token:?}");
        assert!(dbg.contains("TokenFixture"));
        assert!(dbg.contains("debug-label"));
        assert!(!dbg.contains(token.value()));
    }
}
