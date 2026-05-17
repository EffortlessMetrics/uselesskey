use std::fmt;
use std::sync::Arc;

use uselesskey_core::Factory;

use crate::TokenSpec;
use crate::srp::shape::{NegativeToken, generate_negative_token, generate_token};

/// Cache domain for token fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_TOKEN_FIXTURE: &str = "uselesskey:token:fixture";

/// A token fixture with a generated value.
///
/// Created via [`TokenFactoryExt::token()`]. Provides access to
/// the generated token value and an HTTP `Authorization` header.
///
/// # Examples
///
/// ```
/// # use uselesskey_core::{Factory, Seed};
/// # use uselesskey_token::{TokenFactoryExt, TokenSpec};
/// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
/// let tok = fx.token("api-key", TokenSpec::api_key());
/// assert!(tok.value().starts_with("uk_test_"));
/// ```
#[derive(Clone)]
pub struct TokenFixture {
    factory: Factory,
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
    /// Generate (or retrieve from cache) a token fixture.
    ///
    /// The `label` identifies this token within your test suite.
    /// In deterministic mode, `seed + label + spec` always produces the same token.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_token::{TokenFactoryExt, TokenSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let tok = fx.token("billing", TokenSpec::bearer());
    /// assert!(!tok.value().is_empty());
    /// ```
    fn token(&self, label: impl AsRef<str>, spec: TokenSpec) -> TokenFixture;

    /// Generate a token fixture with an explicit variant.
    ///
    /// Different variants for the same `(label, spec)` produce different tokens.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_token::{TokenFactoryExt, TokenSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let good = fx.token("svc", TokenSpec::api_key());
    /// let alt = fx.token_with_variant("svc", TokenSpec::api_key(), "alt");
    /// assert_ne!(good.value(), alt.value());
    /// ```
    fn token_with_variant(
        &self,
        label: impl AsRef<str>,
        spec: TokenSpec,
        variant: impl AsRef<str>,
    ) -> TokenFixture;
}

impl TokenFactoryExt for Factory {
    fn token(&self, label: impl AsRef<str>, spec: TokenSpec) -> TokenFixture {
        TokenFixture::new(self.clone(), label.as_ref(), spec)
    }

    fn token_with_variant(
        &self,
        label: impl AsRef<str>,
        spec: TokenSpec,
        variant: impl AsRef<str>,
    ) -> TokenFixture {
        let label = label.as_ref();
        let variant = variant.as_ref();
        let factory = self.clone();
        let inner = load_inner(&factory, label, spec, variant);
        TokenFixture {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }
}

impl TokenFixture {
    fn new(factory: Factory, label: &str, spec: TokenSpec) -> Self {
        let inner = load_inner(&factory, label, spec, "good");
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    #[allow(
        dead_code,
        reason = "reserved for future variant-based negative fixtures"
    )]
    fn load_variant(&self, variant: &str) -> Arc<Inner> {
        load_inner(&self.factory, &self.label, self.spec, variant)
    }

    /// Returns the spec used to create this token.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_token::{TokenFactoryExt, TokenSpec};
    /// let fx = Factory::random();
    /// let tok = fx.token("svc", TokenSpec::api_key());
    /// assert_eq!(tok.spec(), TokenSpec::api_key());
    /// ```
    pub fn spec(&self) -> TokenSpec {
        self.spec
    }

    /// Returns the label used to create this token.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::Factory;
    /// # use uselesskey_token::{TokenFactoryExt, TokenSpec};
    /// let fx = Factory::random();
    /// let tok = fx.token("my-svc", TokenSpec::api_key());
    /// assert_eq!(tok.label(), "my-svc");
    /// ```
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Access the token value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_token::{TokenFactoryExt, TokenSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let tok = fx.token("svc", TokenSpec::api_key());
    /// let val = tok.value();
    /// assert!(val.starts_with("uk_test_"));
    /// ```
    pub fn value(&self) -> &str {
        &self.inner.value
    }

    /// Returns an HTTP `Authorization` header value for this token.
    ///
    /// - API keys use `ApiKey <token>`
    /// - Bearer and OAuth access tokens use `Bearer <token>`
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_token::{TokenFactoryExt, TokenSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    ///
    /// let bearer = fx.token("svc", TokenSpec::bearer());
    /// assert!(bearer.authorization_header().starts_with("Bearer "));
    ///
    /// let api = fx.token("svc", TokenSpec::api_key());
    /// assert!(api.authorization_header().starts_with("ApiKey "));
    /// ```
    pub fn authorization_header(&self) -> String {
        let scheme = self.spec.authorization_scheme();
        format!("{scheme} {}", self.value())
    }

    /// Generate a scanner-safe negative token value for parser and validator tests.
    ///
    /// The generated value is cached by `(label, spec, variant)` and is stable in
    /// deterministic mode without changing the positive token fixture.
    ///
    /// # Examples
    ///
    /// ```
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_token::{NegativeToken, TokenFactoryExt, TokenSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let oauth = fx.token("issuer", TokenSpec::oauth_access_token());
    /// let expired = oauth.negative_value(NegativeToken::ExpiredClaims);
    /// assert_eq!(expired.matches('.').count(), 2);
    /// ```
    pub fn negative_value(&self, variant: NegativeToken) -> String {
        load_negative_inner(&self.factory, &self.label, self.spec, variant)
            .value
            .clone()
    }
}

fn load_inner(factory: &Factory, label: &str, spec: TokenSpec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_TOKEN_FIXTURE, label, &spec_bytes, variant, |seed| {
        let value = generate_token(label, spec, seed);
        Inner { value }
    })
}

fn load_negative_inner(
    factory: &Factory,
    label: &str,
    spec: TokenSpec,
    variant: NegativeToken,
) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();
    let cache_variant = format!("negative:{}", variant.variant_name());

    factory.get_or_init(
        DOMAIN_TOKEN_FIXTURE,
        label,
        &spec_bytes,
        &cache_variant,
        |seed| {
            let value = generate_negative_token(label, spec, seed, variant);
            Inner { value }
        },
    )
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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
    fn different_variants_produce_different_tokens() {
        let fx = Factory::deterministic(Seed::from_env_value("token-variant").unwrap());
        let token = fx.token("svc", TokenSpec::bearer());
        let other = token.load_variant("other");

        assert_ne!(token.value(), other.value.as_str());
    }

    #[test]
    fn token_with_variant_uses_custom_variant() {
        let fx = Factory::deterministic(Seed::from_env_value("token-variant2").unwrap());
        let good = fx.token("svc", TokenSpec::api_key());
        let custom = fx.token_with_variant("svc", TokenSpec::api_key(), "custom");

        assert_ne!(good.value(), custom.value());
    }

    #[test]
    fn negative_value_is_cached_and_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("token-negative").unwrap());
        let token = fx.token("issuer", TokenSpec::oauth_access_token());

        let a = token.negative_value(NegativeToken::ExpiredClaims);
        let b = token.negative_value(NegativeToken::ExpiredClaims);

        assert_eq!(a, b);
        assert_ne!(a, token.value());
        assert_eq!(a.matches('.').count(), 2);
    }

    #[test]
    fn negative_api_key_near_miss_keeps_positive_fixture_unchanged() {
        let fx = Factory::deterministic(Seed::from_env_value("token-negative-api").unwrap());
        let token = fx.token("billing", TokenSpec::api_key());

        let near_miss = token.negative_value(NegativeToken::NearMissApiKey);

        assert!(token.value().starts_with("uk_test_"));
        assert!(near_miss.starts_with("uk_tset_"));
        assert!(!near_miss.starts_with("uk_test_"));
        assert_ne!(near_miss, token.value());
    }

    #[test]
    fn negative_variants_are_cached_independently() {
        let fx = Factory::deterministic(Seed::from_env_value("token-negative-variants").unwrap());
        let token = fx.token("issuer", TokenSpec::oauth_access_token());

        let expired = token.negative_value(NegativeToken::ExpiredClaims);
        let bad_issuer = token.negative_value(NegativeToken::BadIssuer);
        let bad_audience = token.negative_value(NegativeToken::BadAudience);

        assert_eq!(expired, token.negative_value(NegativeToken::ExpiredClaims));
        assert_eq!(bad_issuer, token.negative_value(NegativeToken::BadIssuer));
        assert_eq!(
            bad_audience,
            token.negative_value(NegativeToken::BadAudience)
        );
        assert_ne!(expired, bad_issuer);
        assert_ne!(expired, bad_audience);
        assert_ne!(bad_issuer, bad_audience);
        assert_ne!(expired, token.value());
    }

    #[test]
    fn negative_values_are_deterministic_across_factories() {
        let seed = Seed::from_env_value("token-negative-cross-factory").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 =
            Factory::deterministic(Seed::from_env_value("token-negative-cross-factory").unwrap());

        let t1 = fx1.token("issuer", TokenSpec::oauth_access_token());
        let t2 = fx2.token("issuer", TokenSpec::oauth_access_token());

        for variant in [
            NegativeToken::ExpiredClaims,
            NegativeToken::BadIssuer,
            NegativeToken::BadAudience,
            NegativeToken::MismatchedKid,
        ] {
            assert_eq!(t1.negative_value(variant), t2.negative_value(variant));
        }
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

    #[test]
    fn random_base62_uses_full_alphabet() {
        let fx = Factory::deterministic(Seed::from_env_value("base62-test").unwrap());
        let t = fx.token("alphabet-test", TokenSpec::api_key());
        let value = t.value();
        // API key format: "uk_test_{32 random base62 chars}".
        // Strip the prefix to inspect only the random suffix.
        let suffix = value.strip_prefix("uk_test_").expect("API key prefix");
        // With / instead of %, only A-E would appear (byte[0] / 62 yields 0..=4).
        // With %, the full base62 alphabet is used. A 32-char random suffix must
        // contain characters beyond the first five uppercase letters.
        assert!(
            suffix
                .chars()
                .any(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "random suffix should use full base62 alphabet, got: {suffix}"
        );
    }
}
