/// Specification for token fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TokenSpec {
    /// API key style token (e.g. `uk_test_<base62>`).
    ApiKey,
    /// Opaque bearer token (base64url body).
    Bearer,
    /// OAuth access token in JWT shape (`header.payload.signature`).
    OAuthAccessToken,
}

impl TokenSpec {
    pub fn api_key() -> Self {
        Self::ApiKey
    }

    pub fn bearer() -> Self {
        Self::Bearer
    }

    pub fn oauth_access_token() -> Self {
        Self::OAuthAccessToken
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Bearer => "bearer",
            Self::OAuthAccessToken => "oauth_access_token",
        }
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::ApiKey => [0, 0, 0, 1],
            Self::Bearer => [0, 0, 0, 2],
            Self::OAuthAccessToken => [0, 0, 0, 3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_bytes_are_unique() {
        let api = TokenSpec::api_key().stable_bytes();
        let bearer = TokenSpec::bearer().stable_bytes();
        let oauth = TokenSpec::oauth_access_token().stable_bytes();

        assert_ne!(api, bearer);
        assert_ne!(api, oauth);
        assert_ne!(bearer, oauth);
    }

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(TokenSpec::api_key().kind_name(), "api_key");
        assert_eq!(TokenSpec::bearer().kind_name(), "bearer");
        assert_eq!(
            TokenSpec::oauth_access_token().kind_name(),
            "oauth_access_token"
        );
    }
}
