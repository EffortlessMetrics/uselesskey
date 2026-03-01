use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_token_shape::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, TokenKind, authorization_scheme, generate_api_key,
    generate_bearer_token, generate_oauth_access_token, generate_token, random_base62,
};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// generate_token is deterministic for the same seed and kind.
    #[test]
    fn generate_token_deterministic(
        seed in any::<[u8; 32]>(),
        kind_idx in 0u8..3,
    ) {
        let kind = match kind_idx {
            0 => TokenKind::ApiKey,
            1 => TokenKind::Bearer,
            _ => TokenKind::OAuthAccessToken,
        };
        let mut rng_a = ChaCha20Rng::from_seed(seed);
        let mut rng_b = ChaCha20Rng::from_seed(seed);
        prop_assert_eq!(
            generate_token("label", kind, &mut rng_a),
            generate_token("label", kind, &mut rng_b)
        );
    }

    /// API keys always start with the expected prefix and have the right suffix length.
    #[test]
    fn api_key_format(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let key = generate_api_key(&mut rng);
        prop_assert!(key.starts_with(API_KEY_PREFIX));
        let suffix = &key[API_KEY_PREFIX.len()..];
        prop_assert_eq!(suffix.len(), API_KEY_RANDOM_LEN);
        prop_assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    /// Bearer tokens always decode to 32 bytes.
    #[test]
    fn bearer_decodes_to_32_bytes(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_bearer_token(&mut rng);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .expect("bearer should be valid base64url");
        prop_assert_eq!(decoded.len(), 32);
    }

    /// OAuth access tokens always have exactly 3 dot-separated segments.
    #[test]
    fn oauth_has_three_segments(
        seed in any::<[u8; 32]>(),
        label in "[a-z0-9_-]{1,16}",
    ) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_oauth_access_token(&label, &mut rng);
        prop_assert_eq!(token.matches('.').count(), 2);
    }

    /// random_base62 always produces the requested length of alphanumeric chars.
    #[test]
    fn random_base62_length_and_charset(
        seed in any::<[u8; 32]>(),
        len in 0usize..=128,
    ) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let result = random_base62(&mut rng, len);
        prop_assert_eq!(result.len(), len);
        prop_assert!(result.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    /// authorization_scheme never panics.
    #[test]
    fn authorization_scheme_never_panics(kind_idx in 0u8..3) {
        let kind = match kind_idx {
            0 => TokenKind::ApiKey,
            1 => TokenKind::Bearer,
            _ => TokenKind::OAuthAccessToken,
        };
        let scheme = authorization_scheme(kind);
        prop_assert!(!scheme.is_empty());
    }
}

use base64::Engine as _;
