use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use uselesskey_core_seed::Seed;
use uselesskey_core_token_shape::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, TokenKind, generate_api_key,
    generate_bearer_token, generate_oauth_access_token, generate_token,
};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn api_key_has_correct_prefix_and_length(seed in any::<[u8; 32]>()) {
        let rng = Seed::new(seed);
        let key = generate_api_key(rng);
        prop_assert!(key.starts_with(API_KEY_PREFIX));
        let suffix = &key[API_KEY_PREFIX.len()..];
        prop_assert_eq!(suffix.len(), API_KEY_RANDOM_LEN);
        prop_assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn bearer_decodes_to_expected_bytes(seed in any::<[u8; 32]>()) {
        let rng = Seed::new(seed);
        let token = generate_bearer_token(rng);
        let decoded = URL_SAFE_NO_PAD.decode(token.as_bytes());
        prop_assert!(decoded.is_ok());
        prop_assert_eq!(decoded.unwrap().len(), BEARER_RANDOM_BYTES);
    }

    #[test]
    fn oauth_has_three_jwt_segments(
        seed in any::<[u8; 32]>(),
        label in "[a-z0-9_-]{1,16}",
    ) {
        let rng = Seed::new(seed);
        let token = generate_oauth_access_token(&label, rng);
        prop_assert_eq!(token.matches('.').count(), 2);

        let parts: Vec<&str> = token.split('.').collect();
        // Header segment is valid base64url
        prop_assert!(URL_SAFE_NO_PAD.decode(parts[0]).is_ok());
        // Payload segment contains the label as sub
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        prop_assert_eq!(json["sub"].as_str().unwrap(), label.as_str());
        prop_assert_eq!(json["iss"].as_str().unwrap(), "uselesskey");
    }

    #[test]
    fn generate_token_deterministic(seed in any::<[u8; 32]>(), label in "[a-z]{1,8}") {
        let a = generate_token(&label, TokenKind::ApiKey, Seed::new(seed));
        let b = generate_token(&label, TokenKind::ApiKey, Seed::new(seed));
        prop_assert_eq!(a, b);

        let a = generate_token(&label, TokenKind::Bearer, Seed::new(seed));
        let b = generate_token(&label, TokenKind::Bearer, Seed::new(seed));
        prop_assert_eq!(a, b);

        let a = generate_token(&label, TokenKind::OAuthAccessToken, Seed::new(seed));
        let b = generate_token(&label, TokenKind::OAuthAccessToken, Seed::new(seed));
        prop_assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_api_keys(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed_a != seed_b);
        let a = generate_api_key(Seed::new(seed_a));
        let b = generate_api_key(Seed::new(seed_b));
        prop_assert_ne!(a, b);
    }
}
