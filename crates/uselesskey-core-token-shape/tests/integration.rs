use uselesskey_core_seed::Seed;

use uselesskey_core_token_shape::{TokenKind, generate_token};

#[test]
fn integration_generate_token_all_kinds() {
    let rng = Seed::new([3u8; 32]);

    let api = generate_token("label", TokenKind::ApiKey, rng);
    let rng = Seed::new([3u8; 32]);
    let bearer = generate_token("label", TokenKind::Bearer, rng);
    let rng = Seed::new([3u8; 32]);
    let oauth = generate_token("label", TokenKind::OAuthAccessToken, rng);

    assert_ne!(api, bearer);
    assert_ne!(api, oauth);
    assert_ne!(bearer, oauth);
}

#[test]
fn integration_api_key_prefix_is_stable() {
    let rng = Seed::new([7u8; 32]);
    let token = generate_token("tenant-a", TokenKind::ApiKey, rng);
    assert!(token.starts_with("uk_test_"));
}
